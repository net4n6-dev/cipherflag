// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ShadowCA is one row in the shadow-CA listing — an observed CA that
// the operator has NOT declared as managed. Carries enough identity
// (subject CN + org, issuer CN) to identify it, enough enrichment
// (direct-children count, recent-issuance flag, host impact,
// unattributed-IP count) to prioritise triage.
//
// Spec: research/shadow-ca-plan-v1.6.0.md §2.3.
type ShadowCA struct {
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	SubjectCN         string    `json:"subject_cn"`
	SubjectOrg        string    `json:"subject_org"`
	IssuerCN          string    `json:"issuer_cn"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	FirstSeen         time.Time `json:"first_seen"`
	KeyAlgorithm      string    `json:"key_algorithm"`
	KeySizeBits       int       `json:"key_size_bits"`
	Grade             string    `json:"grade,omitempty"`

	// DirectChildrenCount is the count of certificates whose issuer_cn
	// matches this CA's subject_cn, excluding self. Not transitively
	// recursive — that's what the AQ-BR-02 descent tree endpoint does
	// per-CA. Operators scanning the shadow list want a quick "how
	// many leaves does this CA sign" signal.
	DirectChildrenCount int `json:"direct_children_count"`

	// RecentChildrenCount — direct children whose first_seen is within
	// the last 30 days. Signals "actively issuing" vs "legacy CA
	// nobody turned off".
	RecentChildrenCount int `json:"recent_children_count"`

	// HostImpact — distinct hosts that host_ip_sightings attributes
	// to any leaf of this CA (via the v1.5.0 attribution path). A
	// proxy for "if this CA is compromised, how many of OUR hosts
	// actively serve its leaves".
	HostImpact int `json:"host_impact"`

	// UnattributedIPs — distinct server_ips where leaves of this CA
	// were observed but no host_ip_sighting resolves the IP. Feeds
	// cross-reference to AQ-IC-02 / AQ-IC-03: shadow CAs whose leaves
	// live on shadow IPs are the biggest candidates for operator
	// investigation.
	UnattributedIPs int `json:"unattributed_ips"`
}

// DeclaredCA is one row in the operator-managed CA registry. Returned
// by ListDeclaredCAs. The accompanying cert identity is joined so the
// UI can render hostname / org without a second fetch.
type DeclaredCA struct {
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	SubjectCN         string    `json:"subject_cn"`
	SubjectOrg        string    `json:"subject_org"`
	AddedAt           time.Time `json:"added_at"`
	AddedBy           string    `json:"added_by,omitempty"` // user UUID; empty if added_by was deleted (FK SET NULL)
	OwnerTeam         string    `json:"owner_team"`
	Note              string    `json:"note"`
	HolderHostID      string    `json:"holder_host_id,omitempty"` // host UUID; empty if not attributed (migration 045)
}

// DeclareCARequest is the upsert payload for DeclareCA. The fingerprint
// MUST correspond to an existing row in `certificates`; the FK in
// migration 025 rejects unknown fingerprints.
type DeclareCARequest struct {
	FingerprintSHA256 string
	AddedBy           string // user UUID; empty string if unknown / unattributed
	OwnerTeam         string
	Note              string
	HolderHostID      string // host UUID; empty string if holder not attributed (migration 045)
}

// ListShadowCAs returns every is_ca=true cert NOT present in
// operator_declared_cas, enriched with triage signals. Ordered by
// DirectChildrenCount DESC (highest-impact shadow first). Spec §2.2.
//
// The query is single-pass but uses correlated subqueries for the
// enrichment columns. At expected real-world scale (hundreds of CAs,
// hundreds-of-thousands of leaves max) this is fine; optimization via
// pre-aggregation CTEs is a future step if the table grows past that.
func (s *PostgresStore) ListShadowCAs(ctx context.Context) ([]ShadowCA, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			c.fingerprint_sha256,
			c.subject_cn,
			c.subject_org,
			c.issuer_cn,
			c.not_before,
			c.not_after,
			c.first_seen,
			c.key_algorithm::text,
			c.key_size_bits,
			COALESCE(h.grade, '') AS grade,
			(SELECT COUNT(*)::int
			 FROM   certificates ch
			 WHERE  ch.issuer_cn = c.subject_cn
			   AND  ch.fingerprint_sha256 != c.fingerprint_sha256
			) AS direct_children_count,
			(SELECT COUNT(*)::int
			 FROM   certificates ch
			 WHERE  ch.issuer_cn = c.subject_cn
			   AND  ch.fingerprint_sha256 != c.fingerprint_sha256
			   AND  ch.first_seen > NOW() - INTERVAL '30 days'
			) AS recent_children_count,
			(SELECT COUNT(DISTINCT sightings.host_id)::int
			 FROM   certificates leaf
			 JOIN   observations o      ON o.cert_fingerprint = leaf.fingerprint_sha256
			 JOIN   host_ip_sightings sightings
			   ON   sightings.ip = o.server_ip
			  AND   o.observed_at BETWEEN sightings.first_seen AND sightings.last_seen
			 WHERE  leaf.issuer_cn = c.subject_cn
			   AND  leaf.is_ca = false
			   AND  sightings.host_id IS NOT NULL
			) AS host_impact,
			(SELECT COUNT(DISTINCT o.server_ip)::int
			 FROM   certificates leaf
			 JOIN   observations o ON o.cert_fingerprint = leaf.fingerprint_sha256
			 WHERE  leaf.issuer_cn = c.subject_cn
			   AND  leaf.is_ca = false
			   AND  NOT EXISTS (
			       SELECT 1
			       FROM   host_ip_sightings s
			       WHERE  s.ip = o.server_ip
			         AND  o.observed_at BETWEEN s.first_seen AND s.last_seen
			         AND  s.host_id IS NOT NULL
			   )
			) AS unattributed_ips
		FROM       certificates c
		LEFT JOIN  health_reports h ON c.fingerprint_sha256 = h.cert_fingerprint
		WHERE      c.is_ca = true
		  AND NOT EXISTS (
		      SELECT 1 FROM operator_declared_cas d
		      WHERE d.fingerprint_sha256 = c.fingerprint_sha256
		  )
		ORDER BY direct_children_count DESC, c.subject_cn ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list shadow cas: %w", err)
	}
	defer rows.Close()

	out := []ShadowCA{}
	for rows.Next() {
		var r ShadowCA
		if err := rows.Scan(
			&r.FingerprintSHA256, &r.SubjectCN, &r.SubjectOrg, &r.IssuerCN,
			&r.NotBefore, &r.NotAfter, &r.FirstSeen,
			&r.KeyAlgorithm, &r.KeySizeBits, &r.Grade,
			&r.DirectChildrenCount, &r.RecentChildrenCount,
			&r.HostImpact, &r.UnattributedIPs,
		); err != nil {
			return nil, fmt.Errorf("scan shadow ca row: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate shadow cas: %w", err)
	}
	return out, nil
}

// ListDeclaredCAs returns every row in operator_declared_cas joined
// with its cert identity, ordered by added_at DESC (most recently
// declared first — usually what an operator wants to see on visit).
func (s *PostgresStore) ListDeclaredCAs(ctx context.Context) ([]DeclaredCA, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			d.fingerprint_sha256,
			COALESCE(c.subject_cn, ''),
			COALESCE(c.subject_org, ''),
			d.added_at,
			COALESCE(d.added_by::text, '') AS added_by,
			d.owner_team,
			d.note,
			COALESCE(d.holder_host_id::text, '') AS holder_host_id
		FROM       operator_declared_cas d
		LEFT JOIN  certificates c ON c.fingerprint_sha256 = d.fingerprint_sha256
		ORDER BY   d.added_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list declared cas: %w", err)
	}
	defer rows.Close()

	out := []DeclaredCA{}
	for rows.Next() {
		var r DeclaredCA
		if err := rows.Scan(
			&r.FingerprintSHA256, &r.SubjectCN, &r.SubjectOrg,
			&r.AddedAt, &r.AddedBy, &r.OwnerTeam, &r.Note,
			&r.HolderHostID,
		); err != nil {
			return nil, fmt.Errorf("scan declared ca row: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeclareCA upserts a managed-CA declaration. Repeat calls on the same
// fingerprint update owner_team / note / added_by in place (not
// duplicated). Rejects with ErrCertNotFound if the fingerprint isn't
// in the certificates table (the FK would reject it anyway; we pre-
// check to give handlers a cleaner error boundary).
func (s *PostgresStore) DeclareCA(ctx context.Context, req *DeclareCARequest) error {
	if req == nil || req.FingerprintSHA256 == "" {
		return errors.New("DeclareCA: fingerprint_sha256 is required")
	}

	// Pre-check: confirm the fingerprint exists AND is a CA. The FK
	// enforces existence; the is_ca check is the semantic gate —
	// declaring a leaf cert as a "managed CA" is always an error.
	var isCA bool
	err := s.pool.QueryRow(ctx,
		`SELECT is_ca FROM certificates WHERE fingerprint_sha256 = $1`,
		req.FingerprintSHA256,
	).Scan(&isCA)
	if err == pgx.ErrNoRows {
		return fmt.Errorf("DeclareCA: fingerprint %s not in certificates", req.FingerprintSHA256)
	}
	if err != nil {
		return fmt.Errorf("DeclareCA precheck: %w", err)
	}
	if !isCA {
		return fmt.Errorf("DeclareCA: fingerprint %s is a leaf, not a CA", req.FingerprintSHA256)
	}

	var addedBy any
	if req.AddedBy != "" {
		addedBy = req.AddedBy
	}

	var holderHostID any
	if req.HolderHostID != "" {
		holderHostID = req.HolderHostID
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO operator_declared_cas
			(fingerprint_sha256, added_at, added_by, owner_team, note, holder_host_id)
		VALUES ($1, NOW(), $2, $3, $4, $5)
		ON CONFLICT (fingerprint_sha256) DO UPDATE SET
			added_at      = NOW(),
			added_by      = EXCLUDED.added_by,
			owner_team    = EXCLUDED.owner_team,
			note          = EXCLUDED.note,
			holder_host_id = EXCLUDED.holder_host_id
	`, req.FingerprintSHA256, addedBy, req.OwnerTeam, req.Note, holderHostID)
	if err != nil {
		return fmt.Errorf("DeclareCA upsert: %w", err)
	}
	return nil
}

// RevokeDeclaredCA removes a managed-CA declaration. Idempotent —
// revoking a fingerprint that isn't declared returns nil. The revoked
// CA will appear in ListShadowCAs on the next call (no lag).
func (s *PostgresStore) RevokeDeclaredCA(ctx context.Context, fingerprint string) error {
	if fingerprint == "" {
		return errors.New("RevokeDeclaredCA: fingerprint required")
	}
	_, err := s.pool.Exec(ctx,
		`DELETE FROM operator_declared_cas WHERE fingerprint_sha256 = $1`,
		fingerprint,
	)
	if err != nil {
		return fmt.Errorf("RevokeDeclaredCA: %w", err)
	}
	return nil
}

// IsDeclared is the fast boolean check used by the cert detail page
// to pick between "Managed" and "Shadow" pills. Returns (false, nil)
// for fingerprints not in operator_declared_cas — the absence-is-
// shadow semantic matches the ListShadowCAs left-anti-join shape.
func (s *PostgresStore) IsDeclared(ctx context.Context, fingerprint string) (bool, error) {
	if fingerprint == "" {
		return false, nil
	}
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM operator_declared_cas WHERE fingerprint_sha256 = $1)`,
		fingerprint,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("IsDeclared: %w", err)
	}
	return exists, nil
}
