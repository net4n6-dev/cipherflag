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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/net4n6-dev/cipherflag/internal/analysis/pqc"
)

// AssetRef is the polymorphic (asset_type, asset_id) pair used by
// the ownership resolver as a lookup key. asset_id is TEXT-uniform
// across asset types — certs use hex fingerprint, most others use
// UUID — matching the asset_provenance convention.
type AssetRef struct {
	AssetType string `json:"asset_type"`
	AssetID   string `json:"asset_id"`
}

// OwnershipSighting is one row in asset_ownership_sightings. See
// research/ownership-plan-v1.8.0.md §2.6 for schema rationale and
// migration 028 for the DB-level CHECK constraints.
type OwnershipSighting struct {
	ID           string         `json:"id,omitempty"`
	AssetType    string         `json:"asset_type"`
	AssetID      string         `json:"asset_id"`
	Team         string         `json:"team"`
	NamedOwner   string         `json:"named_owner,omitempty"`
	BusinessSvc  string         `json:"business_svc,omitempty"`
	Source       string         `json:"source"`
	Confidence   string         `json:"confidence"`
	FirstSeen    time.Time      `json:"first_seen"`
	LastSeen     time.Time      `json:"last_seen"`
	Evidence     map[string]any `json:"evidence,omitempty"`
	CreatedAt    time.Time      `json:"created_at,omitempty"`
}

// OwnershipClaim is a single attribution read by the resolver.
// Multiple claims can exist per asset; the resolver's job is to
// pick the strongest tier without throwing away the alternatives.
type OwnershipClaim struct {
	Team         string         `json:"team"`
	NamedOwner   string         `json:"named_owner,omitempty"`
	BusinessSvc  string         `json:"business_svc,omitempty"`
	Source       string         `json:"source"`
	Confidence   string         `json:"confidence"`
	FirstSeen    time.Time      `json:"first_seen"`
	LastSeen     time.Time      `json:"last_seen"`
	Evidence     map[string]any `json:"evidence,omitempty"`
}

// OwnershipResolution is what the resolver hands back per asset.
// Primary is the winner at the strongest tier. CoOwners holds every
// team tied at that tier (including Primary's team). Alternatives
// holds the weaker-tier fallbacks so the evidence chain stays
// visible. Unknown = true when the asset has no sightings.
type OwnershipResolution struct {
	AssetType    string           `json:"asset_type"`
	AssetID      string           `json:"asset_id"`
	Primary      *OwnershipClaim  `json:"primary,omitempty"`
	CoOwners     []OwnershipClaim `json:"co_owners,omitempty"`
	Alternatives []OwnershipClaim `json:"alternatives,omitempty"`
	Unknown      bool             `json:"unknown"`
}

// UnownedVulnerableAsset is one row in the ownership × HNDL
// cross-reference. Assets surface here when they carry a
// quantum-vulnerable algorithm AND the resolver returns either
// Unknown or a winning tier of 'observed' (per §2.7 predicate).
type UnownedVulnerableAsset struct {
	AssetType          string            `json:"asset_type"`
	AssetID            string            `json:"asset_id"`
	Label              string            `json:"label"`
	AlgorithmCanonical string            `json:"algorithm_canonical"`
	Classification     pqc.QuantumStatus `json:"classification"`
	HNDLAtRisk         bool              `json:"hndl_at_risk"`
	SensitiveUntil     time.Time         `json:"sensitive_until,omitempty"`
}

// UpsertOwnershipSighting inserts or merges a sighting on
// idx_aos_unique = (asset_type, asset_id, source, team). Same
// SELECT-then-INSERT-or-UPDATE pattern as UpsertHostIPSighting
// (host_ip_sightings.go:48). On merge, first_seen = LEAST(existing,
// new) and last_seen = GREATEST(existing, new); evidence is
// overwritten with the latest payload.
//
// Also inserts a skeleton teams(slug=sighting.Team) row via
// UpsertTeamSkeleton so the registry auto-populates as the ledger
// accumulates sightings (§2.9 auto-create).
func (s *PostgresStore) UpsertOwnershipSighting(ctx context.Context, sighting *OwnershipSighting) error {
	if sighting == nil {
		return fmt.Errorf("nil sighting")
	}
	if sighting.Team == "" {
		return fmt.Errorf("sighting team cannot be empty")
	}

	evidenceJSON, err := json.Marshal(sighting.Evidence)
	if err != nil {
		return fmt.Errorf("marshal sighting evidence: %w", err)
	}
	if len(evidenceJSON) == 0 || string(evidenceJSON) == "null" {
		evidenceJSON = []byte("{}")
	}

	var existingID string
	err = s.pool.QueryRow(ctx, `
		SELECT id FROM asset_ownership_sightings
		WHERE asset_type = $1 AND asset_id = $2
		  AND source = $3 AND team = $4
	`, sighting.AssetType, sighting.AssetID, sighting.Source, sighting.Team).Scan(&existingID)

	if err == pgx.ErrNoRows {
		err = s.pool.QueryRow(ctx, `
			INSERT INTO asset_ownership_sightings (
				asset_type, asset_id, team, named_owner, business_svc,
				source, confidence, first_seen, last_seen, evidence
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			RETURNING id, created_at
		`,
			sighting.AssetType, sighting.AssetID, sighting.Team,
			sighting.NamedOwner, sighting.BusinessSvc,
			sighting.Source, sighting.Confidence,
			sighting.FirstSeen, sighting.LastSeen, evidenceJSON,
		).Scan(&sighting.ID, &sighting.CreatedAt)
		if err != nil {
			return fmt.Errorf("insert ownership sighting: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("lookup existing ownership sighting: %w", err)
	} else {
		_, err = s.pool.Exec(ctx, `
			UPDATE asset_ownership_sightings SET
				named_owner = $2,
				business_svc = $3,
				confidence = $4,
				first_seen = LEAST(first_seen, $5),
				last_seen = GREATEST(last_seen, $6),
				evidence = $7
			WHERE id = $1
		`,
			existingID,
			sighting.NamedOwner, sighting.BusinessSvc, sighting.Confidence,
			sighting.FirstSeen, sighting.LastSeen, evidenceJSON,
		)
		if err != nil {
			return fmt.Errorf("update ownership sighting: %w", err)
		}
		sighting.ID = existingID
	}

	// CE-flavor: teams registry (migration 029) is EE-only. The
	// sighting carries the team slug as plain text; without the
	// teams table there is no FK relationship to maintain, so no
	// auto-create step is needed.

	return nil
}

// DeleteOwnershipSighting removes one sighting by primary key.
// Admin-gated at the API layer; at store level this is just a
// delete. Used by the operator-stamp revoke path.
func (s *PostgresStore) DeleteOwnershipSighting(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("sighting id cannot be empty")
	}
	_, err := s.pool.Exec(ctx, `
		DELETE FROM asset_ownership_sightings WHERE id = $1
	`, id)
	if err != nil {
		return fmt.Errorf("delete ownership sighting %q: %w", id, err)
	}
	return nil
}

// DeleteOwnershipStamp removes the operator_stamp sighting matching
// (asset_type, asset_id, team). Only operator_stamp rows are
// revokable — inferred/observed regenerate on next scan. Handler
// validates the source param is 'operator_stamp'; this function
// exists for the common API path.
func (s *PostgresStore) DeleteOwnershipStamp(ctx context.Context, assetType, assetID, team string) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM asset_ownership_sightings
		WHERE asset_type = $1 AND asset_id = $2
		  AND source = 'operator_stamp' AND team = $3
	`, assetType, assetID, team)
	if err != nil {
		return fmt.Errorf("delete operator stamp: %w", err)
	}
	return nil
}

// ResolveOwner fetches every sighting for (assetType, assetID) and
// picks a winner by tier. When assetType == "finding", delegates to
// the source asset's resolution (see §2.1 — findings don't have
// independent ownership).
func (s *PostgresStore) ResolveOwner(ctx context.Context, assetType, assetID string) (*OwnershipResolution, error) {
	if assetType == "finding" {
		return s.resolveFindingOwner(ctx, assetID)
	}
	claims, err := s.fetchClaims(ctx, assetType, assetID)
	if err != nil {
		return nil, err
	}
	return resolveFromClaims(assetType, assetID, claims), nil
}

// resolveFindingOwner reads the source (asset_type, asset_id) from
// asset_health_reports (the finding ID is the report's primary key)
// and recursively resolves the source asset's ownership. Unknown
// when the report doesn't exist.
func (s *PostgresStore) resolveFindingOwner(ctx context.Context, reportID string) (*OwnershipResolution, error) {
	var srcType, srcID string
	err := s.pool.QueryRow(ctx, `
		SELECT asset_type, asset_id FROM asset_health_reports WHERE id = $1
	`, reportID).Scan(&srcType, &srcID)
	if err == pgx.ErrNoRows {
		return &OwnershipResolution{AssetType: "finding", AssetID: reportID, Unknown: true}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("delegate finding ownership: %w", err)
	}

	res, err := s.ResolveOwner(ctx, srcType, srcID)
	if err != nil {
		return nil, err
	}
	// Preserve the finding's identity in the returned resolution so
	// the caller sees what was looked up while the teams come from
	// the source asset.
	res.AssetType = "finding"
	res.AssetID = reportID
	return res, nil
}

// ResolveOwnerBatch is the single-query batch resolver used by the
// extended HNDL response (§2.7) and the /applications/{tag}/
// ownership-rollup endpoint (§2.8). Avoids N+1 round-trips at
// listing-page render. Findings are silently skipped — the caller
// is expected to pre-flatten finding references to their source
// assets before batching.
func (s *PostgresStore) ResolveOwnerBatch(ctx context.Context, refs []AssetRef) (map[AssetRef]*OwnershipResolution, error) {
	out := make(map[AssetRef]*OwnershipResolution, len(refs))
	if len(refs) == 0 {
		return out, nil
	}

	types := make([]string, 0, len(refs))
	ids := make([]string, 0, len(refs))
	for _, r := range refs {
		if r.AssetType == "finding" {
			// Caller responsibility; batch doesn't delegate.
			out[r] = &OwnershipResolution{AssetType: r.AssetType, AssetID: r.AssetID, Unknown: true}
			continue
		}
		types = append(types, r.AssetType)
		ids = append(ids, r.AssetID)
	}
	if len(types) == 0 {
		return out, nil
	}

	rows, err := s.pool.Query(ctx, `
		WITH req(asset_type, asset_id) AS (
			SELECT UNNEST($1::TEXT[]), UNNEST($2::TEXT[])
		)
		SELECT s.asset_type, s.asset_id, s.team, s.named_owner, s.business_svc,
		       s.source, s.confidence, s.first_seen, s.last_seen, s.evidence
		FROM asset_ownership_sightings s
		JOIN req USING (asset_type, asset_id)
	`, types, ids)
	if err != nil {
		return nil, fmt.Errorf("batch resolve: %w", err)
	}
	defer rows.Close()

	grouped := map[AssetRef][]OwnershipClaim{}
	for rows.Next() {
		var at, aid string
		var claim OwnershipClaim
		var evidenceJSON []byte
		if err := rows.Scan(&at, &aid, &claim.Team, &claim.NamedOwner, &claim.BusinessSvc,
			&claim.Source, &claim.Confidence, &claim.FirstSeen, &claim.LastSeen, &evidenceJSON); err != nil {
			return nil, fmt.Errorf("scan batch claim: %w", err)
		}
		if len(evidenceJSON) > 0 && string(evidenceJSON) != "null" {
			_ = json.Unmarshal(evidenceJSON, &claim.Evidence)
		}
		key := AssetRef{AssetType: at, AssetID: aid}
		grouped[key] = append(grouped[key], claim)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("batch resolve rows: %w", err)
	}

	for _, r := range refs {
		if r.AssetType == "finding" {
			continue // already handled above
		}
		out[r] = resolveFromClaims(r.AssetType, r.AssetID, grouped[r])
	}
	return out, nil
}

// fetchClaims reads every sighting for one asset, returning them
// in arbitrary order. The tier-picking logic lives in
// resolveFromClaims so it stays testable without a DB.
func (s *PostgresStore) fetchClaims(ctx context.Context, assetType, assetID string) ([]OwnershipClaim, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT team, named_owner, business_svc, source, confidence,
		       first_seen, last_seen, evidence
		FROM asset_ownership_sightings
		WHERE asset_type = $1 AND asset_id = $2
	`, assetType, assetID)
	if err != nil {
		return nil, fmt.Errorf("fetch ownership claims: %w", err)
	}
	defer rows.Close()

	claims := []OwnershipClaim{}
	for rows.Next() {
		var claim OwnershipClaim
		var evidenceJSON []byte
		if err := rows.Scan(&claim.Team, &claim.NamedOwner, &claim.BusinessSvc,
			&claim.Source, &claim.Confidence, &claim.FirstSeen, &claim.LastSeen, &evidenceJSON); err != nil {
			return nil, fmt.Errorf("scan claim: %w", err)
		}
		if len(evidenceJSON) > 0 && string(evidenceJSON) != "null" {
			_ = json.Unmarshal(evidenceJSON, &claim.Evidence)
		}
		claims = append(claims, claim)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("fetch claims rows: %w", err)
	}
	return claims, nil
}

// resolveFromClaims is the pure-function tier picker. Returned
// resolution's Primary is the first co-owner at the winning tier,
// CoOwners holds every distinct team tied at that tier, and
// Alternatives holds the weaker-tier fallbacks. Pure — no DB
// dependency — so unit-testable.
func resolveFromClaims(assetType, assetID string, claims []OwnershipClaim) *OwnershipResolution {
	res := &OwnershipResolution{AssetType: assetType, AssetID: assetID}
	if len(claims) == 0 {
		res.Unknown = true
		return res
	}

	maxRank := 0
	for _, c := range claims {
		if r := tierRank(c.Confidence); r > maxRank {
			maxRank = r
		}
	}

	teamSeen := map[string]bool{}
	for _, c := range claims {
		if tierRank(c.Confidence) == maxRank {
			if !teamSeen[c.Team] {
				teamSeen[c.Team] = true
				res.CoOwners = append(res.CoOwners, c)
			}
		} else {
			res.Alternatives = append(res.Alternatives, c)
		}
	}
	if len(res.CoOwners) > 0 {
		primary := res.CoOwners[0]
		res.Primary = &primary
	}
	return res
}

// tierRank maps the four confidence tiers to an integer so
// resolveFromClaims can compare by max. direct=4 (strongest),
// observed=1 (weakest), unknown tier = 0 (skipped at max
// comparison, which means unknown-tier rows are effectively
// ignored — defensive against future source additions).
func tierRank(conf string) int {
	switch conf {
	case "direct":
		return 4
	case "attested":
		return 3
	case "inferred":
		return 2
	case "observed":
		return 1
	default:
		return 0
	}
}

// ListUnownedVulnerableAssets intersects the v1.7.0
// weak-algorithm scanner with the ownership ledger. Predicate:
// asset is quantum-vulnerable AND (no sighting exists OR winning
// tier is 'observed'). See §2.7 — this is what powers the
// /analysis/hndl unowned filter pill.
func (s *PostgresStore) ListUnownedVulnerableAssets(ctx context.Context, horizonYear int) ([]UnownedVulnerableAsset, error) {
	weak, err := s.ListWeakAlgorithmOccurrences(ctx, WeakAlgoFilter{IncludeVulnerable: true})
	if err != nil {
		return nil, fmt.Errorf("weak-algo scan: %w", err)
	}
	hndl, err := s.ListHNDLAtRiskAssets(ctx, horizonYear)
	if err != nil {
		return nil, fmt.Errorf("hndl at-risk scan: %w", err)
	}
	hndlByKey := map[AssetRef]HNDLAtRiskAsset{}
	for _, h := range hndl {
		hndlByKey[AssetRef{AssetType: h.AssetType, AssetID: h.AssetID}] = h
	}

	// Dedup the weak-algo rows by (asset_type, asset_id) — one asset
	// can emit multiple rows (e.g., cert with both weak key_algorithm
	// and weak signature_algorithm). First occurrence wins for the
	// display label + classification; this is consistent with how the
	// v1.7.0 HNDL listing dedups.
	seen := map[AssetRef]bool{}
	refs := make([]AssetRef, 0, len(weak))
	dedupedWeak := []WeakAlgoOccurrence{}
	for _, w := range weak {
		key := AssetRef{AssetType: w.AssetType, AssetID: w.AssetID}
		if seen[key] {
			continue
		}
		seen[key] = true
		refs = append(refs, key)
		dedupedWeak = append(dedupedWeak, w)
	}

	resolutions, err := s.ResolveOwnerBatch(ctx, refs)
	if err != nil {
		return nil, fmt.Errorf("batch resolve for unowned: %w", err)
	}

	out := []UnownedVulnerableAsset{}
	for i, w := range dedupedWeak {
		key := refs[i]
		res := resolutions[key]
		// Keep the row if unowned (no sightings) or best-tier is observed.
		if res != nil && !res.Unknown && res.Primary != nil {
			if tierRank(res.Primary.Confidence) > tierRank("observed") {
				continue
			}
		}
		row := UnownedVulnerableAsset{
			AssetType:          w.AssetType,
			AssetID:            w.AssetID,
			Label:              w.Label,
			AlgorithmCanonical: w.AlgorithmCanonical,
			Classification:     w.Classification,
		}
		if h, ok := hndlByKey[key]; ok {
			row.HNDLAtRisk = !h.Unscoped
			row.SensitiveUntil = h.SensitiveUntil
		}
		out = append(out, row)
	}
	return out, nil
}

// applicationTagsTables lists the 7 asset tables carrying
// application_tags (migration 021) paired with their canonical
// asset_type singular-form string and the column that serves as
// asset_id. Drives the generic backfill / delete passes.
var applicationTagsTables = []struct {
	assetType string
	table     string
	idExpr    string // SQL expression producing the asset_id TEXT value
}{
	{"certificate", "certificates", "fingerprint_sha256"},
	{"ssh_key", "ssh_keys", "id::text"},
	{"crypto_library", "crypto_libraries", "id::text"},
	{"crypto_config", "crypto_configs", "id::text"},
	{"protocol_endpoint", "protocol_endpoints", "id::text"},
	{"host", "hosts", "id::text"},
	{"repository", "repositories", "id::text"},
}

// BackfillOwnershipFromApplicationMetadata refreshes every
// attested-tier sighting whose source is 'application_metadata'.
// Per §2.5 replacement semantics (user decision #2, option a): when
// a tag's owner_team changes, the old team's sightings for that
// tag's assets are deleted before new team's sightings are inserted.
// Idempotent — safe to call repeatedly. Returns the count of
// (asset, team) rows written.
func (s *PostgresStore) BackfillOwnershipFromApplicationMetadata(ctx context.Context) (int, error) {
	metas, err := s.ListApplicationMetadata(ctx)
	if err != nil {
		return 0, fmt.Errorf("list application_metadata: %w", err)
	}
	written := 0
	for _, m := range metas {
		if m.OwnerTeam == "" {
			continue // no team declared → nothing to attest
		}
		n, err := s.backfillOneTag(ctx, m.Tag, m.OwnerTeam)
		if err != nil {
			return written, fmt.Errorf("backfill tag %q: %w", m.Tag, err)
		}
		written += n
	}
	return written, nil
}

// backfillOneTag does the option-(a) replace-then-upsert for one
// (tag, team) pair across every application_tags table. Each
// asset-table pass runs in its own transaction so lock scope stays
// narrow on large estates — same pattern noted in the plan's
// Risks + mitigations table for handling 100k+ asset backfills.
func (s *PostgresStore) backfillOneTag(ctx context.Context, tag, ownerTeam string) (int, error) {
	evidence := map[string]any{"tag": tag}
	evidenceJSON, err := json.Marshal(evidence)
	if err != nil {
		return 0, fmt.Errorf("marshal tag evidence: %w", err)
	}

	written := 0
	for _, t := range applicationTagsTables {
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return written, fmt.Errorf("begin tx for %s: %w", t.table, err)
		}
		// Option (a) replacement: remove prior application_metadata
		// sightings for this tag's assets whose team doesn't match.
		deleteSQL := fmt.Sprintf(`
			DELETE FROM asset_ownership_sightings
			WHERE source = 'application_metadata'
			  AND asset_type = $1
			  AND team != $2
			  AND asset_id IN (
				  SELECT %s FROM %s WHERE application_tags @> ARRAY[$3]::text[]
			  )
		`, t.idExpr, t.table)
		if _, err := tx.Exec(ctx, deleteSQL, t.assetType, ownerTeam, tag); err != nil {
			_ = tx.Rollback(ctx)
			return written, fmt.Errorf("delete stale %s sightings: %w", t.table, err)
		}
		// Upsert the current (tag, team) sighting per asset.
		upsertSQL := fmt.Sprintf(`
			INSERT INTO asset_ownership_sightings (
				asset_type, asset_id, team, source, confidence,
				first_seen, last_seen, evidence
			)
			SELECT $1, %s, $2, 'application_metadata', 'attested',
			       NOW(), NOW(), $3::jsonb
			FROM %s WHERE application_tags @> ARRAY[$4]::text[]
			ON CONFLICT (asset_type, asset_id, source, team) DO UPDATE SET
				last_seen = NOW(),
				evidence = EXCLUDED.evidence
		`, t.idExpr, t.table)
		cmd, err := tx.Exec(ctx, upsertSQL, t.assetType, ownerTeam, evidenceJSON, tag)
		if err != nil {
			_ = tx.Rollback(ctx)
			return written, fmt.Errorf("upsert %s sightings: %w", t.table, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return written, fmt.Errorf("commit %s tx: %w", t.table, err)
		}
		written += int(cmd.RowsAffected())
	}

	// CE-flavor: teams registry is EE-only; team slug carries through
	// as plain text without a registry skeleton.
	return written, nil
}

// BackfillOwnershipFromDeclaredCAs copies each
// operator_declared_cas.owner_team onto the matching CA certificate
// as an attested sighting. Same replacement semantics as
// application_metadata: changing a declared CA's owner_team
// deletes the prior team row.
func (s *PostgresStore) BackfillOwnershipFromDeclaredCAs(ctx context.Context) (int, error) {
	cas, err := s.ListDeclaredCAs(ctx)
	if err != nil {
		return 0, fmt.Errorf("list declared cas: %w", err)
	}
	written := 0
	for _, c := range cas {
		if c.OwnerTeam == "" {
			continue
		}
		evidenceJSON, _ := json.Marshal(map[string]any{"fingerprint": c.FingerprintSHA256})

		// Remove stale team rows for this CA cert.
		if _, err := s.pool.Exec(ctx, `
			DELETE FROM asset_ownership_sightings
			WHERE source = 'declared_ca'
			  AND asset_type = 'certificate'
			  AND asset_id = $1
			  AND team != $2
		`, c.FingerprintSHA256, c.OwnerTeam); err != nil {
			return written, fmt.Errorf("delete stale declared_ca sighting: %w", err)
		}

		if err := s.UpsertOwnershipSighting(ctx, &OwnershipSighting{
			AssetType:  "certificate",
			AssetID:    c.FingerprintSHA256,
			Team:       c.OwnerTeam,
			Source:     "declared_ca",
			Confidence: "attested",
			FirstSeen:  time.Now(),
			LastSeen:   time.Now(),
			Evidence:   map[string]any{"fingerprint": c.FingerprintSHA256},
		}); err != nil {
			return written, fmt.Errorf("upsert declared_ca sighting: %w", err)
		}
		_ = evidenceJSON // the Upsert helper re-marshals; keeping the variable silences lint
		written++
	}
	return written, nil
}

// BackfillOwnershipFromCertSubjects extracts cert subject
// Organization / OrganizationalUnit as an inferred-tier
// attribution. Skips CA certs (is_ca=true — inferring ownership
// from a CA's own name is semantically wrong), short / geographic
// / placeholder tokens, and personal-email markers.
func (s *PostgresStore) BackfillOwnershipFromCertSubjects(ctx context.Context) (int, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT fingerprint_sha256, subject_org, subject_ou
		FROM certificates
		WHERE is_ca = false
	`)
	if err != nil {
		return 0, fmt.Errorf("scan cert subjects: %w", err)
	}
	defer rows.Close()

	written := 0
	for rows.Next() {
		var fp, org, ou string
		if err := rows.Scan(&fp, &org, &ou); err != nil {
			return written, fmt.Errorf("scan cert row: %w", err)
		}
		team := inferTeamFromCertSubject(org, ou)
		if team == "" {
			continue
		}
		if err := s.UpsertOwnershipSighting(ctx, &OwnershipSighting{
			AssetType:  "certificate",
			AssetID:    fp,
			Team:       team,
			Source:     "cert_subject",
			Confidence: "inferred",
			FirstSeen:  time.Now(),
			LastSeen:   time.Now(),
			Evidence:   map[string]any{"organization": org, "organizational_unit": ou},
		}); err != nil {
			return written, fmt.Errorf("upsert cert_subject sighting: %w", err)
		}
		written++
	}
	if err := rows.Err(); err != nil {
		return written, fmt.Errorf("cert subject rows: %w", err)
	}
	return written, nil
}

// inferTeamFromCertSubject applies the filter rules from §5 Risks
// + mitigations to choose whether an O/OU pair is strong enough
// evidence to claim as inferred ownership. Returns "" to skip.
func inferTeamFromCertSubject(org, ou string) string {
	pick := strings.TrimSpace(org)
	if pick == "" {
		pick = strings.TrimSpace(ou)
	}
	if pick == "" {
		return ""
	}
	// Length + placeholder filter.
	if len(pick) < 3 {
		return ""
	}
	lower := strings.ToLower(pick)
	placeholder := []string{
		"unknown", "organization", "internet widgits", "example",
		"test", "default", "n/a", "none",
	}
	for _, p := range placeholder {
		if strings.Contains(lower, p) {
			return ""
		}
	}
	// CA-name filter — inferring a cert owner from its issuer-matching
	// O is nonsense when subject looks like a CA name.
	caMarkers := []string{" ca ", " ca,", "ca ", "certificate authority", "root ca", " root ", "intermediate "}
	padded := " " + lower + " "
	for _, m := range caMarkers {
		if strings.Contains(padded, m) {
			return ""
		}
	}
	// Geographic-only tokens (country codes, 2-letter state codes).
	if len(pick) <= 3 && strings.ToUpper(pick) == pick {
		return ""
	}
	return slugify(pick)
}

// personalEmailDomains is the skip list for the v1.8.1 ssh_comment
// producer. Matches the v1.8.0 plan §5 Risks-table rationale: an
// observed-tier attribution pointing at a personal-provider domain is
// noise, not signal. Same list is intended to be reused by the future
// git_author producer.
var personalEmailDomains = map[string]bool{
	"gmail.com":      true,
	"outlook.com":    true,
	"hotmail.com":    true,
	"yahoo.com":      true,
	"protonmail.com": true,
	"icloud.com":     true,
}

// InferTeamFromSSHComment extracts a team slug from an SSH key
// comment. Only comments shaped like `<local>@<domain>` produce a
// result; everything else returns "". Personal-email providers
// (gmail / outlook / hotmail / yahoo / protonmail / icloud) are
// filtered because an observed-tier attribution to a personal
// provider is noise.
//
// Domain parsing drops the TLD and any label containing a digit
// (treated as a hostname prefix, e.g. `ops-01`) — the surviving
// pure-alpha labels are the organizational portion and are joined
// with dashes. Examples:
//
//	alice@ops-01.acme.com         → acme
//	bob@fintech.example.com       → fintech-example
//	charlie@web-01.prod-02.co     → ""  (every non-TLD label is hostname-shaped)
//
// Slug-normalised via the shared slugify helper so this path and
// the cert-subject inferrer produce byte-equal output for the same
// logical input.
//
// Exported so internal/ingest/dedup can call it without exposing
// the package-private inference helpers. See
// research/ownership-plan-v1.8.1.md §3.2.
func InferTeamFromSSHComment(comment string) string {
	c := strings.TrimSpace(comment)
	at := strings.LastIndex(c, "@")
	if at <= 0 || at == len(c)-1 {
		return ""
	}
	domain := strings.ToLower(strings.TrimSpace(c[at+1:]))
	if personalEmailDomains[domain] {
		return ""
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return ""
	}
	// Drop the TLD (last label) and filter out hostname-like labels
	// (anything containing a digit). Pure-alpha survivors are joined
	// with dashes to form the organizational portion.
	orgLabels := make([]string, 0, len(labels)-1)
	for _, l := range labels[:len(labels)-1] {
		if strings.ContainsAny(l, "0123456789") {
			continue
		}
		orgLabels = append(orgLabels, l)
	}
	if len(orgLabels) == 0 {
		return ""
	}
	return slugify(strings.Join(orgLabels, "-"))
}

// slugify is the shared normalisation used by inferTeamFromCertSubject
// and InferTeamFromSSHComment. Lowercases, maps spaces / `-` / `_` /
// `.` to `-`, drops every other non-alnum rune, collapses repeated
// dashes, trims leading/trailing dashes, and returns "" for results
// shorter than 3 characters.
//
// Extracted in v1.8.1 so the cert-subject and ssh-comment inferrers
// produce byte-equal output for the same input — important because
// the resolver's same-tier dedup is by team slug, so drift between
// the two paths would surface duplicate co-owners for assets carrying
// both source types.
func slugify(s string) string {
	slug := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		case r == ' ', r == '-', r == '_', r == '.':
			return '-'
		default:
			return -1
		}
	}, s)
	for strings.Contains(slug, "--") {
		slug = strings.ReplaceAll(slug, "--", "-")
	}
	slug = strings.Trim(slug, "-")
	if len(slug) < 3 {
		return ""
	}
	return slug
}

// SlugifyTeam normalises a raw team identifier into the canonical
// slug form used across every ownership-sighting source. Returns "" for
// inputs shorter than 3 chars after normalisation, or inputs that
// contain only non-alphanumeric runes. Consumers outside this package
// (the ingester's sighting_agent fan-out) use this helper so their
// output is byte-equal to cert_subject / ssh_comment results — the
// resolver's same-tier dedup is by team slug, so drift between
// producer paths would surface duplicate co-owners.
func SlugifyTeam(raw string) string {
	return slugify(raw)
}

// PruneStaleOwnershipSightings removes inferred/observed sightings
// whose owning asset hasn't been seen in `maxAge`. direct +
// attested rows are exempt — they represent explicit operator
// intent or current registry state.
func (s *PostgresStore) PruneStaleOwnershipSightings(ctx context.Context, maxAge time.Duration) (int, error) {
	cutoff := time.Now().Add(-maxAge)
	cmd, err := s.pool.Exec(ctx, `
		DELETE FROM asset_ownership_sightings
		WHERE confidence IN ('inferred', 'observed')
		  AND last_seen < $1
	`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune stale sightings: %w", err)
	}
	return int(cmd.RowsAffected()), nil
}
