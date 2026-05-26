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
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// ApplicationMetadata is one tag-keyed metadata row backing the HNDL
// (Harvest Now, Decrypt Later) risk analysis. See
// research/hndl-plan-v1.7.0.md §2.
//
// Either DataTTLYears OR DataSensitiveUntil MUST be populated. A
// CHECK constraint at the DB enforces this.
type ApplicationMetadata struct {
	Tag                string     `json:"tag"`
	DataTTLYears       *int       `json:"data_ttl_years,omitempty"`
	DataSensitiveUntil *time.Time `json:"data_sensitive_until,omitempty"`
	OwnerTeam          string     `json:"owner_team"`
	Note               string     `json:"note"`
	AddedBy            string     `json:"added_by,omitempty"` // user UUID; empty if FK-SET-NULL'd
	AddedAt            time.Time  `json:"added_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// EffectiveSensitiveUntil returns the absolute date past which the
// application's data must remain confidential. DataSensitiveUntil wins
// if set (operator-declared sunset); otherwise derived from AddedAt +
// DataTTLYears. Returns zero-time if neither field is populated (which
// should be impossible due to the CHECK constraint, but the caller
// handles it defensively).
func (m *ApplicationMetadata) EffectiveSensitiveUntil() time.Time {
	if m.DataSensitiveUntil != nil {
		return *m.DataSensitiveUntil
	}
	if m.DataTTLYears != nil {
		return m.AddedAt.AddDate(*m.DataTTLYears, 0, 0)
	}
	return time.Time{}
}

// DeclareApplicationMetadataRequest is the upsert payload.
type DeclareApplicationMetadataRequest struct {
	Tag                string
	DataTTLYears       *int
	DataSensitiveUntil *time.Time
	OwnerTeam          string
	Note               string
	AddedBy            string
}

// HNDLAtRiskAsset is one row in the HNDL at-risk listing. An asset is
// "at-risk" when its cryptography is quantum-vulnerable AND the
// maximum effective_sensitive_until across its application tags meets
// or exceeds the CRQC horizon year.
//
// Unscoped vulnerable assets (no application tags or no metadata for
// any tag) are returned with Unscoped=true and empty TTL fields so
// the frontend can render them in the same table with a visual
// distinction (user decision #3 on the plan).
type HNDLAtRiskAsset struct {
	AssetType          string    `json:"asset_type"`
	AssetID            string    `json:"asset_id"`
	Label              string    `json:"label"`
	Algorithm          string    `json:"algorithm"`
	AlgorithmCanonical string    `json:"algorithm_canonical"`
	ApplicationTags    []string  `json:"application_tags"`
	MaxTTLYears        int       `json:"max_ttl_years,omitempty"`    // 0 when unscoped
	SensitiveUntil     time.Time `json:"sensitive_until,omitempty"` // zero when unscoped
	Unscoped           bool      `json:"unscoped"`
}

// UpsertApplicationMetadata inserts or updates by tag. Re-declaring
// the same tag updates the metadata + refreshes updated_at without
// creating a duplicate.
func (s *PostgresStore) UpsertApplicationMetadata(ctx context.Context, req *DeclareApplicationMetadataRequest) error {
	if req == nil || req.Tag == "" {
		return errors.New("UpsertApplicationMetadata: tag is required")
	}
	if req.DataTTLYears == nil && req.DataSensitiveUntil == nil {
		return errors.New("UpsertApplicationMetadata: data_ttl_years or data_sensitive_until must be set")
	}
	var addedBy any
	if req.AddedBy != "" {
		addedBy = req.AddedBy
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO application_metadata
			(tag, data_ttl_years, data_sensitive_until, owner_team, note, added_by, added_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
		ON CONFLICT (tag) DO UPDATE SET
			data_ttl_years       = EXCLUDED.data_ttl_years,
			data_sensitive_until = EXCLUDED.data_sensitive_until,
			owner_team           = EXCLUDED.owner_team,
			note                 = EXCLUDED.note,
			updated_at           = NOW()
	`, req.Tag, req.DataTTLYears, req.DataSensitiveUntil, req.OwnerTeam, req.Note, addedBy)
	if err != nil {
		return fmt.Errorf("upsert application_metadata: %w", err)
	}
	return nil
}

// GetApplicationMetadata returns a single row by tag. nil, nil when
// no declaration exists for the tag.
func (s *PostgresStore) GetApplicationMetadata(ctx context.Context, tag string) (*ApplicationMetadata, error) {
	if tag == "" {
		return nil, nil
	}
	var m ApplicationMetadata
	var ttl *int
	var until *time.Time
	var addedBy *string
	err := s.pool.QueryRow(ctx, `
		SELECT tag, data_ttl_years, data_sensitive_until,
		       owner_team, note, added_by::text, added_at, updated_at
		FROM application_metadata
		WHERE tag = $1
	`, tag).Scan(&m.Tag, &ttl, &until, &m.OwnerTeam, &m.Note, &addedBy, &m.AddedAt, &m.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get application_metadata: %w", err)
	}
	m.DataTTLYears = ttl
	m.DataSensitiveUntil = until
	if addedBy != nil {
		m.AddedBy = *addedBy
	}
	return &m, nil
}

// ListApplicationMetadata returns every declared row ordered by
// updated_at DESC (most recently modified first).
func (s *PostgresStore) ListApplicationMetadata(ctx context.Context) ([]ApplicationMetadata, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT tag, data_ttl_years, data_sensitive_until,
		       owner_team, note, COALESCE(added_by::text, ''), added_at, updated_at
		FROM application_metadata
		ORDER BY updated_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list application_metadata: %w", err)
	}
	defer rows.Close()
	out := []ApplicationMetadata{}
	for rows.Next() {
		var m ApplicationMetadata
		var ttl *int
		var until *time.Time
		if err := rows.Scan(&m.Tag, &ttl, &until, &m.OwnerTeam, &m.Note,
			&m.AddedBy, &m.AddedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		m.DataTTLYears = ttl
		m.DataSensitiveUntil = until
		out = append(out, m)
	}
	return out, rows.Err()
}

// DeleteApplicationMetadata removes a declaration by tag. Idempotent
// — deleting an unknown tag returns nil.
func (s *PostgresStore) DeleteApplicationMetadata(ctx context.Context, tag string) error {
	if tag == "" {
		return errors.New("DeleteApplicationMetadata: tag is required")
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM application_metadata WHERE tag = $1`, tag)
	if err != nil {
		return fmt.Errorf("delete application_metadata: %w", err)
	}
	return nil
}

// ListHNDLAtRiskAssets returns vulnerable assets whose application-tag
// metadata crosses the CRQC horizon, plus vulnerable assets with no
// usable metadata (Unscoped=true).
//
// Algorithm (per plan §2.4):
//  1. Build tag → effective_sensitive_until map from application_metadata.
//  2. Pull vulnerable occurrences via ListWeakAlgorithmOccurrences.
//  3. Per asset type, batch-fetch (asset_id, application_tags).
//  4. For each occurrence: max across tags' effective_sensitive_until.
//     - No tags / no metadata for any tag → unscoped, included.
//     - Max ≥ CRQC horizon → at-risk, included.
//     - Max < CRQC horizon → clear, excluded.
//
// crqcHorizonYear default per plan §2.3 is 2030 (CNSA 2.0 transition).
// Caller passes the integer year; we compare against Jan 1 of that year.
func (s *PostgresStore) ListHNDLAtRiskAssets(ctx context.Context, crqcHorizonYear int) ([]HNDLAtRiskAsset, error) {
	horizon := time.Date(crqcHorizonYear, 1, 1, 0, 0, 0, 0, time.UTC)

	// 1. Tag → effective_sensitive_until.
	tagUntil := map[string]time.Time{}
	tagTTL := map[string]int{}
	rows, err := s.pool.Query(ctx, `
		SELECT tag,
		       COALESCE(data_ttl_years, 0),
		       COALESCE(data_sensitive_until,
		                added_at + (data_ttl_years || ' years')::interval) AS effective_until
		FROM application_metadata
		WHERE data_ttl_years IS NOT NULL OR data_sensitive_until IS NOT NULL
	`)
	if err != nil {
		return nil, fmt.Errorf("hndl: read application_metadata: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var tag string
		var ttl int
		var eff time.Time
		if err := rows.Scan(&tag, &ttl, &eff); err != nil {
			return nil, err
		}
		tagUntil[tag] = eff
		tagTTL[tag] = ttl
	}

	// 2. Vulnerable occurrences across all asset types.
	occs, err := s.ListWeakAlgorithmOccurrences(ctx, WeakAlgoFilter{IncludeVulnerable: true})
	if err != nil {
		return nil, fmt.Errorf("hndl: list weak occurrences: %w", err)
	}
	if len(occs) == 0 {
		return []HNDLAtRiskAsset{}, nil
	}

	// 3. Per asset type, batch-fetch application_tags for the asset IDs
	// we care about. Reduces query count from N-per-occurrence to
	// one-per-asset-type.
	byType := map[string][]string{}
	for _, o := range occs {
		byType[o.AssetType] = append(byType[o.AssetType], o.AssetID)
	}
	assetTags := map[string][]string{} // key: assetType|assetID
	for assetType, ids := range byType {
		table, idCol, err := tagTableForAssetType(assetType)
		if err != nil {
			// Unknown asset type — skip. Weak-algo scanner supports 5
			// types; any drift is a dev-time bug we surface loudly.
			return nil, err
		}
		q := fmt.Sprintf(`SELECT %s::text, application_tags FROM %s WHERE %s::text = ANY($1)`,
			idCol, table, idCol)
		rows, err := s.pool.Query(ctx, q, ids)
		if err != nil {
			return nil, fmt.Errorf("hndl: fetch tags for %s: %w", assetType, err)
		}
		for rows.Next() {
			var id string
			var tags []string
			if err := rows.Scan(&id, &tags); err != nil {
				rows.Close()
				return nil, err
			}
			assetTags[assetType+"|"+id] = tags
		}
		rows.Close()
	}

	// 4. Evaluate the HNDL predicate per occurrence. Dedup by
	// (asset_type, asset_id) — the weak-algorithm scanner emits one
	// row per (asset, algorithm) pair, so a cert with both a weak
	// key_algorithm AND a weak signature_algorithm lands twice. Tags
	// + TTL are properties of the asset, not the algorithm, so the
	// duplicates would carry identical HNDL metadata and confuse the
	// UI's keyed each-block. First occurrence wins; the algorithm
	// field of the retained row reflects whichever algorithm the
	// scanner enumerated first (deterministic per-asset-type order).
	seenAssets := map[string]bool{}
	out := []HNDLAtRiskAsset{}
	for _, o := range occs {
		dedupKey := o.AssetType + "|" + o.AssetID
		if seenAssets[dedupKey] {
			continue
		}
		tags := assetTags[o.AssetType+"|"+o.AssetID]

		var maxUntil time.Time
		var maxTTL int
		var anyDeclared bool
		for _, t := range tags {
			if u, ok := tagUntil[t]; ok {
				anyDeclared = true
				if u.After(maxUntil) {
					maxUntil = u
				}
				if ttl := tagTTL[t]; ttl > maxTTL {
					maxTTL = ttl
				}
			}
		}

		row := HNDLAtRiskAsset{
			AssetType:          o.AssetType,
			AssetID:            o.AssetID,
			Label:              o.Label,
			Algorithm:          o.AlgorithmRaw,
			AlgorithmCanonical: o.AlgorithmCanonical,
			ApplicationTags:    tags,
		}

		switch {
		case !anyDeclared:
			// Unscoped: vulnerable + no metadata for any of its tags
			// (or no tags at all). Surface so operators can declare TTL.
			row.Unscoped = true
			out = append(out, row)
		case !maxUntil.Before(horizon):
			// At-risk: max sensitive_until ≥ CRQC horizon.
			row.MaxTTLYears = maxTTL
			row.SensitiveUntil = maxUntil
			out = append(out, row)
			// else: clear — excluded from the listing.
		}
		// Mark seen regardless of include/exclude: an asset's HNDL
		// classification is asset-level, not per-algorithm, so later
		// occurrences with different algorithms would reach the same
		// decision.
		seenAssets[dedupKey] = true
	}

	// v1.8.0 — at-risk rows come before unscoped rows so the
	// `/analysis/hndl` listing and the v1.8.0 "Unowned" filter pill
	// surface the highest-priority assets first. Stable sort preserves
	// the deterministic per-asset-type / per-asset-id order established
	// by ListWeakAlgorithmOccurrences within each bucket — two callers
	// with the same underlying data still see byte-equal output.
	// Matches research/ownership-plan-v1.8.0.md §7 acceptance criterion
	// for the unowned filter ("sorted with HNDL-at-risk rows on top").
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Unscoped != out[j].Unscoped {
			return !out[i].Unscoped // at-risk (false) ranks before unscoped (true)
		}
		return false
	})

	return out, nil
}

// tagTableForAssetType maps a weak-algorithm occurrence's asset_type
// string to the (table_name, id_column_name) needed to pull
// application_tags. Asset-type strings mirror WeakAlgoOccurrence.AssetType
// values (certificate / ssh_key / crypto_library / protocol_endpoint /
// crypto_config). Unknown types return an error — the HNDL query
// aborts rather than silently skipping, so any future weak-algo asset
// type addition fails loudly here until added.
func tagTableForAssetType(t string) (table, idCol string, err error) {
	switch t {
	case "certificate":
		return "certificates", "fingerprint_sha256", nil
	case "ssh_key":
		return "ssh_keys", "id", nil
	case "crypto_library":
		return "crypto_libraries", "id", nil
	case "protocol_endpoint":
		return "protocol_endpoints", "id", nil
	case "crypto_config":
		return "crypto_configs", "id", nil
	default:
		return "", "", fmt.Errorf("HNDL: unknown asset_type %q — add to tagTableForAssetType or remove from weak-algo scanner", t)
	}
}
