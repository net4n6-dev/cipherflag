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

	"github.com/jackc/pgx/v5"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

func (s *PostgresStore) CreateLineageLink(ctx context.Context, l *model.LineageLink) error {
	ev, err := json.Marshal(l.Evidence)
	if err != nil {
		return fmt.Errorf("marshal evidence: %w", err)
	}
	if l.Evidence == nil {
		ev = []byte("{}")
	}
	// Idempotent insert — the UNIQUE constraint catches duplicates.
	// We use ON CONFLICT ... DO UPDATE so the caller's *LineageLink ends up
	// populated with the existing row's ID even on re-create (matches the
	// provenance-write pattern in asset_provenance).
	err = s.pool.QueryRow(ctx, `
		INSERT INTO lineage_links (
			from_asset_type, from_asset_id, to_asset_type, to_asset_id,
			link_type, confidence, evidence
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (from_asset_type, from_asset_id, to_asset_type, to_asset_id, link_type)
		DO UPDATE SET evidence = EXCLUDED.evidence
		RETURNING id, created_at
	`,
		l.FromAssetType, l.FromAssetID, l.ToAssetType, l.ToAssetID,
		l.LinkType, l.Confidence, ev,
	).Scan(&l.ID, &l.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert lineage_link: %w", err)
	}
	return nil
}

func (s *PostgresStore) ListLineageFrom(ctx context.Context, fromAssetType, fromAssetID string) ([]model.LineageLink, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, from_asset_type, from_asset_id, to_asset_type, to_asset_id,
		       link_type, confidence, evidence, created_at
		FROM lineage_links
		WHERE from_asset_type = $1 AND from_asset_id = $2
		ORDER BY created_at DESC
	`, fromAssetType, fromAssetID)
	if err != nil {
		return nil, fmt.Errorf("list lineage from: %w", err)
	}
	defer rows.Close()
	return scanLineageRows(rows)
}

func (s *PostgresStore) ListLineageTo(ctx context.Context, toAssetType, toAssetID string) ([]model.LineageLink, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, from_asset_type, from_asset_id, to_asset_type, to_asset_id,
		       link_type, confidence, evidence, created_at
		FROM lineage_links
		WHERE to_asset_type = $1 AND to_asset_id = $2
		ORDER BY created_at DESC
	`, toAssetType, toAssetID)
	if err != nil {
		return nil, fmt.Errorf("list lineage to: %w", err)
	}
	defer rows.Close()
	return scanLineageRows(rows)
}

func (s *PostgresStore) CountLineageLinks(ctx context.Context) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM lineage_links`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count lineage_links: %w", err)
	}
	return n, nil
}

func scanLineageRows(rows pgx.Rows) ([]model.LineageLink, error) {
	var out []model.LineageLink
	for rows.Next() {
		var l model.LineageLink
		var ev []byte
		if err := rows.Scan(
			&l.ID, &l.FromAssetType, &l.FromAssetID, &l.ToAssetType, &l.ToAssetID,
			&l.LinkType, &l.Confidence, &ev, &l.CreatedAt,
		); err != nil {
			return nil, err
		}
		if len(ev) > 0 {
			if err := json.Unmarshal(ev, &l.Evidence); err != nil {
				return nil, fmt.Errorf("unmarshal evidence: %w", err)
			}
		}
		out = append(out, l)
	}
	return out, rows.Err()
}
