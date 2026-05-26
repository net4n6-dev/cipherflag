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
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

func (s *PostgresStore) GetCacheEntry(ctx context.Context, blobSHA []byte, ruleVersion, promptHash, scanMode, assetType string) (*model.RepoScanCacheEntry, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT blob_sha, rule_version, prompt_content_hash, scan_mode, asset_type,
		       findings_json, scanned_at, token_cost
		FROM repo_scan_cache
		WHERE blob_sha = $1 AND rule_version = $2 AND prompt_content_hash = $3
		  AND scan_mode = $4 AND asset_type = $5
	`, blobSHA, ruleVersion, promptHash, scanMode, assetType)

	e := &model.RepoScanCacheEntry{}
	if err := row.Scan(
		&e.BlobSHA, &e.RuleVersion, &e.PromptContentHash, &e.ScanMode, &e.AssetType,
		&e.FindingsJSON, &e.ScannedAt, &e.TokenCost,
	); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get cache entry: %w", err)
	}
	return e, nil
}

// SweepCache deletes repo_scan_cache rows for a given asset_type that are both:
//   - older than `olderThan`, AND
//   - do NOT match the current (activeRuleVersion, activePromptContentHash).
//
// Both conditions must hold — fresh rows stay; stale-but-still-relevant rows
// stay. Scoping by assetType is required (6.2a+): container-image rows live
// in the same table but have independent rule_version / prompt_content_hash
// lineages from repository rows, so a cross-type sweep would delete
// still-current rows belonging to the other scanner. Returns the number of
// deleted rows.
func (s *PostgresStore) SweepCache(ctx context.Context, assetType, activeRuleVersion, activePromptContentHash string, olderThan time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM repo_scan_cache
		WHERE asset_type = $4
		  AND scanned_at < $1
		  AND (rule_version <> $2 OR prompt_content_hash <> $3)
	`, olderThan, activeRuleVersion, activePromptContentHash, assetType)
	if err != nil {
		return 0, fmt.Errorf("sweep cache: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func (s *PostgresStore) PutCacheEntry(ctx context.Context, e *model.RepoScanCacheEntry) error {
	if e.FindingsJSON == nil {
		e.FindingsJSON = []byte("[]")
	}
	if e.AssetType == "" {
		return fmt.Errorf("put cache entry: asset_type is required (use model.AssetTypeRepository or model.AssetTypeContainerImage)")
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO repo_scan_cache (blob_sha, rule_version, prompt_content_hash, scan_mode, asset_type, findings_json, token_cost)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (blob_sha, rule_version, prompt_content_hash, scan_mode, asset_type)
		DO UPDATE SET findings_json = EXCLUDED.findings_json,
		              scanned_at    = NOW(),
		              token_cost    = EXCLUDED.token_cost
	`, e.BlobSHA, e.RuleVersion, e.PromptContentHash, e.ScanMode, e.AssetType, e.FindingsJSON, e.TokenCost)
	if err != nil {
		return fmt.Errorf("put cache entry: %w", err)
	}
	return nil
}
