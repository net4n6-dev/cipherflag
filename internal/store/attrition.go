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
	"strconv"
)

func (s *PostgresStore) MarkStaleAssets(ctx context.Context, cfg AttritionConfig) (*AttritionSummary, error) {
	summary := &AttritionSummary{ByAssetType: map[string]int{}}

	tables := []struct {
		name        string
		assetType   string
		sourceCol   string // column name for discovery source varies by table
	}{
		{"ssh_keys", "ssh_key", "source"},
		{"crypto_libraries", "crypto_library", "source"},
		{"crypto_configs", "crypto_config", "source"},
		{"certificates", "certificate", "source_discovery"},
	}

	for _, table := range tables {
		if len(cfg.CycleBasedSources) > 0 {
			staleHours := cfg.CycleStaleThreshold * 24
			sql := fmt.Sprintf(`
				UPDATE %s SET discovery_status = 'stale'
				WHERE discovery_status = 'active'
				  AND %s = ANY($1)
				  AND last_seen < NOW() - ($2 || ' hours')::interval
			`, table.name, table.sourceCol)
			ct, err := s.pool.Exec(ctx, sql, cfg.CycleBasedSources, strconv.Itoa(staleHours))
			if err != nil {
				return nil, fmt.Errorf("mark stale %s (cycle): %w", table.name, err)
			}
			n := int(ct.RowsAffected())
			summary.MarkedStale += n
			summary.ByAssetType[table.assetType+" (stale)"] += n

			removedHours := cfg.CycleRemovedThreshold * 24
			sql2 := fmt.Sprintf(`
				UPDATE %s SET discovery_status = 'removed'
				WHERE discovery_status = 'stale'
				  AND %s = ANY($1)
				  AND last_seen < NOW() - ($2 || ' hours')::interval
			`, table.name, table.sourceCol)
			ct2, err := s.pool.Exec(ctx, sql2, cfg.CycleBasedSources, strconv.Itoa(removedHours))
			if err != nil {
				return nil, fmt.Errorf("mark removed %s (cycle): %w", table.name, err)
			}
			n2 := int(ct2.RowsAffected())
			summary.MarkedRemoved += n2
			summary.ByAssetType[table.assetType+" (removed)"] += n2
		}

		if len(cfg.NetworkBasedSources) > 0 {
			staleHours := cfg.NetworkStaleDays * 24
			sql := fmt.Sprintf(`
				UPDATE %s SET discovery_status = 'stale'
				WHERE discovery_status = 'active'
				  AND %s = ANY($1)
				  AND last_seen < NOW() - ($2 || ' hours')::interval
			`, table.name, table.sourceCol)
			ct, err := s.pool.Exec(ctx, sql, cfg.NetworkBasedSources, strconv.Itoa(staleHours))
			if err != nil {
				return nil, fmt.Errorf("mark stale %s (network): %w", table.name, err)
			}
			n := int(ct.RowsAffected())
			summary.MarkedStale += n
			summary.ByAssetType[table.assetType+" (stale)"] += n

			removedHours := cfg.NetworkRemovedDays * 24
			sql2 := fmt.Sprintf(`
				UPDATE %s SET discovery_status = 'removed'
				WHERE discovery_status = 'stale'
				  AND %s = ANY($1)
				  AND last_seen < NOW() - ($2 || ' hours')::interval
			`, table.name, table.sourceCol)
			ct2, err := s.pool.Exec(ctx, sql2, cfg.NetworkBasedSources, strconv.Itoa(removedHours))
			if err != nil {
				return nil, fmt.Errorf("mark removed %s (network): %w", table.name, err)
			}
			n2 := int(ct2.RowsAffected())
			summary.MarkedRemoved += n2
			summary.ByAssetType[table.assetType+" (removed)"] += n2
		}
	}

	return summary, nil
}

func (s *PostgresStore) ReactivateAsset(ctx context.Context, assetType, assetID string) error {
	var table string
	switch assetType {
	case "ssh_key":
		table = "ssh_keys"
	case "crypto_library":
		table = "crypto_libraries"
	case "crypto_config":
		table = "crypto_configs"
	case "certificate":
		table = "certificates"
	default:
		return fmt.Errorf("unknown asset type: %s", assetType)
	}

	sql := fmt.Sprintf(`UPDATE %s SET discovery_status = 'active', last_seen = NOW() WHERE id = $1`, table)
	_, err := s.pool.Exec(ctx, sql, assetID)
	if err != nil {
		return fmt.Errorf("reactivate asset %s/%s: %w", assetType, assetID, err)
	}
	return nil
}
