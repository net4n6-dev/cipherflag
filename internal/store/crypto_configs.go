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

func (s *PostgresStore) UpsertCryptoConfig(ctx context.Context, cfg *model.CryptoConfig) error {
	settings, _ := json.Marshal(cfg.Settings)
	findings, _ := json.Marshal(cfg.Findings)

	err := s.pool.QueryRow(ctx, `
		INSERT INTO crypto_configs (
			host_id, config_type, file_path, settings, findings,
			source, discovery_status
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (host_id, file_path) DO UPDATE SET
			last_seen = NOW(),
			discovery_status = 'active',
			settings = EXCLUDED.settings,
			findings = EXCLUDED.findings,
			config_type = EXCLUDED.config_type
		RETURNING id, first_seen, last_seen
	`, cfg.HostID, cfg.ConfigType, cfg.FilePath, settings, findings,
		cfg.Source, cfg.DiscoveryStatus,
	).Scan(&cfg.ID, &cfg.FirstSeen, &cfg.LastSeen)
	if err != nil {
		return fmt.Errorf("upsert crypto config: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetCryptoConfig(ctx context.Context, id string) (*model.CryptoConfig, error) {
	cfg := &model.CryptoConfig{}
	var settingsB, findingsB []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, host_id, config_type, file_path, settings, findings,
		       source, discovery_status, first_seen, last_seen
		FROM crypto_configs
		WHERE id = $1
	`, id).Scan(
		&cfg.ID, &cfg.HostID, &cfg.ConfigType, &cfg.FilePath, &settingsB, &findingsB,
		&cfg.Source, &cfg.DiscoveryStatus, &cfg.FirstSeen, &cfg.LastSeen,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get crypto config: %w", err)
	}
	json.Unmarshal(settingsB, &cfg.Settings)
	json.Unmarshal(findingsB, &cfg.Findings)
	if cfg.Settings == nil {
		cfg.Settings = map[string]string{}
	}
	if cfg.Findings == nil {
		cfg.Findings = []model.ConfigIssue{}
	}
	return cfg, nil
}

func (s *PostgresStore) ListCryptoConfigs(ctx context.Context, query ConfigSearchQuery) (*ConfigSearchResult, error) {
	where := "WHERE 1=1"
	args := []any{}
	argN := 1

	if query.HostID != "" {
		where += fmt.Sprintf(" AND host_id = $%d", argN)
		args = append(args, query.HostID)
		argN++
	}
	if query.ConfigType != "" {
		where += fmt.Sprintf(" AND config_type = $%d", argN)
		args = append(args, query.ConfigType)
		argN++
	}
	if query.Status != "" {
		where += fmt.Sprintf(" AND discovery_status = $%d", argN)
		args = append(args, query.Status)
		argN++
	}
	if query.Search != "" {
		like := "%" + query.Search + "%"
		where += fmt.Sprintf(
			" AND (config_type ILIKE $%d OR file_path ILIKE $%d)",
			argN, argN,
		)
		args = append(args, like)
		argN++
	}

	var total int
	if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM crypto_configs "+where, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count crypto configs: %w", err)
	}

	limit := query.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := query.Offset
	if offset < 0 {
		offset = 0
	}

	querySQL := fmt.Sprintf(`
		SELECT id, host_id, config_type, file_path, settings, findings,
		       source, discovery_status, first_seen, last_seen
		FROM crypto_configs %s
		ORDER BY last_seen DESC
		LIMIT $%d OFFSET $%d
	`, where, argN, argN+1)
	args = append(args, limit, offset)

	rows, err := s.pool.Query(ctx, querySQL, args...)
	if err != nil {
		return nil, fmt.Errorf("list crypto configs: %w", err)
	}
	defer rows.Close()

	configs := []model.CryptoConfig{}
	for rows.Next() {
		var cfg model.CryptoConfig
		var settingsB, findingsB []byte
		if err := rows.Scan(
			&cfg.ID, &cfg.HostID, &cfg.ConfigType, &cfg.FilePath,
			&settingsB, &findingsB,
			&cfg.Source, &cfg.DiscoveryStatus, &cfg.FirstSeen, &cfg.LastSeen,
		); err != nil {
			return nil, fmt.Errorf("scan crypto config row: %w", err)
		}
		json.Unmarshal(settingsB, &cfg.Settings)
		json.Unmarshal(findingsB, &cfg.Findings)
		if cfg.Settings == nil {
			cfg.Settings = map[string]string{}
		}
		if cfg.Findings == nil {
			cfg.Findings = []model.ConfigIssue{}
		}
		configs = append(configs, cfg)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list crypto configs rows: %w", err)
	}

	return &ConfigSearchResult{Configs: configs, Total: total}, nil
}
