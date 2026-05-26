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

func (s *PostgresStore) UpsertHost(ctx context.Context, host *model.Host) error {
	aliases, _ := json.Marshal(host.Aliases)
	ips, _ := json.Marshal(host.IPAddresses)
	sources, _ := json.Marshal(host.DiscoverySources)

	if host.ID != "" {
		// Update existing host.
		_, err := s.pool.Exec(ctx, `
			UPDATE hosts SET
				canonical_hostname = $2,
				aliases = $3,
				ip_addresses = $4,
				os_family = $5,
				os_version = $6,
				host_type = $7,
				discovery_sources = $8,
				last_seen = $9
			WHERE id = $1
		`, host.ID, host.CanonicalHostname, aliases, ips,
			host.OSFamily, host.OSVersion, host.HostType, sources, host.LastSeen)
		if err != nil {
			return fmt.Errorf("update host: %w", err)
		}
		return nil
	}

	err := s.pool.QueryRow(ctx, `
		INSERT INTO hosts (canonical_hostname, aliases, ip_addresses, os_family, os_version, host_type, discovery_sources, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, first_seen, last_seen
	`, host.CanonicalHostname, aliases, ips,
		host.OSFamily, host.OSVersion, host.HostType, sources,
		host.FirstSeen, host.LastSeen,
	).Scan(&host.ID, &host.FirstSeen, &host.LastSeen)
	if err != nil {
		return fmt.Errorf("insert host: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetHost(ctx context.Context, id string) (*model.Host, error) {
	h := &model.Host{}
	var aliases, ips, sources []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, canonical_hostname, aliases, ip_addresses, os_family, os_version,
		       host_type, discovery_sources, first_seen, last_seen
		FROM hosts WHERE id = $1
	`, id).Scan(
		&h.ID, &h.CanonicalHostname, &aliases, &ips,
		&h.OSFamily, &h.OSVersion, &h.HostType, &sources,
		&h.FirstSeen, &h.LastSeen,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get host: %w", err)
	}
	json.Unmarshal(aliases, &h.Aliases)
	json.Unmarshal(ips, &h.IPAddresses)
	json.Unmarshal(sources, &h.DiscoverySources)
	if h.Aliases == nil {
		h.Aliases = []string{}
	}
	if h.IPAddresses == nil {
		h.IPAddresses = []string{}
	}
	if h.DiscoverySources == nil {
		h.DiscoverySources = []string{}
	}
	return h, nil
}

func (s *PostgresStore) FindHostByIP(ctx context.Context, ip string) (*model.Host, error) {
	h := &model.Host{}
	var aliases, ips, sources []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, canonical_hostname, aliases, ip_addresses, os_family, os_version,
		       host_type, discovery_sources, first_seen, last_seen
		FROM hosts
		WHERE ip_addresses @> $1::jsonb
		ORDER BY last_seen DESC
		LIMIT 1
	`, fmt.Sprintf(`[%q]`, ip)).Scan(
		&h.ID, &h.CanonicalHostname, &aliases, &ips,
		&h.OSFamily, &h.OSVersion, &h.HostType, &sources,
		&h.FirstSeen, &h.LastSeen,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find host by ip: %w", err)
	}
	json.Unmarshal(aliases, &h.Aliases)
	json.Unmarshal(ips, &h.IPAddresses)
	json.Unmarshal(sources, &h.DiscoverySources)
	if h.Aliases == nil {
		h.Aliases = []string{}
	}
	if h.IPAddresses == nil {
		h.IPAddresses = []string{}
	}
	if h.DiscoverySources == nil {
		h.DiscoverySources = []string{}
	}
	return h, nil
}

func (s *PostgresStore) FindHostByHostname(ctx context.Context, hostname string) (*model.Host, error) {
	h := &model.Host{}
	var aliases, ips, sources []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, canonical_hostname, aliases, ip_addresses, os_family, os_version,
		       host_type, discovery_sources, first_seen, last_seen
		FROM hosts
		WHERE canonical_hostname = $1 OR aliases @> $2::jsonb
		ORDER BY last_seen DESC
		LIMIT 1
	`, hostname, fmt.Sprintf(`[%q]`, hostname)).Scan(
		&h.ID, &h.CanonicalHostname, &aliases, &ips,
		&h.OSFamily, &h.OSVersion, &h.HostType, &sources,
		&h.FirstSeen, &h.LastSeen,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find host by hostname: %w", err)
	}
	json.Unmarshal(aliases, &h.Aliases)
	json.Unmarshal(ips, &h.IPAddresses)
	json.Unmarshal(sources, &h.DiscoverySources)
	if h.Aliases == nil {
		h.Aliases = []string{}
	}
	if h.IPAddresses == nil {
		h.IPAddresses = []string{}
	}
	if h.DiscoverySources == nil {
		h.DiscoverySources = []string{}
	}
	return h, nil
}

func (s *PostgresStore) ListHosts(ctx context.Context, query HostSearchQuery) (*HostSearchResult, error) {
	where := "WHERE 1=1"
	args := []any{}
	argN := 1

	if query.Search != "" {
		where += fmt.Sprintf(" AND (canonical_hostname ILIKE $%d OR aliases::text ILIKE $%d OR ip_addresses::text ILIKE $%d)", argN, argN, argN)
		args = append(args, "%"+query.Search+"%")
		argN++
	}
	if query.OSFamily != "" {
		where += fmt.Sprintf(" AND os_family = $%d", argN)
		args = append(args, query.OSFamily)
		argN++
	}
	if query.HostType != "" {
		where += fmt.Sprintf(" AND host_type = $%d", argN)
		args = append(args, query.HostType)
		argN++
	}
	if query.Source != "" {
		where += fmt.Sprintf(" AND discovery_sources @> $%d::jsonb", argN)
		args = append(args, fmt.Sprintf(`[%q]`, query.Source))
		argN++
	}

	// Count total
	var total int
	countSQL := "SELECT COUNT(*) FROM hosts " + where
	if err := s.pool.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count hosts: %w", err)
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
		SELECT id, canonical_hostname, aliases, ip_addresses, os_family, os_version,
		       host_type, discovery_sources, first_seen, last_seen
		FROM hosts %s
		ORDER BY last_seen DESC
		LIMIT $%d OFFSET $%d
	`, where, argN, argN+1)
	args = append(args, limit, offset)

	rows, err := s.pool.Query(ctx, querySQL, args...)
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}
	defer rows.Close()

	hosts := []model.Host{}
	for rows.Next() {
		var h model.Host
		var aliasesB, ipsB, sourcesB []byte
		if err := rows.Scan(
			&h.ID, &h.CanonicalHostname, &aliasesB, &ipsB,
			&h.OSFamily, &h.OSVersion, &h.HostType, &sourcesB,
			&h.FirstSeen, &h.LastSeen,
		); err != nil {
			return nil, fmt.Errorf("scan host row: %w", err)
		}
		json.Unmarshal(aliasesB, &h.Aliases)
		json.Unmarshal(ipsB, &h.IPAddresses)
		json.Unmarshal(sourcesB, &h.DiscoverySources)
		if h.Aliases == nil {
			h.Aliases = []string{}
		}
		if h.IPAddresses == nil {
			h.IPAddresses = []string{}
		}
		if h.DiscoverySources == nil {
			h.DiscoverySources = []string{}
		}
		hosts = append(hosts, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list hosts rows: %w", err)
	}

	return &HostSearchResult{Hosts: hosts, Total: total}, nil
}

func (s *PostgresStore) MergeHosts(ctx context.Context, targetID, sourceID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin merge tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Move all foreign keys from source to target.
	fkUpdates := []string{
		`UPDATE ssh_keys SET host_id = $1 WHERE host_id = $2`,
		`UPDATE crypto_libraries SET host_id = $1 WHERE host_id = $2`,
		`UPDATE crypto_configs SET host_id = $1 WHERE host_id = $2`,
		`UPDATE protocol_observations SET host_id = $1 WHERE host_id = $2`,
		`UPDATE asset_provenance SET host_id = $1 WHERE host_id = $2`,
		`UPDATE host_identifiers SET host_id = $1 WHERE host_id = $2`,
		`UPDATE certificates SET discovered_on_host = $1 WHERE discovered_on_host = $2`,
	}
	for _, sql := range fkUpdates {
		if _, err := tx.Exec(ctx, sql, targetID, sourceID); err != nil {
			return fmt.Errorf("merge fk update: %w", err)
		}
	}

	// Union ip_addresses, aliases, discovery_sources from source into target.
	_, err = tx.Exec(ctx, `
		UPDATE hosts SET
			ip_addresses = (
				SELECT jsonb_agg(DISTINCT val)
				FROM (
					SELECT jsonb_array_elements(ip_addresses) AS val FROM hosts WHERE id = $1
					UNION
					SELECT jsonb_array_elements(ip_addresses) AS val FROM hosts WHERE id = $2
				) sub
			),
			aliases = (
				SELECT COALESCE(jsonb_agg(DISTINCT val), '[]'::jsonb)
				FROM (
					SELECT jsonb_array_elements(aliases) AS val FROM hosts WHERE id = $1
					UNION
					SELECT jsonb_array_elements(aliases) AS val FROM hosts WHERE id = $2
				) sub
			),
			discovery_sources = (
				SELECT COALESCE(jsonb_agg(DISTINCT val), '[]'::jsonb)
				FROM (
					SELECT jsonb_array_elements(discovery_sources) AS val FROM hosts WHERE id = $1
					UNION
					SELECT jsonb_array_elements(discovery_sources) AS val FROM hosts WHERE id = $2
				) sub
			)
		WHERE id = $1
	`, targetID, sourceID)
	if err != nil {
		return fmt.Errorf("merge host arrays: %w", err)
	}

	// Delete source host (cascading deletes handle remaining FKs).
	if _, err := tx.Exec(ctx, `DELETE FROM hosts WHERE id = $1`, sourceID); err != nil {
		return fmt.Errorf("delete source host: %w", err)
	}

	return tx.Commit(ctx)
}

func (s *PostgresStore) UpsertHostIdentifier(ctx context.Context, ident *model.HostIdentifier) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO host_identifiers (host_id, source, source_host_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (source, source_host_id) DO UPDATE SET
			host_id = EXCLUDED.host_id
	`, ident.HostID, ident.Source, ident.SourceHostID)
	if err != nil {
		return fmt.Errorf("upsert host identifier: %w", err)
	}
	return nil
}

func (s *PostgresStore) FindHostBySourceID(ctx context.Context, source, sourceHostID string) (*model.Host, error) {
	var hostID string
	err := s.pool.QueryRow(ctx, `
		SELECT host_id FROM host_identifiers
		WHERE source = $1 AND source_host_id = $2
	`, source, sourceHostID).Scan(&hostID)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find host by source id: %w", err)
	}
	return s.GetHost(ctx, hostID)
}
