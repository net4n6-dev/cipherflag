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

	"github.com/jackc/pgx/v5"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

func (s *PostgresStore) UpsertSSHKey(ctx context.Context, key *model.SSHKey) error {
	err := s.pool.QueryRow(ctx, `
		INSERT INTO ssh_keys (
			host_id, key_type, key_size_bits, fingerprint_sha256, file_path,
			owner_user, is_authorized, is_protected, grants_root, comment,
			source, discovery_status
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (host_id, fingerprint_sha256) DO UPDATE SET
			last_seen = NOW(),
			discovery_status = 'active',
			is_protected = EXCLUDED.is_protected,
			is_authorized = EXCLUDED.is_authorized,
			grants_root = EXCLUDED.grants_root,
			file_path = EXCLUDED.file_path,
			owner_user = EXCLUDED.owner_user,
			comment = EXCLUDED.comment
		RETURNING id, first_seen, last_seen
	`, key.HostID, key.KeyType, key.KeySizeBits, key.FingerprintSHA256,
		key.FilePath, key.OwnerUser, key.IsAuthorized, key.IsProtected,
		key.GrantsRoot, key.Comment, key.Source, key.DiscoveryStatus,
	).Scan(&key.ID, &key.FirstSeen, &key.LastSeen)
	if err != nil {
		return fmt.Errorf("upsert ssh key: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetSSHKey(ctx context.Context, id string) (*model.SSHKey, error) {
	k := &model.SSHKey{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, host_id, key_type, key_size_bits, fingerprint_sha256, file_path,
		       owner_user, is_authorized, is_protected, grants_root, comment,
		       source, discovery_status, first_seen, last_seen
		FROM ssh_keys WHERE id = $1
	`, id).Scan(
		&k.ID, &k.HostID, &k.KeyType, &k.KeySizeBits, &k.FingerprintSHA256,
		&k.FilePath, &k.OwnerUser, &k.IsAuthorized, &k.IsProtected, &k.GrantsRoot, &k.Comment,
		&k.Source, &k.DiscoveryStatus, &k.FirstSeen, &k.LastSeen,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get ssh key: %w", err)
	}
	return k, nil
}

func (s *PostgresStore) ListSSHKeys(ctx context.Context, query SSHKeySearchQuery) (*SSHKeySearchResult, error) {
	where := "WHERE 1=1"
	args := []any{}
	argN := 1

	if query.HostID != "" {
		where += fmt.Sprintf(" AND host_id = $%d", argN)
		args = append(args, query.HostID)
		argN++
	}
	if query.KeyType != "" {
		where += fmt.Sprintf(" AND key_type = $%d", argN)
		args = append(args, query.KeyType)
		argN++
	}
	if query.Status != "" {
		where += fmt.Sprintf(" AND discovery_status = $%d", argN)
		args = append(args, query.Status)
		argN++
	}
	if query.Search != "" {
		// Substring match across the identity fields a human would search by.
		// ILIKE on a table that fits in shared_buffers is fine; if ssh_keys
		// ever grows past that we'd revisit with a tsvector column.
		like := "%" + query.Search + "%"
		where += fmt.Sprintf(
			" AND (key_type ILIKE $%d OR fingerprint_sha256 ILIKE $%d OR owner_user ILIKE $%d OR file_path ILIKE $%d)",
			argN, argN, argN, argN,
		)
		args = append(args, like)
		argN++
	}

	var total int
	if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM ssh_keys "+where, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count ssh keys: %w", err)
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
		SELECT id, host_id, key_type, key_size_bits, fingerprint_sha256, file_path,
		       owner_user, is_authorized, is_protected, grants_root, comment,
		       source, discovery_status, first_seen, last_seen
		FROM ssh_keys %s
		ORDER BY last_seen DESC
		LIMIT $%d OFFSET $%d
	`, where, argN, argN+1)
	args = append(args, limit, offset)

	rows, err := s.pool.Query(ctx, querySQL, args...)
	if err != nil {
		return nil, fmt.Errorf("list ssh keys: %w", err)
	}
	defer rows.Close()

	keys := []model.SSHKey{}
	for rows.Next() {
		var k model.SSHKey
		if err := rows.Scan(
			&k.ID, &k.HostID, &k.KeyType, &k.KeySizeBits, &k.FingerprintSHA256,
			&k.FilePath, &k.OwnerUser, &k.IsAuthorized, &k.IsProtected, &k.GrantsRoot, &k.Comment,
			&k.Source, &k.DiscoveryStatus, &k.FirstSeen, &k.LastSeen,
		); err != nil {
			return nil, fmt.Errorf("scan ssh key row: %w", err)
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list ssh keys rows: %w", err)
	}

	return &SSHKeySearchResult{Keys: keys, Total: total}, nil
}
