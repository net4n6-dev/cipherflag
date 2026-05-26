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
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

func (s *PostgresStore) UpsertRepository(ctx context.Context, r *model.Repository) error {
	tags, err := json.Marshal(r.Tags)
	if err != nil {
		return fmt.Errorf("marshal tags: %w", err)
	}
	if r.Tags == nil {
		tags = []byte("{}")
	}

	if r.ID != "" {
		_, err := s.pool.Exec(ctx, `
			UPDATE repositories SET
				provider_id       = $2,
				url               = $3,
				default_branch    = $4,
				schedule_cron     = $5,
				default_scan_mode = $6,
				tags              = $7,
				auth_secret_ref   = $8,
				last_scanned_sha  = $9,
				last_scan_at      = $10,
				last_seen         = NOW()
			WHERE id = $1
		`,
			r.ID, r.ProviderID, r.URL, r.DefaultBranch, nullIfEmpty(r.ScheduleCron),
			r.DefaultScanMode, tags, nullIfEmpty(r.AuthSecretRef),
			nullIfEmpty(r.LastScannedSHA), r.LastScanAt,
		)
		if err != nil {
			return fmt.Errorf("update repository: %w", err)
		}
		return nil
	}

	err = s.pool.QueryRow(ctx, `
		INSERT INTO repositories (
			provider_id, url, default_branch, schedule_cron, default_scan_mode,
			tags, auth_secret_ref, last_scanned_sha, last_scan_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, first_seen, last_seen
	`,
		r.ProviderID, r.URL, r.DefaultBranch, nullIfEmpty(r.ScheduleCron),
		r.DefaultScanMode, tags, nullIfEmpty(r.AuthSecretRef),
		nullIfEmpty(r.LastScannedSHA), r.LastScanAt,
	).Scan(&r.ID, &r.FirstSeen, &r.LastSeen)
	if err != nil {
		return fmt.Errorf("insert repository: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetRepository(ctx context.Context, id string) (*model.Repository, error) {
	return s.scanRepoRow(ctx, `
		SELECT id, provider_id, url, default_branch, COALESCE(schedule_cron, ''),
		       default_scan_mode, tags, COALESCE(auth_secret_ref, ''),
		       COALESCE(last_scanned_sha, ''), last_scan_at, last_scheduled_at, first_seen, last_seen
		FROM repositories WHERE id = $1
	`, id)
}

func (s *PostgresStore) FindRepositoryByURL(ctx context.Context, providerID, url string) (*model.Repository, error) {
	return s.scanRepoRow(ctx, `
		SELECT id, provider_id, url, default_branch, COALESCE(schedule_cron, ''),
		       default_scan_mode, tags, COALESCE(auth_secret_ref, ''),
		       COALESCE(last_scanned_sha, ''), last_scan_at, last_scheduled_at, first_seen, last_seen
		FROM repositories WHERE provider_id = $1 AND url = $2
	`, providerID, url)
}

func (s *PostgresStore) ListRepositories(ctx context.Context, providerID string, limit, offset int) ([]model.Repository, error) {
	if limit <= 0 {
		limit = 100
	}
	var rows pgx.Rows
	var err error
	if providerID == "" {
		rows, err = s.pool.Query(ctx, `
			SELECT id, provider_id, url, default_branch, COALESCE(schedule_cron, ''),
			       default_scan_mode, tags, COALESCE(auth_secret_ref, ''),
			       COALESCE(last_scanned_sha, ''), last_scan_at, last_scheduled_at, first_seen, last_seen
			FROM repositories ORDER BY first_seen DESC LIMIT $1 OFFSET $2
		`, limit, offset)
	} else {
		rows, err = s.pool.Query(ctx, `
			SELECT id, provider_id, url, default_branch, COALESCE(schedule_cron, ''),
			       default_scan_mode, tags, COALESCE(auth_secret_ref, ''),
			       COALESCE(last_scanned_sha, ''), last_scan_at, last_scheduled_at, first_seen, last_seen
			FROM repositories WHERE provider_id = $1 ORDER BY first_seen DESC LIMIT $2 OFFSET $3
		`, providerID, limit, offset)
	}
	if err != nil {
		return nil, fmt.Errorf("list repositories: %w", err)
	}
	defer rows.Close()

	var out []model.Repository
	for rows.Next() {
		r, err := scanRepo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

func (s *PostgresStore) DeleteRepository(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM repositories WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete repository: %w", err)
	}
	return nil
}

// Helpers --------------------------------------------------------------------

func (s *PostgresStore) scanRepoRow(ctx context.Context, sql string, args ...any) (*model.Repository, error) {
	row := s.pool.QueryRow(ctx, sql, args...)
	r, err := scanRepo(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return r, err
}

// rowScanner covers both pgx.Row and pgx.Rows for the shared scan helper.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanRepo(row rowScanner) (*model.Repository, error) {
	r := &model.Repository{}
	var tags []byte
	if err := row.Scan(
		&r.ID, &r.ProviderID, &r.URL, &r.DefaultBranch, &r.ScheduleCron,
		&r.DefaultScanMode, &tags, &r.AuthSecretRef,
		&r.LastScannedSHA, &r.LastScanAt, &r.LastScheduledAt, &r.FirstSeen, &r.LastSeen,
	); err != nil {
		return nil, err
	}
	if len(tags) > 0 {
		if err := json.Unmarshal(tags, &r.Tags); err != nil {
			return nil, fmt.Errorf("unmarshal tags: %w", err)
		}
	}
	return r, nil
}

// ListScheduledRepos returns every repo with a non-empty schedule_cron.
func (s *PostgresStore) ListScheduledRepos(ctx context.Context) ([]model.Repository, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, provider_id, url, default_branch, COALESCE(schedule_cron, ''),
		       default_scan_mode, tags, COALESCE(auth_secret_ref, ''),
		       COALESCE(last_scanned_sha, ''), last_scan_at, last_scheduled_at, first_seen, last_seen
		FROM repositories
		WHERE schedule_cron IS NOT NULL AND schedule_cron <> ''
	`)
	if err != nil {
		return nil, fmt.Errorf("list scheduled repos: %w", err)
	}
	defer rows.Close()

	var out []model.Repository
	for rows.Next() {
		r, err := scanRepo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// UpdateRepositoryLastScheduledAt advances the persistent cron cursor for one repo.
func (s *PostgresStore) UpdateRepositoryLastScheduledAt(ctx context.Context, id string, when time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE repositories SET last_scheduled_at = $2 WHERE id = $1`, id, when)
	if err != nil {
		return fmt.Errorf("update last_scheduled_at: %w", err)
	}
	return nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
