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

func (s *PostgresStore) UpsertProvider(ctx context.Context, p *model.Provider) error {
	if p.ID != "" {
		_, err := s.pool.Exec(ctx, `
			UPDATE providers SET
				kind            = $2,
				base_url        = $3,
				auth_secret_ref = $4,
				display_name    = $5
			WHERE id = $1
		`, p.ID, p.Kind, p.BaseURL, p.AuthSecretRef, p.DisplayName)
		if err != nil {
			return fmt.Errorf("update provider: %w", err)
		}
		return nil
	}

	err := s.pool.QueryRow(ctx, `
		INSERT INTO providers (kind, base_url, auth_secret_ref, display_name)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at
	`, p.Kind, p.BaseURL, p.AuthSecretRef, p.DisplayName,
	).Scan(&p.ID, &p.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert provider: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetProvider(ctx context.Context, id string) (*model.Provider, error) {
	return s.scanProviderRow(ctx, `
		SELECT id, kind, base_url, auth_secret_ref, display_name, created_at
		FROM providers WHERE id = $1
	`, id)
}

func (s *PostgresStore) FindProviderByKindURL(ctx context.Context, kind, baseURL string) (*model.Provider, error) {
	return s.scanProviderRow(ctx, `
		SELECT id, kind, base_url, auth_secret_ref, display_name, created_at
		FROM providers WHERE kind = $1 AND base_url = $2
	`, kind, baseURL)
}

func (s *PostgresStore) ListProviders(ctx context.Context) ([]model.Provider, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, kind, base_url, auth_secret_ref, display_name, created_at
		FROM providers ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list providers: %w", err)
	}
	defer rows.Close()

	var out []model.Provider
	for rows.Next() {
		p, err := scanProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

func (s *PostgresStore) DeleteProvider(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM providers WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete provider: %w", err)
	}
	return nil
}

// Helpers --------------------------------------------------------------------

func (s *PostgresStore) scanProviderRow(ctx context.Context, sql string, args ...any) (*model.Provider, error) {
	row := s.pool.QueryRow(ctx, sql, args...)
	p, err := scanProvider(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return p, err
}

func scanProvider(row rowScanner) (*model.Provider, error) {
	p := &model.Provider{}
	if err := row.Scan(&p.ID, &p.Kind, &p.BaseURL, &p.AuthSecretRef, &p.DisplayName, &p.CreatedAt); err != nil {
		return nil, err
	}
	return p, nil
}
