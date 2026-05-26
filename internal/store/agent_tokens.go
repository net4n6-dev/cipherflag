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

func (s *PostgresStore) CreateAgentToken(ctx context.Context, token *model.AgentToken) error {
	err := s.pool.QueryRow(ctx, `
		INSERT INTO agent_tokens (name, token_hash, token_prefix, created_by)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at
	`, token.Name, token.TokenHash, token.TokenPrefix, token.CreatedBy,
	).Scan(&token.ID, &token.CreatedAt)
	if err != nil {
		return fmt.Errorf("create agent token: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetAgentToken(ctx context.Context, tokenHash string) (*model.AgentToken, error) {
	t := &model.AgentToken{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, token_hash, token_prefix, created_by, created_at, last_used_at, revoked_at
		FROM agent_tokens WHERE token_hash = $1
	`, tokenHash).Scan(
		&t.ID, &t.Name, &t.TokenHash, &t.TokenPrefix, &t.CreatedBy,
		&t.CreatedAt, &t.LastUsedAt, &t.RevokedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get agent token: %w", err)
	}
	return t, nil
}

func (s *PostgresStore) ListAgentTokens(ctx context.Context) ([]model.AgentToken, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, token_hash, token_prefix, created_by, created_at, last_used_at, revoked_at
		FROM agent_tokens ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list agent tokens: %w", err)
	}
	defer rows.Close()

	tokens := []model.AgentToken{}
	for rows.Next() {
		var t model.AgentToken
		if err := rows.Scan(
			&t.ID, &t.Name, &t.TokenHash, &t.TokenPrefix, &t.CreatedBy,
			&t.CreatedAt, &t.LastUsedAt, &t.RevokedAt,
		); err != nil {
			return nil, fmt.Errorf("scan agent token row: %w", err)
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

func (s *PostgresStore) RevokeAgentToken(ctx context.Context, id string) error {
	ct, err := s.pool.Exec(ctx, `
		UPDATE agent_tokens SET revoked_at = NOW()
		WHERE id = $1 AND revoked_at IS NULL
	`, id)
	if err != nil {
		return fmt.Errorf("revoke agent token: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("agent token not found or already revoked")
	}
	return nil
}

func (s *PostgresStore) UpdateAgentTokenLastUsed(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE agent_tokens SET last_used_at = NOW()
		WHERE id = $1
	`, id)
	if err != nil {
		return fmt.Errorf("update agent token last used: %w", err)
	}
	return nil
}
