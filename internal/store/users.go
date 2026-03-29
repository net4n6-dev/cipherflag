package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/cyberflag-ai/cipherflag/internal/model"
)

func (s *PostgresStore) HasUsers(ctx context.Context) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users)`).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("checking users exist: %w", err)
	}
	return exists, nil
}

func (s *PostgresStore) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	u := &model.User{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, email, password_hash, display_name, role, created_at, updated_at, last_login_at
		FROM users WHERE email = $1
	`, email).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.DisplayName, &u.Role,
		&u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	return u, nil
}

func (s *PostgresStore) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	u := &model.User{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, email, password_hash, display_name, role, created_at, updated_at, last_login_at
		FROM users WHERE id = $1
	`, id).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.DisplayName, &u.Role,
		&u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	return u, nil
}

func (s *PostgresStore) ListUsers(ctx context.Context) ([]model.User, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, email, password_hash, display_name, role, created_at, updated_at, last_login_at
		FROM users ORDER BY created_at
	`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	users := []model.User{}
	for rows.Next() {
		var u model.User
		if err := rows.Scan(
			&u.ID, &u.Email, &u.PasswordHash, &u.DisplayName, &u.Role,
			&u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
		); err != nil {
			return nil, fmt.Errorf("scan user row: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *PostgresStore) CreateUser(ctx context.Context, user *model.User) error {
	err := s.pool.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, display_name, role)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at, updated_at
	`, user.Email, user.PasswordHash, user.DisplayName, user.Role).Scan(
		&user.ID, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

func (s *PostgresStore) UpdateUser(ctx context.Context, id string, displayName string, role string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE users SET display_name = $2, role = $3, updated_at = NOW()
		WHERE id = $1
	`, id, displayName, role)
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	return nil
}

func (s *PostgresStore) UpdateUserPassword(ctx context.Context, id string, passwordHash string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE users SET password_hash = $2, updated_at = NOW()
		WHERE id = $1
	`, id, passwordHash)
	if err != nil {
		return fmt.Errorf("update user password: %w", err)
	}
	return nil
}

func (s *PostgresStore) UpdateUserLastLogin(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE users SET last_login_at = NOW()
		WHERE id = $1
	`, id)
	if err != nil {
		return fmt.Errorf("update user last login: %w", err)
	}
	return nil
}

func (s *PostgresStore) DeleteUser(ctx context.Context, id string) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}
