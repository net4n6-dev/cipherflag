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

func (s *PostgresStore) EnqueueScanJob(ctx context.Context, j *model.ScanJob) error {
	summary, err := json.Marshal(j.SummaryJSON)
	if err != nil {
		return fmt.Errorf("marshal summary: %w", err)
	}
	if j.SummaryJSON == nil {
		summary = []byte("{}")
	}
	err = s.pool.QueryRow(ctx, `
		INSERT INTO scan_jobs (repo_id, scan_mode, trigger, branch_ref, summary_json,
		                       retry_count, next_retry_at, failure_class)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, status, created_at
	`, j.RepoID, j.ScanMode, j.Trigger, j.BranchRef, summary,
		j.RetryCount, j.NextRetryAt, j.FailureClass,
	).Scan(&j.ID, &j.Status, &j.CreatedAt)
	if err != nil {
		return fmt.Errorf("enqueue scan_job: %w", err)
	}
	return nil
}

// ClaimScanJob atomically claims the oldest queued job for this worker.
// Returns (nil, nil) when the queue is empty. Uses SELECT ... FOR UPDATE
// SKIP LOCKED so concurrent workers don't block each other.
func (s *PostgresStore) ClaimScanJob(ctx context.Context, workerID string) (*model.ScanJob, error) {
	const sql = `
		WITH claimed AS (
			SELECT id FROM scan_jobs
			WHERE status = 'queued'
			  AND (next_retry_at IS NULL OR next_retry_at <= NOW())
			ORDER BY created_at
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE scan_jobs AS j
		SET status     = 'running',
		    worker_id  = $1,
		    started_at = NOW()
		FROM claimed
		WHERE j.id = claimed.id
		RETURNING j.id, j.repo_id, j.scan_mode, j.trigger, j.branch_ref, j.status,
		          j.worker_id, j.started_at, j.completed_at, j.summary_json,
		          j.llm_tokens_spent, j.llm_cost_usd, j.findings_count, j.error_text,
		          j.created_at, j.retry_count, j.next_retry_at, j.failure_class
	`
	row := s.pool.QueryRow(ctx, sql, workerID)
	j, err := scanScanJob(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return j, err
}

func (s *PostgresStore) UpdateScanJob(ctx context.Context, j *model.ScanJob) error {
	summary, err := json.Marshal(j.SummaryJSON)
	if err != nil {
		return fmt.Errorf("marshal summary: %w", err)
	}
	if j.SummaryJSON == nil {
		summary = []byte("{}")
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE scan_jobs SET
			status            = $2,
			worker_id         = $3,
			summary_json      = $4,
			llm_tokens_spent  = $5,
			llm_cost_usd      = $6,
			findings_count    = $7,
			error_text        = $8,
			retry_count       = $9,
			next_retry_at     = $10,
			failure_class     = $11,
			completed_at      = CASE WHEN $2 IN ('completed','failed','cancelled') AND completed_at IS NULL
			                         THEN NOW() ELSE completed_at END
		WHERE id = $1
	`, j.ID, j.Status, j.WorkerID, summary, j.LLMTokensSpent, j.LLMCostUSD, j.FindingsCount, j.ErrorText,
		j.RetryCount, j.NextRetryAt, j.FailureClass)
	if err != nil {
		return fmt.Errorf("update scan_job: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetScanJob(ctx context.Context, id string) (*model.ScanJob, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, repo_id, scan_mode, trigger, branch_ref, status,
		       worker_id, started_at, completed_at, summary_json,
		       llm_tokens_spent, llm_cost_usd, findings_count, error_text, created_at,
		       retry_count, next_retry_at, failure_class
		FROM scan_jobs WHERE id = $1
	`, id)
	j, err := scanScanJob(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return j, err
}

// CancelScanJob flips a queued job to cancelled atomically. Running jobs
// are NOT affected — worker cooperative cancellation would require a ctx
// signal channel, deferred to v2.
func (s *PostgresStore) CancelScanJob(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE scan_jobs
		SET status = 'cancelled', completed_at = NOW()
		WHERE id = $1 AND status = 'queued'
	`, id)
	if err != nil {
		return fmt.Errorf("cancel scan_job: %w", err)
	}
	return nil
}

// HasActiveScanJob reports whether the given repo has any queued or running
// scan job (used by the scheduler to skip overlapping fires).
func (s *PostgresStore) HasActiveScanJob(ctx context.Context, repoID string) (bool, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM scan_jobs
		WHERE repo_id = $1 AND status IN ('queued', 'running')
	`, repoID).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("count active scans: %w", err)
	}
	return n > 0, nil
}

func (s *PostgresStore) ListScanJobs(ctx context.Context, q ScanJobQuery) ([]model.ScanJob, error) {
	if q.Limit <= 0 {
		q.Limit = 100
	}
	const base = `
		SELECT id, repo_id, scan_mode, trigger, branch_ref, status,
		       worker_id, started_at, completed_at, summary_json,
		       llm_tokens_spent, llm_cost_usd, findings_count, error_text, created_at,
		       retry_count, next_retry_at, failure_class
		FROM scan_jobs
	`
	where := " WHERE 1=1"
	args := []any{}
	i := 1
	if q.RepoID != "" {
		where += fmt.Sprintf(" AND repo_id = $%d", i)
		args = append(args, q.RepoID)
		i++
	}
	if q.Status != "" {
		where += fmt.Sprintf(" AND status = $%d", i)
		args = append(args, q.Status)
		i++
	}
	where += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", i, i+1)
	args = append(args, q.Limit, q.Offset)

	rows, err := s.pool.Query(ctx, base+where, args...)
	if err != nil {
		return nil, fmt.Errorf("list scan_jobs: %w", err)
	}
	defer rows.Close()

	var out []model.ScanJob
	for rows.Next() {
		j, err := scanScanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *j)
	}
	return out, rows.Err()
}

func scanScanJob(row rowScanner) (*model.ScanJob, error) {
	j := &model.ScanJob{}
	var llmCost float64
	var summary []byte
	if err := row.Scan(
		&j.ID, &j.RepoID, &j.ScanMode, &j.Trigger, &j.BranchRef, &j.Status,
		&j.WorkerID, &j.StartedAt, &j.CompletedAt, &summary,
		&j.LLMTokensSpent, &llmCost, &j.FindingsCount, &j.ErrorText, &j.CreatedAt,
		&j.RetryCount, &j.NextRetryAt, &j.FailureClass,
	); err != nil {
		return nil, err
	}
	j.LLMCostUSD = llmCost
	if len(summary) > 0 {
		if err := json.Unmarshal(summary, &j.SummaryJSON); err != nil {
			return nil, fmt.Errorf("unmarshal summary: %w", err)
		}
	}
	return j, nil
}
