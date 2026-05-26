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
	"strings"

	"github.com/jackc/pgx/v5"
)

// ListRepositoryFindings expands the JSONB findings array on a repository's
// asset_health_reports row into individual RepoFindingRow values, applying
// in-Go filters where possible (severity, bucket, detected_by contains).
func (s *PostgresStore) ListRepositoryFindings(ctx context.Context, q RepoFindingQuery) ([]RepoFindingRow, error) {
	if q.RepoID == "" {
		return nil, fmt.Errorf("RepoID required")
	}
	if q.Limit <= 0 {
		q.Limit = 100
	}
	var findingsJSON []byte
	err := s.pool.QueryRow(ctx, `
		SELECT findings FROM asset_health_reports
		WHERE asset_type = 'repository' AND asset_id = $1
	`, q.RepoID).Scan(&findingsJSON)
	if err != nil {
		if err == pgx.ErrNoRows {
			return []RepoFindingRow{}, nil
		}
		return nil, fmt.Errorf("list findings: %w", err)
	}

	var raw []map[string]any
	if err := json.Unmarshal(findingsJSON, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal findings: %w", err)
	}

	sevSet := stringSet(q.Severities)
	bucketSet := stringSet(q.Buckets)

	out := make([]RepoFindingRow, 0, len(raw))
	for _, r := range raw {
		row := rowFromRaw(r, q.RepoID)
		if len(sevSet) > 0 {
			if _, ok := sevSet[row.Severity]; !ok {
				continue
			}
		}
		if len(bucketSet) > 0 {
			if _, ok := bucketSet[row.Bucket]; !ok {
				continue
			}
		}
		if q.DetectedBy != "" && !anyContains(row.DetectedBy, q.DetectedBy) {
			continue
		}
		out = append(out, row)
	}
	if q.Offset > len(out) {
		return []RepoFindingRow{}, nil
	}
	out = out[q.Offset:]
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

func rowFromRaw(r map[string]any, repoID string) RepoFindingRow {
	row := RepoFindingRow{RepoID: repoID, Raw: r}
	if v, ok := r["rule_id"].(string); ok {
		row.RuleID = v
	}
	if v, ok := r["severity"].(string); ok {
		row.Severity = v
	}
	if v, ok := r["bucket"].(string); ok {
		row.Bucket = v
	}
	if v, ok := r["path"].(string); ok {
		row.Path = v
	}
	if v, ok := r["confidence"].(float64); ok {
		row.Confidence = v
	}
	if v, ok := r["fingerprint"].(string); ok {
		row.Fingerprint = v
	}
	if v, ok := r["scan_id"].(string); ok {
		row.ScanID = v
	}
	if arr, ok := r["detected_by"].([]any); ok {
		for _, el := range arr {
			if s, ok := el.(string); ok {
				row.DetectedBy = append(row.DetectedBy, s)
			}
		}
	}
	return row
}

func stringSet(ss []string) map[string]struct{} {
	if len(ss) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(ss))
	for _, s := range ss {
		m[s] = struct{}{}
	}
	return m
}

func anyContains(ss []string, needle string) bool {
	for _, s := range ss {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}
