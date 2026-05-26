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
	"strings"
)

// SearchMultiType performs a ranked full-text search across certificates,
// ssh_keys, crypto_libraries, and crypto_configs using their search_vector
// columns, returning a unified list of MultiSearchItem ordered by ts_rank.
func (s *PostgresStore) SearchMultiType(ctx context.Context, query string, limit int) (*MultiSearchResult, error) {
	if limit <= 0 || limit > 50 {
		limit = 20
	}

	// Build tsquery: split on spaces and join tokens with &.
	tokens := strings.Fields(query)
	if len(tokens) == 0 {
		return &MultiSearchResult{Items: []MultiSearchItem{}, Total: 0}, nil
	}
	tsq := strings.Join(tokens, " & ")

	sql := `
		SELECT type, id, label, sublabel, grade, ts_rank(sv, q) AS rank
		FROM (
			SELECT
				'certificate'::text AS type,
				c.fingerprint_sha256 AS id,
				COALESCE(c.subject_cn, '') AS label,
				COALESCE(c.issuer_cn, '') AS sublabel,
				COALESCE(h.grade, '') AS grade,
				c.search_vector AS sv,
				to_tsquery('english', $1) AS q
			FROM certificates c
			LEFT JOIN health_reports h ON h.cert_fingerprint = c.fingerprint_sha256
			WHERE c.search_vector @@ to_tsquery('english', $1)

			UNION ALL

			SELECT
				'ssh_key'::text,
				k.id::text,
				COALESCE(k.owner_user || ' (' || k.key_type || ')', k.key_type),
				COALESCE(k.file_path, ''),
				'',
				k.search_vector,
				to_tsquery('english', $1)
			FROM ssh_keys k
			WHERE k.search_vector @@ to_tsquery('english', $1)

			UNION ALL

			SELECT
				'crypto_library'::text,
				l.id::text,
				COALESCE(l.library_name, ''),
				COALESCE(l.version, ''),
				'',
				l.search_vector,
				to_tsquery('english', $1)
			FROM crypto_libraries l
			WHERE l.search_vector @@ to_tsquery('english', $1)

			UNION ALL

			SELECT
				'crypto_config'::text,
				cfg.id::text,
				COALESCE(cfg.file_path, ''),
				COALESCE(cfg.config_type, ''),
				'',
				cfg.search_vector,
				to_tsquery('english', $1)
			FROM crypto_configs cfg
			WHERE cfg.search_vector @@ to_tsquery('english', $1)
		) sub
		ORDER BY rank DESC
		LIMIT $2
	`

	rows, err := s.pool.Query(ctx, sql, tsq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := &MultiSearchResult{Items: []MultiSearchItem{}}
	for rows.Next() {
		var item MultiSearchItem
		var rank float64
		if err := rows.Scan(&item.Type, &item.ID, &item.Label, &item.Sublabel, &item.Grade, &rank); err != nil {
			return nil, err
		}
		result.Items = append(result.Items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	result.Total = len(result.Items)
	return result, nil
}
