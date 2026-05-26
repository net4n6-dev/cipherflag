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
)

// GetProvenanceHostIDs returns the distinct host UUIDs that have a provenance
// record for the given (assetType, assetID) pair.
func (s *PostgresStore) GetProvenanceHostIDs(ctx context.Context, assetType, assetID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
        SELECT DISTINCT host_id::text
        FROM asset_provenance
        WHERE asset_type = $1 AND asset_id = $2 AND host_id IS NOT NULL
    `, assetType, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// GetHostIDsByPatterns returns UUIDs of hosts whose canonical_hostname matches
// any of the provided glob-style patterns. Patterns use '*' (any sequence)
// and '?' (any single character) — converted to SQL ILIKE syntax.
// Character classes ([seq]) from filepath.Match are not supported in SQL;
// callers that need character classes should pass explicit host_ids instead.
// Literal '%' and '_' in patterns are escaped to prevent unintended wildcarding.
func (s *PostgresStore) GetHostIDsByPatterns(ctx context.Context, patterns []string) ([]string, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	// Escape SQL ILIKE metacharacters before translating glob wildcards.
	// Order matters: backslash first (escape char), then % and _, then glob chars.
	replacer := strings.NewReplacer(
		`\`, `\\`,
		`%`, `\%`,
		`_`, `\_`,
		`*`, `%`,
		`?`, `_`,
	)
	like := make([]string, len(patterns))
	for i, p := range patterns {
		like[i] = replacer.Replace(p)
	}
	// Use unnest to apply per-element ESCAPE clause.
	// canonical_hostname ILIKE p ESCAPE '\' for each pattern p.
	rows, err := s.pool.Query(ctx, `
        SELECT DISTINCT id::text FROM hosts
        WHERE EXISTS (
            SELECT 1 FROM unnest($1::text[]) AS p
            WHERE canonical_hostname ILIKE p ESCAPE '\'
        )
    `, like)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ListScopeAssets returns the most recently scored AssetHealthReport for every
// asset that has at least one provenance record on a host in q.HostIDs.
// Results are filtered by q.AssetTypes (empty = all) and q.MinRiskScore.
func (s *PostgresStore) ListScopeAssets(ctx context.Context, q ScopeAssetQuery) ([]ScopeAssetRow, error) {
	if len(q.HostIDs) == 0 {
		return nil, nil
	}

	args := []any{q.HostIDs, q.MinRiskScore}
	typeClause := ""
	if len(q.AssetTypes) > 0 {
		typeClause = fmt.Sprintf(" AND ahr.asset_type = ANY($%d)", len(args)+1)
		args = append(args, q.AssetTypes)
	}

	sql := `
        SELECT DISTINCT ON (ahr.asset_type, ahr.asset_id)
            ahr.id, ahr.asset_type, ahr.asset_id,
            ahr.grade, ahr.score, ahr.risk_score, ahr.risk_factors,
            ahr.pqc_status, ahr.compliance, ahr.findings,
            ahr.scored_at, ahr.rule_engine_version,
            (SELECT array_agg(DISTINCT src.source ORDER BY src.source)
             FROM asset_provenance src
             WHERE src.asset_type = ahr.asset_type AND src.asset_id = ahr.asset_id
               AND src.host_id = ANY($1::uuid[])
               AND src.source IS NOT NULL) AS sources,
            CASE WHEN ahr.asset_type = 'crypto_library'
                 THEN (SELECT cl.library_name FROM crypto_libraries cl WHERE cl.id::text = ahr.asset_id LIMIT 1)
                 ELSE NULL END AS library_name,
            CASE WHEN ahr.asset_type = 'crypto_library'
                 THEN (SELECT cl.version FROM crypto_libraries cl WHERE cl.id::text = ahr.asset_id LIMIT 1)
                 ELSE NULL END AS library_version
        FROM asset_health_reports ahr
        JOIN asset_provenance ap
            ON ahr.asset_type = ap.asset_type AND ahr.asset_id = ap.asset_id
        WHERE ap.host_id = ANY($1::uuid[])
          AND ahr.risk_score >= $2
    ` + typeClause + `
        ORDER BY ahr.asset_type, ahr.asset_id, ahr.scored_at DESC
    `

	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []ScopeAssetRow
	for rows.Next() {
		var row ScopeAssetRow
		var riskFactors, compliance, findings []byte
		var libraryName, libraryVersion *string
		err := rows.Scan(
			&row.Report.ID,
			&row.AssetType, &row.AssetID,
			&row.Report.Grade, &row.Report.Score,
			&row.Report.RiskScore, &riskFactors,
			&row.Report.PQCStatus, &compliance, &findings,
			&row.Report.ScoredAt, &row.Report.RuleEngineVersion,
			&row.Sources,
			&libraryName, &libraryVersion,
		)
		if err != nil {
			return nil, err
		}
		if libraryName != nil {
			row.LibraryName = *libraryName
		}
		if libraryVersion != nil {
			row.LibraryVersion = *libraryVersion
		}
		row.Report.AssetType = row.AssetType
		row.Report.AssetID = row.AssetID
		if err := json.Unmarshal(riskFactors, &row.Report.RiskFactors); err != nil {
			return nil, fmt.Errorf("unmarshal risk_factors: %w", err)
		}
		if err := json.Unmarshal(compliance, &row.Report.Compliance); err != nil {
			return nil, fmt.Errorf("unmarshal compliance: %w", err)
		}
		row.Report.Findings = adaptFindings(findings)
		result = append(result, row)
	}
	return result, rows.Err()
}

// ListAllAssetHealthReports returns the most-recently-scored
// AssetHealthReport for every scored asset in the database, regardless
// of host provenance or application tag. Powers the agency-wide
// evidence pack (AQ-CE-04) which needs a complete inventory snapshot.
//
// Tolerant findings unmarshal — see ListApplicationScopeAssets.
func (s *PostgresStore) ListAllAssetHealthReports(ctx context.Context) ([]ScopeAssetRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT ON (asset_type, asset_id)
		    id, asset_type, asset_id,
		    grade, score, risk_score, risk_factors,
		    pqc_status, compliance, findings,
		    scored_at, rule_engine_version,
		    (SELECT array_agg(DISTINCT src.source ORDER BY src.source)
		     FROM asset_provenance src
		     WHERE src.asset_type = ahr.asset_type AND src.asset_id = ahr.asset_id
		       AND src.source IS NOT NULL) AS sources,
		    CASE WHEN ahr.asset_type = 'crypto_library'
		         THEN (SELECT cl.library_name FROM crypto_libraries cl WHERE cl.id::text = ahr.asset_id LIMIT 1)
		         ELSE NULL END AS library_name,
		    CASE WHEN ahr.asset_type = 'crypto_library'
		         THEN (SELECT cl.version FROM crypto_libraries cl WHERE cl.id::text = ahr.asset_id LIMIT 1)
		         ELSE NULL END AS library_version
		FROM asset_health_reports ahr
		ORDER BY ahr.asset_type, ahr.asset_id, ahr.scored_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list all asset health reports: %w", err)
	}
	defer rows.Close()

	var result []ScopeAssetRow
	for rows.Next() {
		var row ScopeAssetRow
		var riskFactors, compliance, findings []byte
		var libraryName, libraryVersion *string
		if err := rows.Scan(
			&row.Report.ID,
			&row.AssetType, &row.AssetID,
			&row.Report.Grade, &row.Report.Score,
			&row.Report.RiskScore, &riskFactors,
			&row.Report.PQCStatus, &compliance, &findings,
			&row.Report.ScoredAt, &row.Report.RuleEngineVersion,
			&row.Sources,
			&libraryName, &libraryVersion,
		); err != nil {
			return nil, err
		}
		if libraryName != nil {
			row.LibraryName = *libraryName
		}
		if libraryVersion != nil {
			row.LibraryVersion = *libraryVersion
		}
		row.Report.AssetType = row.AssetType
		row.Report.AssetID = row.AssetID
		_ = json.Unmarshal(riskFactors, &row.Report.RiskFactors)
		_ = json.Unmarshal(compliance, &row.Report.Compliance)
		row.Report.Findings = adaptFindings(findings)
		result = append(result, row)
	}
	return result, rows.Err()
}

// ListApplicationScopeAssets returns the most-recently-scored
// AssetHealthReport for every asset that carries the given
// application_tag, across all seven tag-carrying asset tables. The
// return shape matches ListScopeAssets so downstream consumers
// (cbom.Generator.mapRow) work unchanged.
//
// Findings are unmarshaled tolerantly — the Layer-6 repo scanner writes
// a wrapped JSONB object via AssetHealthReport.RawFindings rather than a
// plain array, so rigid json.Unmarshal would error on those rows. We
// zero the Findings slice in that case; the CBOM generator uses grade/
// score/PQCStatus to build components, not the finding list.
func (s *PostgresStore) ListApplicationScopeAssets(ctx context.Context, tag string) ([]ScopeAssetRow, error) {
	if tag == "" {
		return nil, fmt.Errorf("list application scope assets: empty tag")
	}

	rows, err := s.pool.Query(ctx, `
		WITH tagged AS (
			SELECT fingerprint_sha256 AS asset_id, 'certificate' AS asset_type FROM certificates WHERE $1 = ANY(application_tags)
			UNION ALL
			SELECT id::text, 'ssh_key'           FROM ssh_keys           WHERE $1 = ANY(application_tags)
			UNION ALL
			SELECT id::text, 'crypto_library'    FROM crypto_libraries   WHERE $1 = ANY(application_tags)
			UNION ALL
			SELECT id::text, 'crypto_config'     FROM crypto_configs     WHERE $1 = ANY(application_tags)
			UNION ALL
			SELECT id::text, 'protocol_endpoint' FROM protocol_endpoints WHERE $1 = ANY(application_tags)
			UNION ALL
			SELECT id::text, 'host'              FROM hosts              WHERE $1 = ANY(application_tags)
			UNION ALL
			SELECT id::text, 'repository'        FROM repositories       WHERE $1 = ANY(application_tags)
		)
		SELECT DISTINCT ON (ahr.asset_type, ahr.asset_id)
		    ahr.id, ahr.asset_type, ahr.asset_id,
		    ahr.grade, ahr.score, ahr.risk_score, ahr.risk_factors,
		    ahr.pqc_status, ahr.compliance, ahr.findings,
		    ahr.scored_at, ahr.rule_engine_version,
		    (SELECT array_agg(DISTINCT src.source ORDER BY src.source)
		     FROM asset_provenance src
		     WHERE src.asset_type = ahr.asset_type AND src.asset_id = ahr.asset_id
		       AND src.source IS NOT NULL) AS sources,
		    CASE WHEN ahr.asset_type = 'crypto_library'
		         THEN (SELECT cl.library_name FROM crypto_libraries cl WHERE cl.id::text = ahr.asset_id LIMIT 1)
		         ELSE NULL END AS library_name,
		    CASE WHEN ahr.asset_type = 'crypto_library'
		         THEN (SELECT cl.version FROM crypto_libraries cl WHERE cl.id::text = ahr.asset_id LIMIT 1)
		         ELSE NULL END AS library_version
		FROM asset_health_reports ahr
		JOIN tagged t ON t.asset_type = ahr.asset_type AND t.asset_id = ahr.asset_id
		ORDER BY ahr.asset_type, ahr.asset_id, ahr.scored_at DESC
	`, tag)
	if err != nil {
		return nil, fmt.Errorf("list application scope assets: %w", err)
	}
	defer rows.Close()

	var result []ScopeAssetRow
	for rows.Next() {
		var row ScopeAssetRow
		var riskFactors, compliance, findings []byte
		var libraryName, libraryVersion *string
		if err := rows.Scan(
			&row.Report.ID,
			&row.AssetType, &row.AssetID,
			&row.Report.Grade, &row.Report.Score,
			&row.Report.RiskScore, &riskFactors,
			&row.Report.PQCStatus, &compliance, &findings,
			&row.Report.ScoredAt, &row.Report.RuleEngineVersion,
			&row.Sources,
			&libraryName, &libraryVersion,
		); err != nil {
			return nil, err
		}
		if libraryName != nil {
			row.LibraryName = *libraryName
		}
		if libraryVersion != nil {
			row.LibraryVersion = *libraryVersion
		}
		row.Report.AssetType = row.AssetType
		row.Report.AssetID = row.AssetID
		_ = json.Unmarshal(riskFactors, &row.Report.RiskFactors)
		_ = json.Unmarshal(compliance, &row.Report.Compliance)
		// Dual-shape findings adapter — see internal/store/findings_adapter.go.
		// Scanner FindingRecord rows (detected by the `bucket` key) are
		// enriched with synthesized Title/Category/Deduction/Remediation so
		// they surface in top-contributing-rules + evidence-pack output.
		row.Report.Findings = adaptFindings(findings)
		result = append(result, row)
	}
	return result, rows.Err()
}
