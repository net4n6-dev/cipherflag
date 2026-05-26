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

func (s *PostgresStore) SaveAssetHealthReport(ctx context.Context, report *model.AssetHealthReport) error {
	// Prefer RawFindings if the caller supplied a richer JSONB shape than
	// HealthFinding can represent (e.g. scanner B3 findings with bucket+cbom).
	var findings []byte
	if len(report.RawFindings) > 0 {
		findings = report.RawFindings
	} else {
		findings, _ = json.Marshal(report.Findings)
	}
	compliance, _ := json.Marshal(report.Compliance)
	riskFactors, _ := json.Marshal(report.RiskFactors)

	err := s.pool.QueryRow(ctx, `
		INSERT INTO asset_health_reports (asset_type, asset_id, grade, score, findings, pqc_status, compliance, rule_engine_version, scored_at, risk_score, risk_factors)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (asset_type, asset_id) DO UPDATE SET
			grade = EXCLUDED.grade,
			score = EXCLUDED.score,
			findings = EXCLUDED.findings,
			pqc_status = EXCLUDED.pqc_status,
			compliance = EXCLUDED.compliance,
			rule_engine_version = EXCLUDED.rule_engine_version,
			scored_at = EXCLUDED.scored_at,
			risk_score = EXCLUDED.risk_score,
			risk_factors = EXCLUDED.risk_factors
		RETURNING id
	`, report.AssetType, report.AssetID, report.Grade, report.Score,
		findings, report.PQCStatus, compliance, report.RuleEngineVersion, report.ScoredAt,
		report.RiskScore, riskFactors,
	).Scan(&report.ID)
	if err != nil {
		return fmt.Errorf("save asset health report: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetAssetHealthReport(ctx context.Context, assetType, assetID string) (*model.AssetHealthReport, error) {
	r := &model.AssetHealthReport{}
	var findingsB, complianceB, riskFactorsB []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, asset_type, asset_id, grade, score, findings, pqc_status, compliance, rule_engine_version, scored_at, risk_score, risk_factors
		FROM asset_health_reports
		WHERE asset_type = $1 AND asset_id = $2
	`, assetType, assetID).Scan(
		&r.ID, &r.AssetType, &r.AssetID, &r.Grade, &r.Score,
		&findingsB, &r.PQCStatus, &complianceB, &r.RuleEngineVersion, &r.ScoredAt,
		&r.RiskScore, &riskFactorsB,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get asset health report: %w", err)
	}
	json.Unmarshal(findingsB, &r.Findings)
	json.Unmarshal(complianceB, &r.Compliance)
	json.Unmarshal(riskFactorsB, &r.RiskFactors)
	if r.Findings == nil {
		r.Findings = []model.HealthFinding{}
	}
	if r.Compliance == nil {
		r.Compliance = map[string]string{}
	}
	if r.RiskFactors == nil {
		r.RiskFactors = map[string]int{}
	}
	return r, nil
}

// MergeFindingsForAsset performs a read-modify-write on the findings JSONB
// column for (assetType, assetID), replacing only the entries whose rule_id
// matches one of the rule_ids present in findings while preserving all other
// scorers' findings. If no row exists for the pair, a new one is inserted with
// just the supplied findings (grade/score default to empty/0 per column
// defaults).
//
// The operation is atomic — a single SQL UPSERT with no SELECT-then-UPDATE
// race window. Callers do NOT need an external transaction.
func (s *PostgresStore) MergeFindingsForAsset(ctx context.Context, assetType, assetID string, findings []model.HealthFinding) error {
	if len(findings) == 0 {
		return nil
	}

	// Collect the distinct rule_ids in findings to form the merge-authority set.
	ruleIDSet := make(map[string]struct{}, len(findings))
	for _, f := range findings {
		ruleIDSet[f.RuleID] = struct{}{}
	}
	ruleIDs := make([]string, 0, len(ruleIDSet))
	for id := range ruleIDSet {
		ruleIDs = append(ruleIDs, id)
	}

	findingsJSON, err := json.Marshal(findings)
	if err != nil {
		return fmt.Errorf("merge findings: marshal: %w", err)
	}

	// The subquery filters out existing findings whose rule_id is in the
	// merge-authority set ($4), then concatenates the kept findings with the
	// new ones. COALESCE handles jsonb_agg returning NULL on empty input.
	_, err = s.pool.Exec(ctx, `
		INSERT INTO asset_health_reports (asset_type, asset_id, findings, scored_at)
		VALUES ($1, $2, $3::jsonb, NOW())
		ON CONFLICT (asset_type, asset_id) DO UPDATE SET
		    findings = COALESCE(
		        (SELECT jsonb_agg(elem)
		         FROM jsonb_array_elements(asset_health_reports.findings) elem
		         WHERE NOT (elem->>'rule_id' = ANY($4::text[]))),
		        '[]'::jsonb
		    ) || EXCLUDED.findings,
		    scored_at = NOW()
	`, assetType, assetID, string(findingsJSON), ruleIDs)
	if err != nil {
		return fmt.Errorf("merge findings for asset (%s/%s): %w", assetType, assetID, err)
	}
	return nil
}

func (s *PostgresStore) RecordProvenance(ctx context.Context, prov *model.AssetProvenance) error {
	rawMeta, _ := json.Marshal(prov.RawMetadata)

	var hostID any
	if prov.HostID != "" {
		hostID = prov.HostID
	}

	// PostgreSQL does not support expressions in ON CONFLICT column lists, so we
	// use a SELECT-then-INSERT-or-UPDATE pattern to honour the functional unique
	// index idx_provenance_unique which is defined on
	// (asset_type, asset_id, source, COALESCE(host_id, '00000000-...')).
	var existingID string
	err := s.pool.QueryRow(ctx, `
		SELECT id FROM asset_provenance
		WHERE asset_type = $1
		  AND asset_id   = $2
		  AND source     = $3
		  AND COALESCE(host_id, '00000000-0000-0000-0000-000000000000'::uuid)
		    = COALESCE($4::uuid, '00000000-0000-0000-0000-000000000000'::uuid)
	`, prov.AssetType, prov.AssetID, prov.Source, hostID).Scan(&existingID)

	if err == pgx.ErrNoRows {
		// No existing row — insert.
		var extSrcIDArg any
		if prov.ExternalSourceID != "" {
			extSrcIDArg = prov.ExternalSourceID
		}
		// Note: passing `nil` via `any` sends SQL NULL; passing the string sends the UUID.

		_, err = s.pool.Exec(ctx, `
			INSERT INTO asset_provenance
				(asset_type, asset_id, source, host_id, file_path, store_type, raw_metadata, external_source_id, first_seen, last_seen)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
		`, prov.AssetType, prov.AssetID, prov.Source, hostID,
			prov.FilePath, prov.StoreType, rawMeta, extSrcIDArg,
		)
		if err != nil {
			return fmt.Errorf("insert provenance: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("record provenance lookup: %w", err)
	}

	// Existing row — update.
	_, err = s.pool.Exec(ctx, `
		UPDATE asset_provenance
		SET last_seen    = NOW(),
		    file_path    = $2,
		    store_type   = $3,
		    raw_metadata = $4
		WHERE id = $1
	`, existingID, prov.FilePath, prov.StoreType, rawMeta)
	if err != nil {
		return fmt.Errorf("update provenance: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetProvenance(ctx context.Context, assetType, assetID string) ([]model.AssetProvenance, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, asset_type, asset_id, source, COALESCE(host_id::text, ''), file_path, store_type, raw_metadata, first_seen, last_seen, COALESCE(external_source_id::text, '')
		FROM asset_provenance
		WHERE asset_type = $1 AND asset_id = $2
		ORDER BY last_seen DESC
	`, assetType, assetID)
	if err != nil {
		return nil, fmt.Errorf("get provenance: %w", err)
	}
	defer rows.Close()

	var records []model.AssetProvenance
	for rows.Next() {
		var p model.AssetProvenance
		var rawMetaB []byte
		if err := rows.Scan(
			&p.ID, &p.AssetType, &p.AssetID, &p.Source, &p.HostID,
			&p.FilePath, &p.StoreType, &rawMetaB,
			&p.FirstSeen, &p.LastSeen, &p.ExternalSourceID,
		); err != nil {
			return nil, fmt.Errorf("scan provenance row: %w", err)
		}
		json.Unmarshal(rawMetaB, &p.RawMetadata)
		if p.RawMetadata == nil {
			p.RawMetadata = map[string]any{}
		}
		records = append(records, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("get provenance rows: %w", err)
	}
	if records == nil {
		records = []model.AssetProvenance{}
	}
	return records, nil
}
