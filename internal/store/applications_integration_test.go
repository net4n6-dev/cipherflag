//go:build integration

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
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// TestGetApplication_MixesScannerAndScorerFindings pins the v1.3.1
// hardening: repo-scanner FindingRecord rows tagged with the same
// application_tag as scoring-engine HealthFinding rows must BOTH
// surface in TopContributingRules on the application detail response.
//
// Before the read-time adapter (internal/store/findings_adapter.go)
// scanner findings unmarshaled with Deduction=0, which
// aggregateTopRules then filtered out via its
// `if f.Deduction <= 0 { continue }` gate. This test inserts both
// shapes and asserts the mixed aggregation is correct.
func TestGetApplication_MixesScannerAndScorerFindings(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	tag := "test-app-mixed"

	// --- Scoring-engine-shape row on a crypto_config (native HealthFinding).
	// Note: certificates / ssh_keys / crypto_libraries are blocked by a
	// trigger bug in migration 019 (references NEW.source which doesn't
	// exist; column is source_discovery). crypto_configs has no such
	// trigger. This test is deliberately routed around the bug.
	var hostID string
	if err := st.pool.QueryRow(ctx, `
		INSERT INTO hosts (canonical_hostname, os_family, host_type, application_tags)
		VALUES ('test-host-mixed.example', 'linux', 'server', ARRAY[$1])
		RETURNING id::text
	`, tag).Scan(&hostID); err != nil {
		t.Fatalf("insert host: %v", err)
	}

	var configID string
	if err := st.pool.QueryRow(ctx, `
		INSERT INTO crypto_configs
			(host_id, file_path, config_type, source, application_tags)
		VALUES
			($1::uuid, '/etc/nginx/ssl.conf', 'nginx', 'test', ARRAY[$2])
		RETURNING id::text
	`, hostID, tag).Scan(&configID); err != nil {
		t.Fatalf("insert crypto_config: %v", err)
	}

	scorerDeadline := time.Now().Add(30 * 24 * time.Hour)
	scorerReport := &model.AssetHealthReport{
		AssetType:         "crypto_config",
		AssetID:           configID,
		Grade:             "B",
		Score:             78,
		PQCStatus:         "vulnerable",
		Compliance:        map[string]string{"cnsa_2": "fail"},
		RuleEngineVersion: 3,
		ScoredAt:          time.Now(),
		RiskScore:         45,
		RiskFactors:       map[string]int{"algo_weakness": 40, "quantum_urgency": 50, "compliance_gap": 50},
		Findings: []model.HealthFinding{
			{
				RuleID:        "CFG-001",
				Title:         "Weak TLS config",
				Severity:      model.SeverityHigh,
				Category:      model.CategoryProtocol,
				Detail:        "TLSv1.0 enabled",
				Remediation:   "disable TLSv1.0, set min TLS 1.2",
				Deduction:     30,
				ScopeDeadline: &scorerDeadline,
			},
		},
	}
	if err := st.SaveAssetHealthReport(ctx, scorerReport); err != nil {
		t.Fatalf("save scorer report: %v", err)
	}

	// --- Scanner-shape row on a repository (raw FindingRecord JSONB).
	// Need a provider first (FK requirement from migration 014).
	var providerID string
	if err := st.pool.QueryRow(ctx, `
		INSERT INTO providers (kind, base_url, auth_secret_ref)
		VALUES ('github', 'https://test-mixed.example', 'env:TEST')
		RETURNING id
	`).Scan(&providerID); err != nil {
		t.Fatalf("insert provider: %v", err)
	}

	// Insert the repository row, then write an asset_health_report with
	// RawFindings set to the wire shape the scanner pipeline actually
	// produces (see internal/scanner/pipeline/pipeline.go::convertFindingsIntoReport).
	var repoID string
	if err := st.pool.QueryRow(ctx, `
		INSERT INTO repositories
			(provider_id, url, default_branch, default_scan_mode, application_tags)
		VALUES
			($1, 'https://example.com/mixed-repo.git', 'main', 'deterministic', ARRAY[$2])
		RETURNING id
	`, providerID, tag).Scan(&repoID); err != nil {
		t.Fatalf("insert repository: %v", err)
	}

	// Raw scanner-shape JSON — marshaled []FindingRecord as the scanner
	// pipeline would produce. Deduction / Title / Category / Remediation
	// are deliberately absent, matching the real wire shape.
	scannerRawJSON := []byte(`[
		{"rule_id": "B1-PEM-PRIVKEY", "severity": "Critical", "bucket": "B1",
		 "path": "deploy/prod.pem", "detected_by": ["det:b1-pem-privkey"],
		 "confidence": 1.0, "scan_id": "scan-test-1",
		 "model_attribution": "deterministic"},
		{"rule_id": "B3-MD5", "severity": "High", "bucket": "B3",
		 "path": "src/legacy/hash.go", "detected_by": ["det:b3-md5"],
		 "confidence": 1.0, "scan_id": "scan-test-1",
		 "model_attribution": "deterministic"}
	]`)
	scannerReport := &model.AssetHealthReport{
		AssetType:         "repository",
		AssetID:           repoID,
		Grade:             "F",
		Score:             30,
		PQCStatus:         "unknown",
		Compliance:        map[string]string{},
		RuleEngineVersion: 3,
		ScoredAt:          time.Now(),
		RiskScore:         90,
		RiskFactors:       map[string]int{"algo_weakness": 80},
		RawFindings:       scannerRawJSON,
	}
	if err := st.SaveAssetHealthReport(ctx, scannerReport); err != nil {
		t.Fatalf("save scanner report: %v", err)
	}

	// --- Now exercise the Application read path.
	detail, err := st.GetApplication(ctx, tag)
	if err != nil {
		t.Fatalf("GetApplication: %v", err)
	}
	if detail == nil {
		t.Fatalf("GetApplication returned nil for tag %q", tag)
	}

	// Scoped assets: host + config + repo (host is tagged too).
	if detail.TotalAssets != 3 {
		t.Errorf("TotalAssets = %d; expected 3 (host + config + repo)", detail.TotalAssets)
	}
	if got := detail.AssetCounts["crypto_config"]; got != 1 {
		t.Errorf("AssetCounts[crypto_config] = %d; expected 1", got)
	}
	if got := detail.AssetCounts["repository"]; got != 1 {
		t.Errorf("AssetCounts[repository] = %d; expected 1", got)
	}
	if got := detail.AssetCounts["host"]; got != 1 {
		t.Errorf("AssetCounts[host] = %d; expected 1", got)
	}

	// TopContributingRules must include BOTH the scorer rule (CFG-001)
	// and the scanner rules (B1-PEM-PRIVKEY, B3-MD5). Before v1.3.1
	// this assertion fails because the scanner rules are silently
	// dropped at aggregateTopRules's Deduction<=0 gate.
	ruleIDs := map[string]int{} // rule_id -> total deduction
	for _, c := range detail.TopContributingRules {
		ruleIDs[c.RuleID] = c.TotalDeduction
	}
	if _, ok := ruleIDs["CFG-001"]; !ok {
		t.Errorf("TopContributingRules missing CFG-001; got %v", ruleIDs)
	}
	if d := ruleIDs["B1-PEM-PRIVKEY"]; d <= 0 {
		t.Errorf("TopContributingRules missing B1-PEM-PRIVKEY (scanner Critical); got map=%v — v1.3.1 regression", ruleIDs)
	}
	if d := ruleIDs["B3-MD5"]; d <= 0 {
		t.Errorf("TopContributingRules missing B3-MD5 (scanner High); got map=%v — v1.3.1 regression", ruleIDs)
	}
	// Ranking must respect severity: Critical (B1) should deduct more
	// than High (B3 / CFG-001).
	if ruleIDs["B1-PEM-PRIVKEY"] <= ruleIDs["B3-MD5"] {
		t.Errorf("expected Critical > High synthesized deduction; got B1=%d B3=%d",
			ruleIDs["B1-PEM-PRIVKEY"], ruleIDs["B3-MD5"])
	}

	// Cleanup — avoid cross-test pollution.
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM asset_health_reports WHERE asset_id IN ($1, $2)`, configID, repoID)
		_, _ = st.pool.Exec(ctx, `DELETE FROM crypto_configs WHERE id::text = $1`, configID)
		_, _ = st.pool.Exec(ctx, `DELETE FROM repositories WHERE id = $1`, repoID)
		_, _ = st.pool.Exec(ctx, `DELETE FROM providers WHERE id = $1`, providerID)
		_, _ = st.pool.Exec(ctx, `DELETE FROM hosts WHERE id::text = $1`, hostID)
	})
}
