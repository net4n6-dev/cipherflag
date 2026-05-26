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
	"encoding/json"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

func TestSaveAndGetAssetHealthReport(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	report := &model.AssetHealthReport{
		AssetType: "ssh_key",
		AssetID:   "test-key-id-123",
		Grade:     "B",
		Score:     75,
		Findings: []model.HealthFinding{
			{RuleID: "SSH-001", Severity: "medium", Title: "RSA key under 4096 bits", Detail: "Key uses 2048-bit RSA"},
		},
		PQCStatus:   "vulnerable",
		Compliance:  map[string]string{"nist": "partial"},
		ScoredAt:    time.Now().Truncate(time.Microsecond),
		RiskScore:   75,
		RiskFactors: map[string]int{"algo_weakness": 50, "quantum_urgency": 80, "compliance_gap": 40},
	}

	if err := st.SaveAssetHealthReport(ctx, report); err != nil {
		t.Fatalf("SaveAssetHealthReport: %v", err)
	}

	got, err := st.GetAssetHealthReport(ctx, "ssh_key", "test-key-id-123")
	if err != nil {
		t.Fatalf("GetAssetHealthReport: %v", err)
	}
	if got == nil {
		t.Fatal("expected report, got nil")
	}
	if got.Grade != "B" {
		t.Errorf("grade = %q, want B", got.Grade)
	}
	if got.Score != 75 {
		t.Errorf("score = %d, want 75", got.Score)
	}
	if got.PQCStatus != "vulnerable" {
		t.Errorf("pqc_status = %q, want vulnerable", got.PQCStatus)
	}
	if got.Compliance["nist"] != "partial" {
		t.Errorf("compliance[nist] = %q, want partial", got.Compliance["nist"])
	}
	if got.RiskScore != 75 {
		t.Errorf("RiskScore = %d, want 75", got.RiskScore)
	}
	if got.RiskFactors["algo_weakness"] != 50 {
		t.Errorf("RiskFactors[algo_weakness] = %d, want 50", got.RiskFactors["algo_weakness"])
	}
	if got.RiskFactors["quantum_urgency"] != 80 {
		t.Errorf("RiskFactors[quantum_urgency] = %d, want 80", got.RiskFactors["quantum_urgency"])
	}
	if got.RiskFactors["compliance_gap"] != 40 {
		t.Errorf("RiskFactors[compliance_gap] = %d, want 40", got.RiskFactors["compliance_gap"])
	}
}

func TestSaveAssetHealthReport_Upsert(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	report1 := &model.AssetHealthReport{
		AssetType: "certificate", AssetID: "cert-fp-abc",
		Grade: "C", Score: 55, Findings: []model.HealthFinding{},
		PQCStatus: "unknown", Compliance: map[string]string{},
		ScoredAt:    time.Now(),
		RiskScore:   10,
		RiskFactors: map[string]int{"a": 1},
	}
	if err := st.SaveAssetHealthReport(ctx, report1); err != nil {
		t.Fatalf("first SaveAssetHealthReport: %v", err)
	}

	report2 := &model.AssetHealthReport{
		AssetType: "certificate", AssetID: "cert-fp-abc",
		Grade: "A", Score: 90, Findings: []model.HealthFinding{},
		PQCStatus: "safe", Compliance: map[string]string{"pci": "compliant"},
		ScoredAt:    time.Now(),
		RiskScore:   90,
		RiskFactors: map[string]int{"algo_weakness": 80},
	}
	if err := st.SaveAssetHealthReport(ctx, report2); err != nil {
		t.Fatalf("second SaveAssetHealthReport: %v", err)
	}

	got, err := st.GetAssetHealthReport(ctx, "certificate", "cert-fp-abc")
	if err != nil {
		t.Fatalf("GetAssetHealthReport: %v", err)
	}
	if got.Grade != "A" {
		t.Errorf("grade after upsert = %q, want A", got.Grade)
	}
	if got.Score != 90 {
		t.Errorf("score after upsert = %d, want 90", got.Score)
	}
	if got.RiskScore != 90 {
		t.Errorf("RiskScore after upsert = %d, want 90", got.RiskScore)
	}
	if got.RiskFactors["algo_weakness"] != 80 {
		t.Errorf("RiskFactors after upsert should reflect report2")
	}
}

func TestGetAssetHealthReport_NotFound(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	got, err := st.GetAssetHealthReport(ctx, "nonexistent", "no-such-id")
	if err != nil {
		t.Fatalf("GetAssetHealthReport: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}

func TestRecordAndGetProvenance(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := seedHost(t, st)

	prov := &model.AssetProvenance{
		AssetType:   "certificate",
		AssetID:     "cert-fp-xyz",
		Source:      "zeek_passive",
		HostID:      host.ID,
		FilePath:    "",
		StoreType:   "network",
		RawMetadata: map[string]any{"zeek_uid": "CHhAvVGS1DHFjwGM9"},
	}

	if err := st.RecordProvenance(ctx, prov); err != nil {
		t.Fatalf("RecordProvenance: %v", err)
	}

	records, err := st.GetProvenance(ctx, "certificate", "cert-fp-xyz")
	if err != nil {
		t.Fatalf("GetProvenance: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("provenance count = %d, want 1", len(records))
	}
	if records[0].Source != "zeek_passive" {
		t.Errorf("source = %q, want zeek_passive", records[0].Source)
	}
	if records[0].HostID != host.ID {
		t.Errorf("host_id = %q, want %q", records[0].HostID, host.ID)
	}
}

func TestRecordProvenance_Dedup(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := seedHost(t, st)

	prov := &model.AssetProvenance{
		AssetType: "certificate", AssetID: "cert-dedup", Source: "osquery",
		HostID: host.ID, StoreType: "filesystem",
		RawMetadata: map[string]any{"path": "/etc/ssl/cert.pem"},
	}

	if err := st.RecordProvenance(ctx, prov); err != nil {
		t.Fatalf("first RecordProvenance: %v", err)
	}
	if err := st.RecordProvenance(ctx, prov); err != nil {
		t.Fatalf("second RecordProvenance: %v", err)
	}

	records, err := st.GetProvenance(ctx, "certificate", "cert-dedup")
	if err != nil {
		t.Fatalf("GetProvenance: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("provenance count after dedup = %d, want 1", len(records))
	}
}

func TestRecordProvenance_NullHostID_Coalesce(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	prov1 := &model.AssetProvenance{
		AssetType: "certificate", AssetID: "cert-network",
		Source: "zeek_passive", RawMetadata: map[string]any{},
	}
	prov2 := &model.AssetProvenance{
		AssetType: "certificate", AssetID: "cert-network",
		Source: "zeek_passive", RawMetadata: map[string]any{"uid": "new"},
	}

	if err := st.RecordProvenance(ctx, prov1); err != nil {
		t.Fatalf("first RecordProvenance null host: %v", err)
	}
	if err := st.RecordProvenance(ctx, prov2); err != nil {
		t.Fatalf("second RecordProvenance null host: %v", err)
	}

	records, err := st.GetProvenance(ctx, "certificate", "cert-network")
	if err != nil {
		t.Fatalf("GetProvenance: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("provenance count with null host = %d, want 1 (COALESCE dedup)", len(records))
	}
}

func TestRecordProvenance_MultipleSourcesSameAsset(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := seedHost(t, st)

	sources := []string{"zeek_passive", "osquery", "active_scan"}
	for _, src := range sources {
		prov := &model.AssetProvenance{
			AssetType: "certificate", AssetID: "multi-source-cert",
			Source: src, HostID: host.ID,
			RawMetadata: map[string]any{},
		}
		if err := st.RecordProvenance(ctx, prov); err != nil {
			t.Fatalf("RecordProvenance %s: %v", src, err)
		}
	}

	records, err := st.GetProvenance(ctx, "certificate", "multi-source-cert")
	if err != nil {
		t.Fatalf("GetProvenance: %v", err)
	}
	if len(records) != 3 {
		t.Errorf("provenance count = %d, want 3 (one per source)", len(records))
	}
}

func TestRecordProvenance_WithExternalSourceID(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// Seed an external_source row to FK against.
	src := &ExternalSource{
		Kind:                "aws_account",
		DisplayName:         "prov-fk-test",
		Config:              json.RawMessage(`{}`),
		Enabled:             true,
		PollIntervalSeconds: 3600,
	}
	if err := st.CreateExternalSource(ctx, src); err != nil {
		t.Fatalf("CreateExternalSource: %v", err)
	}

	prov := &model.AssetProvenance{
		AssetType:        "certificate",
		AssetID:          "cert-for-prov-test",
		Source:           "aws_acm",
		ExternalSourceID: src.ID,
	}
	if err := st.RecordProvenance(ctx, prov); err != nil {
		t.Fatalf("RecordProvenance: %v", err)
	}

	// Verify via direct query.
	var got *string
	err := st.Pool().QueryRow(ctx, `
		SELECT external_source_id::text
		FROM asset_provenance
		WHERE asset_type = $1 AND asset_id = $2 AND source = $3
	`, "certificate", "cert-for-prov-test", "aws_acm").Scan(&got)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if got == nil {
		t.Fatal("external_source_id is NULL; want non-NULL")
	}
	if *got != src.ID {
		t.Errorf("external_source_id = %q, want %q", *got, src.ID)
	}
}

func TestRecordProvenance_EmptyExternalSourceID_Stays_NULL(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	prov := &model.AssetProvenance{
		AssetType: "certificate",
		AssetID:   "cert-no-src",
		Source:    "file_scan",
		// ExternalSourceID left empty
	}
	if err := st.RecordProvenance(ctx, prov); err != nil {
		t.Fatalf("RecordProvenance: %v", err)
	}

	var got *string
	err := st.Pool().QueryRow(ctx, `
		SELECT external_source_id::text
		FROM asset_provenance
		WHERE asset_type = $1 AND asset_id = $2 AND source = $3
	`, "certificate", "cert-no-src", "file_scan").Scan(&got)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if got != nil {
		t.Errorf("external_source_id = %q, want NULL", *got)
	}
}
