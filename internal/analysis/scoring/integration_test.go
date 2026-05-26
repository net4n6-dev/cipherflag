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

package scoring

import (
	"context"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
	"github.com/net4n6-dev/cipherflag/internal/testdb"
)

func newIntegrationStore(t *testing.T) *store.PostgresStore {
	t.Helper()
	ctx := context.Background()
	st, err := store.NewPostgresStore(ctx, testdb.Require(t))
	if err != nil {
		t.Skipf("integration DB unavailable: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	tables := []string{
		"asset_provenance",
		"asset_health_reports",
		"agent_tokens",
		"protocol_observations",
		"crypto_configs",
		"crypto_libraries",
		"ssh_keys",
		"host_identifiers",
		"observations",
		"endpoint_profiles",
		"health_reports",
		"ingestion_state",
		"pcap_jobs",
		"certificates",
		"hosts",
		"users",
	}
	pool := st.Pool()
	for _, tbl := range tables {
		if _, err := pool.Exec(ctx, "TRUNCATE TABLE "+tbl+" CASCADE"); err != nil {
			// Table may not exist in earlier migration states; ignore.
			_ = err
		}
	}
	return st
}

// seedHost inserts a host and returns the DB-assigned ID.
func seedHost(t *testing.T, st *store.PostgresStore, hostname string) string {
	t.Helper()
	ctx := context.Background()
	h := &model.Host{
		CanonicalHostname: hostname,
		IPAddresses:       []string{"10.0.0.1"},
		FirstSeen:         time.Now(),
		LastSeen:          time.Now(),
	}
	if err := st.UpsertHost(ctx, h); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	return h.ID
}

// seedSSHKey inserts an RSA-1024 SSH key and returns the DB-assigned ID.
func seedSSHKey(t *testing.T, st *store.PostgresStore, fingerprint, hostID string) string {
	t.Helper()
	ctx := context.Background()
	k := &model.SSHKey{
		HostID:            hostID,
		KeyType:           "ssh-rsa",
		KeySizeBits:       1024,
		FingerprintSHA256: fingerprint,
		FilePath:          "/root/.ssh/id_rsa",
		IsAuthorized:      false,
		IsProtected:       false,
		GrantsRoot:        false,
		Source:            "test",
		DiscoveryStatus:   "active",
		FirstSeen:         time.Now().Add(-100 * 24 * time.Hour),
		LastSeen:          time.Now(),
	}
	if err := st.UpsertSSHKey(ctx, k); err != nil {
		t.Fatalf("seed ssh key: %v", err)
	}
	return k.ID
}

func TestIntegration_ScoreSSHKey_EndToEnd(t *testing.T) {
	st := newIntegrationStore(t)
	ctx := context.Background()

	hostID := seedHost(t, st, "web-01")
	sshID := seedSSHKey(t, st, "sha256:test-fp-001", hostID)

	d := NewDispatcher(st)
	if err := d.ScoreAsset(ctx, "ssh_key", sshID); err != nil {
		t.Fatalf("ScoreAsset: %v", err)
	}

	r, err := st.GetAssetHealthReport(ctx, "ssh_key", sshID)
	if err != nil {
		t.Fatalf("GetAssetHealthReport: %v", err)
	}
	if r == nil {
		t.Fatal("no row persisted")
	}
	if r.RuleEngineVersion != CurrentRuleEngineVersion {
		t.Errorf("RuleEngineVersion = %d, want %d", r.RuleEngineVersion, CurrentRuleEngineVersion)
	}
	foundSSH002 := false
	for _, f := range r.Findings {
		if f.RuleID == "SSH-002" {
			foundSSH002 = true
		}
	}
	if !foundSSH002 {
		t.Error("SSH-002 not in findings")
	}
}

func TestIntegration_ScoreUnknownAsset_ReturnsNil(t *testing.T) {
	st := newIntegrationStore(t)
	ctx := context.Background()

	d := NewDispatcher(st)
	nonExistentID := "ffffffff-ffff-ffff-ffff-ffffffffffff"
	if err := d.ScoreAsset(ctx, "ssh_key", nonExistentID); err != nil {
		t.Errorf("nil asset should not be an error: %v", err)
	}
	r, _ := st.GetAssetHealthReport(ctx, "ssh_key", nonExistentID)
	if r != nil {
		t.Errorf("expected no asset_health_reports row for non-existent asset; got %+v", r)
	}
}

func TestIntegration_Sweeper_BootstrapsExistingAssets(t *testing.T) {
	st := newIntegrationStore(t)
	ctx := context.Background()

	hostID := seedHost(t, st, "sweep-host")
	sshID := seedSSHKey(t, st, "sha256:test-fp-002", hostID)

	d := NewDispatcher(st)
	sw := NewSweeper(st, d, time.Hour, 100)
	sw.runOnce(ctx)

	r, err := st.GetAssetHealthReport(ctx, "ssh_key", sshID)
	if err != nil {
		t.Fatalf("GetAssetHealthReport: %v", err)
	}
	if r == nil {
		t.Fatal("sweeper did not create asset_health_reports row")
	}
	if r.RuleEngineVersion != CurrentRuleEngineVersion {
		t.Errorf("RuleEngineVersion = %d, want %d", r.RuleEngineVersion, CurrentRuleEngineVersion)
	}
}

func TestIntegration_Sweeper_RescoresStaleVersion(t *testing.T) {
	st := newIntegrationStore(t)
	ctx := context.Background()

	hostID := seedHost(t, st, "stale-host")
	sshID := seedSSHKey(t, st, "sha256:test-fp-003", hostID)

	staleReport := &model.AssetHealthReport{
		AssetType:         "ssh_key",
		AssetID:           sshID,
		Grade:             "C",
		Score:             70,
		Findings:          []model.HealthFinding{},
		PQCStatus:         "vulnerable",
		Compliance:        map[string]string{},
		RuleEngineVersion: 0, // stale!
		ScoredAt:          time.Now().Add(-24 * time.Hour),
	}
	if err := st.SaveAssetHealthReport(ctx, staleReport); err != nil {
		t.Fatalf("seed stale: %v", err)
	}

	d := NewDispatcher(st)
	sw := NewSweeper(st, d, time.Hour, 100)
	sw.runOnce(ctx)

	r, err := st.GetAssetHealthReport(ctx, "ssh_key", sshID)
	if err != nil {
		t.Fatalf("GetAssetHealthReport: %v", err)
	}
	if r == nil {
		t.Fatal("row disappeared after sweep")
	}
	if r.RuleEngineVersion != CurrentRuleEngineVersion {
		t.Errorf("RuleEngineVersion after sweep = %d, want %d", r.RuleEngineVersion, CurrentRuleEngineVersion)
	}
}

func TestIntegration_ScoreSSHKey_PopulatesCompliance(t *testing.T) {
	st := newIntegrationStore(t)
	ctx := context.Background()

	hostID := seedHost(t, st, "compliance-host")
	sshID := seedSSHKey(t, st, "sha256:test-fp-compliance-001", hostID)

	d := NewDispatcher(st)
	if err := d.ScoreAsset(ctx, "ssh_key", sshID); err != nil {
		t.Fatalf("ScoreAsset: %v", err)
	}

	r, err := st.GetAssetHealthReport(ctx, "ssh_key", sshID)
	if err != nil {
		t.Fatalf("GetAssetHealthReport: %v", err)
	}
	if r == nil {
		t.Fatal("no row persisted")
	}

	// All 5 frameworks should be populated with non-empty status values
	// after round-trip through Postgres (JSONB serialisation and back).
	expectedFrameworks := []string{
		"nist_800_131a", "pci_dss_4", "fips_140_3", "cnsa_2", "nis2",
	}
	for _, fw := range expectedFrameworks {
		v, ok := r.Compliance[fw]
		if !ok {
			t.Errorf("Compliance[%q] missing after round-trip through Postgres", fw)
			continue
		}
		if v == "" {
			t.Errorf("Compliance[%q] is empty string", fw)
		}
	}
}

func TestIntegration_ScoreSSHKey_PopulatesRisk(t *testing.T) {
	st := newIntegrationStore(t)
	ctx := context.Background()

	hostID := seedHost(t, st, "risk-host")
	sshID := seedSSHKey(t, st, "sha256:test-fp-risk-001", hostID)

	d := NewDispatcher(st)
	if err := d.ScoreAsset(ctx, "ssh_key", sshID); err != nil {
		t.Fatalf("ScoreAsset: %v", err)
	}

	r, err := st.GetAssetHealthReport(ctx, "ssh_key", sshID)
	if err != nil {
		t.Fatalf("GetAssetHealthReport: %v", err)
	}
	if r == nil {
		t.Fatal("no row persisted")
	}

	// RiskScore must be in 0-100.
	if r.RiskScore < 0 || r.RiskScore > 100 {
		t.Errorf("RiskScore %d out of 0-100 range after round-trip", r.RiskScore)
	}

	// RiskFactors must have the three expected keys.
	for _, k := range []string{"algo_weakness", "quantum_urgency", "compliance_gap"} {
		if _, ok := r.RiskFactors[k]; !ok {
			t.Errorf("RiskFactors[%q] missing after JSONB round-trip", k)
		}
	}

	// The seeded SSH key is ssh-rsa 1024 bits, which triggers SSH-002 (fail)
	// so algo_weakness should be substantial (Score degraded by rule stack).
	if r.RiskFactors["algo_weakness"] <= 0 {
		t.Errorf("RSA-1024 SSH key should have algo_weakness > 0, got %d", r.RiskFactors["algo_weakness"])
	}
}
