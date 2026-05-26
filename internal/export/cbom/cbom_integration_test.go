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

package cbom

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/config"
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
	for _, tbl := range []string{
		"asset_health_reports", "asset_provenance", "ssh_keys",
		"crypto_libraries", "crypto_configs", "hosts",
	} {
		_, _ = st.Pool().Exec(ctx, "TRUNCATE TABLE "+tbl+" CASCADE")
	}
	return st
}

func seedHostAndSSHKey(t *testing.T, st *store.PostgresStore) (hostID, keyID string) {
	t.Helper()
	ctx := context.Background()

	host := &model.Host{
		CanonicalHostname: "web-01.prod.corp",
		OSFamily:          "linux",
		HostType:          "server",
	}
	if err := st.UpsertHost(ctx, host); err != nil {
		t.Fatalf("UpsertHost: %v", err)
	}
	h, err := st.FindHostByHostname(ctx, "web-01.prod.corp")
	if err != nil || h == nil {
		t.Fatalf("FindHostByHostname: %v %v", h, err)
	}
	hostID = h.ID

	key := &model.SSHKey{
		HostID:            hostID,
		KeyType:           "ssh-ed25519",
		KeySizeBits:       256,
		FingerprintSHA256: "sha256:integration-test-key",
		DiscoveryStatus:   "active",
		Source:            "test",
		FirstSeen:         time.Now(),
		LastSeen:          time.Now(),
	}
	if err := st.UpsertSSHKey(ctx, key); err != nil {
		t.Fatalf("UpsertSSHKey: %v", err)
	}
	// GetSSHKeyByFingerprint is not available; use ListSSHKeys scoped to hostID.
	result, err := st.ListSSHKeys(ctx, store.SSHKeySearchQuery{HostID: hostID, Limit: 1})
	if err != nil || result == nil || len(result.Keys) == 0 {
		t.Fatalf("ListSSHKeys: err=%v result=%v", err, result)
	}
	keyID = result.Keys[0].ID

	report := &model.AssetHealthReport{
		AssetType:         "ssh_key",
		AssetID:           keyID,
		Grade:             "B",
		Score:             70,
		RiskScore:         25,
		PQCStatus:         "safe",
		ScoredAt:          time.Now(),
		Compliance:        map[string]string{"fips_140_3": "partial"},
		RiskFactors:       map[string]int{"algo_weakness": 10},
		RuleEngineVersion: 2,
	}
	if err := st.SaveAssetHealthReport(ctx, report); err != nil {
		t.Fatalf("SaveAssetHealthReport: %v", err)
	}

	prov := &model.AssetProvenance{
		AssetType: "ssh_key",
		AssetID:   keyID,
		Source:    "test",
		HostID:    hostID,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}
	if err := st.RecordProvenance(ctx, prov); err != nil {
		t.Fatalf("RecordProvenance: %v", err)
	}
	return
}

func TestIntegration_GenerateForScope(t *testing.T) {
	st := newIntegrationStore(t)
	hostID, _ := seedHostAndSSHKey(t, st)
	ctx := context.Background()

	scope := &Scope{Name: "prod", HostIDs: []string{hostID}}
	gen := NewGenerator()
	bom, err := gen.Generate(ctx, st, scope)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if bom == nil {
		t.Fatal("BOM is nil")
	}
	if bom.Components == nil || len(*bom.Components) == 0 {
		t.Fatal("expected at least one component (the SSH key)")
	}
	if bom.SpecVersion != cdx.SpecVersion1_6 {
		t.Errorf("SpecVersion = %v, want 1.6", bom.SpecVersion)
	}
}

func TestIntegration_EventPushEndToEnd(t *testing.T) {
	st := newIntegrationStore(t)
	hostID, keyID := seedHostAndSSHKey(t, st)
	_ = keyID

	dir := t.TempDir()

	var bomReceived atomic.Bool
	fakeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bomReceived.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer fakeServer.Close()

	cfg := &config.CBOMConfig{
		Enabled:          true,
		OutputDir:        dir,
		PushInterval:     0,
		EventPushEnabled: true,
		MinEmitInterval:  50 * time.Millisecond,
		Scopes: []config.ScopeConfig{{
			Name:    "prod",
			HostIDs: []string{hostID},
			Sinks: []config.SinkConfig{
				{Type: "http", HTTP: &config.HTTPSinkConfig{URL: fakeServer.URL, Auth: "none"}, Timeout: 5 * time.Second},
				{Type: "file", File: &config.FileSinkConfig{PathTemplate: "{output_dir}/{scope}/{timestamp}.cdx.json"}},
			},
		}},
	}

	rt := NewRuntime(st, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	rt.Start(ctx)

	rt.NotifyAssetScored("ssh_key", keyID)
	time.Sleep(200 * time.Millisecond)

	if !bomReceived.Load() {
		t.Error("expected HTTP sink to receive a CBOM push")
	}
	scopeDir := filepath.Join(dir, "prod")
	entries, err := os.ReadDir(scopeDir)
	if err != nil || len(entries) == 0 {
		t.Errorf("expected file sink output in %s, err=%v entries=%v", scopeDir, err, entries)
	}
}

func TestIntegration_DownloadEndpoint(t *testing.T) {
	st := newIntegrationStore(t)
	hostID, _ := seedHostAndSSHKey(t, st)
	ctx := context.Background()

	scope := &Scope{Name: "test", HostIDs: []string{hostID}}
	gen := NewGenerator()
	bom, err := gen.Generate(ctx, st, scope)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if bom == nil || bom.Metadata == nil {
		t.Fatal("expected non-nil BOM with metadata")
	}
}

func TestIntegration_ScheduledPushBatch(t *testing.T) {
	st := newIntegrationStore(t)

	var pushCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pushCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	scopes := []config.ScopeConfig{
		{Name: "s1", Sinks: []config.SinkConfig{{Type: "http", HTTP: &config.HTTPSinkConfig{URL: srv.URL, Auth: "none"}, Timeout: 5 * time.Second}}},
		{Name: "s2", Sinks: []config.SinkConfig{{Type: "http", HTTP: &config.HTTPSinkConfig{URL: srv.URL, Auth: "none"}, Timeout: 5 * time.Second}}},
		{Name: "s3", Sinks: []config.SinkConfig{{Type: "http", HTTP: &config.HTTPSinkConfig{URL: srv.URL, Auth: "none"}, Timeout: 5 * time.Second}}},
	}

	cfg := &config.CBOMConfig{
		Enabled:          true,
		PushInterval:     50 * time.Millisecond,
		EventPushEnabled: false,
		Scopes:           scopes,
	}
	rt := NewRuntime(st, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	rt.Start(ctx)

	time.Sleep(150 * time.Millisecond)

	if got := pushCount.Load(); got < 3 {
		t.Errorf("expected at least 3 pushes (one per scope), got %d", got)
	}
}

func TestRuntime_EmitMultiSinkScope(t *testing.T) {
	st := newIntegrationStore(t)
	ctx := context.Background()

	// Seed one crypto_library asset with a scored health report, returns hostID.
	hostID := seedLibraryForIntegration(t, st)

	// --- Sink capture fixtures ---

	// HTTP capture (asset granularity → NDJSON)
	var httpBody bytes.Buffer
	var httpCT string
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpCT = r.Header.Get("Content-Type")
		io.Copy(&httpBody, r.Body) //nolint:errcheck
		w.WriteHeader(200)
	}))
	defer httpServer.Close()

	// Splunk HEC capture (finding granularity)
	var splunkBody bytes.Buffer
	splunkServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(&splunkBody, r.Body) //nolint:errcheck
		w.WriteHeader(200)
	}))
	defer splunkServer.Close()

	// Syslog UDP capture (asset granularity, rfc5424)
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	var syslogReceived []byte
	syslogDone := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		udpConn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
		n, _, _ := udpConn.ReadFromUDP(buf)
		syslogReceived = buf[:n]
		close(syslogDone)
	}()

	// File sink (cbom granularity)
	tmpDir := t.TempDir()

	cfg := &config.CBOMConfig{
		Enabled:   true,
		OutputDir: tmpDir,
		Scopes: []config.ScopeConfig{{
			Name:       "integration",
			HostIDs:    []string{hostID},
			AssetTypes: []string{"crypto_library"},
			Sinks: []config.SinkConfig{
				{
					Type: "file", Granularity: "cbom", Timeout: 2 * time.Second,
					File: &config.FileSinkConfig{PathTemplate: "{output_dir}/{scope}-{timestamp}.cbom.json"},
				},
				{
					Type: "http", Granularity: "asset", Timeout: 2 * time.Second,
					HTTP: &config.HTTPSinkConfig{URL: httpServer.URL, Auth: "none"},
				},
				{
					Type: "splunk", Granularity: "finding", Timeout: 2 * time.Second,
					Splunk: &config.SplunkSinkConfig{
						URL:      splunkServer.URL,
						TokenRef: "CIPHERFLAG_SPLUNK_TEST_TOKEN", // env var (unset is fine; fake server ignores auth)
						BatchSize: 10,
					},
				},
				{
					Type: "syslog", Granularity: "asset", Timeout: 2 * time.Second,
					Syslog: &config.SyslogSinkConfig{
						Protocol: "udp",
						Address:  udpConn.LocalAddr().String(),
						Format:   "rfc5424",
					},
				},
			},
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validate: %v", err)
	}

	rt := NewRuntime(st, cfg)
	// emitScope is unexported; test is in the same package (package cbom).
	rt.emitScope(ctx, &rt.scopes[0])

	// Verify CBOM file written
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Errorf("ReadDir tmpDir: %v", err)
	}
	if len(entries) == 0 {
		t.Error("no file written by FileSink")
	}

	// Verify HTTP NDJSON received
	if httpCT != "application/x-ndjson" {
		t.Errorf("HTTP content-type = %q, want application/x-ndjson", httpCT)
	}
	if httpBody.Len() == 0 {
		t.Error("HTTP server received no data")
	}

	// Verify Splunk HEC received at least one record
	if splunkBody.Len() == 0 {
		t.Error("Splunk server received no data")
	}

	// Verify syslog listener received at least one line
	<-syslogDone
	if len(syslogReceived) == 0 {
		t.Error("syslog listener received no data")
	}
}

// seedLibraryForIntegration writes one crypto_library + provenance + scored
// asset health report so ListScopeAssets returns a row for the
// "integration" scope defined in TestRuntime_EmitMultiSinkScope.
// Returns the hostID so callers can wire it into scope.HostIDs.
func seedLibraryForIntegration(t *testing.T, st *store.PostgresStore) (hostID string) {
	t.Helper()
	ctx := context.Background()

	// Host (UpsertHost populates host.ID via RETURNING when host.ID is "")
	host := &model.Host{
		CanonicalHostname: "integration-lib-host",
		OSFamily:          "linux",
		HostType:          "server",
	}
	if err := st.UpsertHost(ctx, host); err != nil {
		t.Fatalf("UpsertHost: %v", err)
	}
	hostID = host.ID

	// Library (UpsertCryptoLibrary uses host_id as part of unique key)
	lib := &model.CryptoLibrary{
		HostID:          hostID,
		LibraryName:     "openssl",
		Version:         "1.0.1c",
		PQCCapable:      false,
		Source:          "integration-test",
		DiscoveryStatus: "active",
	}
	if err := st.UpsertCryptoLibrary(ctx, lib); err != nil {
		t.Fatalf("UpsertCryptoLibrary: %v", err)
	}

	// Provenance linking the library to the host
	if err := st.RecordProvenance(ctx, &model.AssetProvenance{
		AssetType: "crypto_library",
		AssetID:   lib.ID,
		HostID:    hostID,
		Source:    "integration-test",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}); err != nil {
		t.Fatalf("RecordProvenance: %v", err)
	}

	// Asset health report — minimal, so the scope query matches
	if err := st.SaveAssetHealthReport(ctx, &model.AssetHealthReport{
		AssetType: "crypto_library",
		AssetID:   lib.ID,
		Grade:     "D",
		Score:     40,
		PQCStatus: "vulnerable",
		Findings: []model.HealthFinding{
			{
				RuleID: "LIB-001", Title: "Critical CVE",
				Severity: model.SeverityCritical, Category: model.CategoryAgility,
				Deduction: 50, ImmediateFail: true,
			},
		},
		Compliance:        map[string]string{},
		RiskScore:         90,
		RiskFactors:       map[string]int{"algo_weakness": 60, "quantum_urgency": 80},
		RuleEngineVersion: 4,
		ScoredAt:          time.Now().UTC(),
	}); err != nil {
		t.Fatalf("SaveAssetHealthReport: %v", err)
	}
	return hostID
}
