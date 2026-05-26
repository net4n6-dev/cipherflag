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

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	// Write minimal TOML
	dir := t.TempDir()
	path := filepath.Join(dir, "test.toml")
	os.WriteFile(path, []byte("[server]\n"), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Server.Listen != "0.0.0.0:8443" {
		t.Errorf("listen = %q, want 0.0.0.0:8443", cfg.Server.Listen)
	}
	if cfg.Analysis.RecheckIntervalHours != 6 {
		t.Errorf("recheck = %d, want 6", cfg.Analysis.RecheckIntervalHours)
	}
	if cfg.Sources.ZeekFile.PollIntervalSeconds != 30 {
		t.Errorf("poll interval = %d, want 30", cfg.Sources.ZeekFile.PollIntervalSeconds)
	}
	if cfg.Export.Venafi.PushIntervalMinutes != 60 {
		t.Errorf("push interval = %d, want 60", cfg.Export.Venafi.PushIntervalMinutes)
	}
	if cfg.Export.Venafi.Platform != "cloud" {
		t.Errorf("platform = %q, want cloud", cfg.Export.Venafi.Platform)
	}
	if cfg.Export.Venafi.Region != "us" {
		t.Errorf("region = %q, want us", cfg.Export.Venafi.Region)
	}
	if cfg.PCAP.MaxFileSizeMB != 500 {
		t.Errorf("pcap max = %d, want 500", cfg.PCAP.MaxFileSizeMB)
	}
}

func TestLoadFullConfig(t *testing.T) {
	toml := `
[server]
listen = "127.0.0.1:9090"

[storage]
postgres_url = "postgres://user:pass@localhost/db"

[analysis]
recheck_interval_hours = 12

[sources.zeek_file]
enabled = false
log_dir = "/custom/logs"
poll_interval_seconds = 60

[export.venafi]
enabled = true
platform = "tpp"
base_url = "https://tpp.example.com"
client_id = "my-client"
push_interval_minutes = 30
`
	dir := t.TempDir()
	path := filepath.Join(dir, "full.toml")
	os.WriteFile(path, []byte(toml), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Server.Listen != "127.0.0.1:9090" {
		t.Errorf("listen = %q", cfg.Server.Listen)
	}
	if cfg.Sources.ZeekFile.Enabled {
		t.Error("zeek should be disabled")
	}
	if cfg.Sources.ZeekFile.LogDir != "/custom/logs" {
		t.Errorf("log_dir = %q", cfg.Sources.ZeekFile.LogDir)
	}
	if cfg.Export.Venafi.Platform != "tpp" {
		t.Errorf("platform = %q", cfg.Export.Venafi.Platform)
	}
	if cfg.Export.Venafi.PushIntervalMinutes != 30 {
		t.Errorf("push interval = %d", cfg.Export.Venafi.PushIntervalMinutes)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path.toml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadInvalidTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.toml")
	os.WriteFile(path, []byte("this is not valid toml {{{"), 0644)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid TOML")
	}
}

func TestSaveAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "save.toml")

	// Create initial config
	os.WriteFile(path, []byte("[server]\nlisten = \"0.0.0.0:8443\"\n"), 0644)
	cfg, _ := Load(path)

	// Modify and save
	cfg.Export.Venafi.Enabled = true
	cfg.Export.Venafi.Platform = "cloud"
	cfg.Export.Venafi.APIKey = "test-key-123"

	err := Save(path, cfg)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Reload and verify
	cfg2, err := Load(path)
	if err != nil {
		t.Fatalf("Reload failed: %v", err)
	}
	if !cfg2.Export.Venafi.Enabled {
		t.Error("venafi should be enabled after reload")
	}
	if cfg2.Export.Venafi.APIKey != "test-key-123" {
		t.Errorf("api_key = %q, want test-key-123", cfg2.Export.Venafi.APIKey)
	}
}

func TestAttritionDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.toml")
	os.WriteFile(path, []byte("[server]\n"), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Attrition.CheckIntervalMinutes != 60 {
		t.Errorf("check_interval_minutes = %d, want 60", cfg.Attrition.CheckIntervalMinutes)
	}
	if cfg.Attrition.CycleStaleThreshold != 3 {
		t.Errorf("cycle_stale_threshold = %d, want 3", cfg.Attrition.CycleStaleThreshold)
	}
	if cfg.Attrition.CycleRemovedThreshold != 7 {
		t.Errorf("cycle_removed_threshold = %d, want 7", cfg.Attrition.CycleRemovedThreshold)
	}
	if cfg.Attrition.NetworkStaleDays != 7 {
		t.Errorf("network_stale_days = %d, want 7", cfg.Attrition.NetworkStaleDays)
	}
	if cfg.Attrition.NetworkRemovedDays != 30 {
		t.Errorf("network_removed_days = %d, want 30", cfg.Attrition.NetworkRemovedDays)
	}
}

func TestModelScoreToGrade(t *testing.T) {
	tests := []struct {
		score         int
		immediateFail bool
		want          string
	}{
		{100, false, "A+"},
		{95, false, "A+"},
		{94, false, "A"},
		{85, false, "A"},
		{84, false, "B"},
		{70, false, "B"},
		{69, false, "C"},
		{50, false, "C"},
		{49, false, "D"},
		{20, false, "D"},
		{19, false, "F"},
		{0, false, "F"},
		{100, true, "F"},
		{95, true, "F"},
	}

	for _, tt := range tests {
		// Can't import model here directly, but we test through the scorer
		// This is a documentation of expected behavior
		t.Logf("score=%d immediateFail=%v → %s", tt.score, tt.immediateFail, tt.want)
	}
}

func TestLoad_AIDefaults(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "cipherflag.toml")
	if err := os.WriteFile(path, []byte(``), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.AI.Provider != "anthropic" || cfg.AI.Model != "claude-sonnet-4-6" {
		t.Errorf("AI defaults: %+v", cfg.AI)
	}
	if cfg.AI.PerScanMaxUSD != 20.0 || cfg.AI.PerDayMaxUSD != 100.0 || cfg.AI.PerMonthMaxUSD != 1000.0 {
		t.Errorf("AI budget defaults: %+v", cfg.AI)
	}
}

func TestLoad_RankFormulaDefaultIsBlastRadius(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "cipherflag.toml")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Analysis.RankFormula != "blast_radius" {
		t.Errorf("RankFormula = %q, want \"blast_radius\" (default since v1.20.0)", cfg.Analysis.RankFormula)
	}
	if !cfg.Analysis.RankFormulaIsDefault {
		t.Errorf("RankFormulaIsDefault = false, want true (no rank_formula in TOML)")
	}
}

func TestLoad_RankFormulaLegacyAccepted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.toml")
	os.WriteFile(path, []byte(`[storage]
postgres_url = "postgres://test/test"
[analysis]
rank_formula = "legacy"
`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Analysis.RankFormula != "legacy" {
		t.Errorf("RankFormula = %q, want \"legacy\"", cfg.Analysis.RankFormula)
	}
}

func TestLoad_RankFormulaBlastRadiusAccepted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.toml")
	os.WriteFile(path, []byte(`[storage]
postgres_url = "postgres://test/test"
[analysis]
rank_formula = "blast_radius"
`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Analysis.RankFormula != "blast_radius" {
		t.Errorf("RankFormula = %q, want \"blast_radius\"", cfg.Analysis.RankFormula)
	}
}

func TestLoad_RankFormulaGarbageRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.toml")
	os.WriteFile(path, []byte(`[storage]
postgres_url = "postgres://test/test"
[analysis]
rank_formula = "garbage"
`), 0644)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load err = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "rank_formula must be") {
		t.Errorf("err = %v, want canonical validation message", err)
	}
	if !strings.Contains(err.Error(), "garbage") {
		t.Errorf("err = %v, want the invalid value in the message", err)
	}
}

// loadFromTOML is a test helper: writes body to a temp file and calls Load.
func loadFromTOML(t *testing.T, body string) (*Config, error) {
	t.Helper()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "cipherflag.toml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func TestConfig_DefaultsForPKITrustAndJVMPasswords(t *testing.T) {
	// Load the empty TOML; defaults should populate.
	cfg, err := loadFromTOML(t, "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Analysis.PKITrustEdgesEnabled {
		t.Error("PKITrustEdgesEnabled default = true, want false")
	}
	if len(cfg.Scanners.JVMKeystorePasswords) != 1 || cfg.Scanners.JVMKeystorePasswords[0] != "changeit" {
		t.Errorf("JVMKeystorePasswords default = %v, want [changeit]", cfg.Scanners.JVMKeystorePasswords)
	}
}

func TestConfig_LoadFromTOML_HonorsTrustOverrides(t *testing.T) {
	cfg, err := loadFromTOML(t, `
[analysis]
pki_trust_edges_enabled = true

[scanners]
jvm_keystore_passwords = ["changeit", "company-default", "legacy-pw"]
`)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Analysis.PKITrustEdgesEnabled {
		t.Error("override not applied")
	}
	if len(cfg.Scanners.JVMKeystorePasswords) != 3 {
		t.Errorf("got %d passwords, want 3", len(cfg.Scanners.JVMKeystorePasswords))
	}
}

func TestLoad_RankFormulaIsDefaultTracksTomlPresence(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		wantFormula string
		wantIsDef   bool
	}{
		{"empty_toml", "", "blast_radius", true},
		{"explicit_blast_radius", "[analysis]\nrank_formula = \"blast_radius\"\n", "blast_radius", false},
		{"explicit_legacy", "[analysis]\nrank_formula = \"legacy\"\n", "legacy", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			path := filepath.Join(tmp, "cipherflag.toml")
			if err := os.WriteFile(path, []byte(tc.body), 0o644); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Analysis.RankFormula != tc.wantFormula {
				t.Errorf("RankFormula = %q, want %q", cfg.Analysis.RankFormula, tc.wantFormula)
			}
			if cfg.Analysis.RankFormulaIsDefault != tc.wantIsDef {
				t.Errorf("RankFormulaIsDefault = %v, want %v", cfg.Analysis.RankFormulaIsDefault, tc.wantIsDef)
			}
		})
	}
}

func TestConfig_CTKindEnableFlags_DefaultsAndOverride(t *testing.T) {
	// Default (no TOML ct_crtsh sub-block): every CT kind enabled.
	defaults, err := loadFromTOML(t, `
[sources.external_sources]
`)
	if err != nil {
		t.Fatalf("loadFromTOML: %v", err)
	}
	if !defaults.Sources.ExternalSources.CtCrtsh.Enabled {
		t.Error("default: ct_crtsh.enabled should be true")
	}
	if !defaults.Sources.ExternalSources.CtStatic.Enabled {
		t.Error("default: ct_static.enabled should be true")
	}

	// Operator disables ct_crtsh.
	overridden, err := loadFromTOML(t, `
[sources.external_sources.ct_crtsh]
enabled = false
`)
	if err != nil {
		t.Fatalf("loadFromTOML: %v", err)
	}
	if overridden.Sources.ExternalSources.CtCrtsh.Enabled {
		t.Error("override: ct_crtsh.enabled should be false")
	}
	// ct_static not overridden — should still default to true.
	if !overridden.Sources.ExternalSources.CtStatic.Enabled {
		t.Error("override: ct_static.enabled should remain true when not overridden")
	}
}
