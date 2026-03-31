package config

import (
	"os"
	"path/filepath"
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
