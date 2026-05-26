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
	"testing"
)

const sampleTOML = `
[storage]
postgres_url = "postgres://x@h/d"

[scanner]
workers = 4
clone_dir = "/var/cache/scan"
max_blob_size_bytes = 10485760
blob_scan_concurrency = 8
clone_timeout_seconds = 600
scan_timeout_seconds = 3600
worker_id_prefix = "acme-prod"

[git]
partial_clone_filter = "blob:none"
fetch_depth = 0
checkout_mode = "sparse"

[cache]
max_rows = 1000000
eviction = "lru"
`

func TestLoad_FullSample(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scanner.toml")
	if err := os.WriteFile(path, []byte(sampleTOML), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Scanner.Workers != 4 {
		t.Errorf("workers: want 4 got %d", cfg.Scanner.Workers)
	}
	if cfg.Git.PartialCloneFilter != "blob:none" {
		t.Errorf("git filter: %q", cfg.Git.PartialCloneFilter)
	}
	if cfg.Cache.MaxRows != 1_000_000 {
		t.Errorf("cache max_rows: %d", cfg.Cache.MaxRows)
	}
	if cfg.Storage.PostgresURL == "" {
		t.Error("postgres_url empty")
	}
}

func TestLoad_AppliesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scanner.toml")
	if err := os.WriteFile(path, []byte(`
[storage]
postgres_url = "postgres://x@h/d"
`), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Scanner.Workers != 2 {
		t.Errorf("default workers want 2, got %d", cfg.Scanner.Workers)
	}
	if cfg.Scanner.BlobScanConcurrency != 8 {
		t.Errorf("default blob_scan_concurrency want 8, got %d", cfg.Scanner.BlobScanConcurrency)
	}
	if cfg.Scanner.MaxBlobSizeBytes != 10*1024*1024 {
		t.Errorf("default max_blob_size_bytes want 10MiB, got %d", cfg.Scanner.MaxBlobSizeBytes)
	}
	if cfg.Git.PartialCloneFilter != "blob:none" {
		t.Errorf("default partial_clone_filter: %q", cfg.Git.PartialCloneFilter)
	}
	if cfg.Cache.MaxRows != 1_000_000 {
		t.Errorf("default max_rows: %d", cfg.Cache.MaxRows)
	}
}

func TestLoad_DetectorsB1(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scanner.toml")
	_ = os.WriteFile(path, []byte(`
[storage]
postgres_url = "postgres://x@h/d"
[detectors.b1]
common_passwords = ["corp-password", "acme-default"]
include_zip_recursion = true
`), 0644)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Detectors.B1.CommonPasswords) != 2 {
		t.Errorf("want 2 passwords, got %d", len(cfg.Detectors.B1.CommonPasswords))
	}
	if !cfg.Detectors.B1.IncludeZIP {
		t.Error("include_zip_recursion not parsed")
	}
}

func TestLoad_RejectsInvalidCheckoutMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scanner.toml")
	_ = os.WriteFile(path, []byte(`
[storage]
postgres_url = "postgres://x@h/d"
[git]
checkout_mode = "bogus"
`), 0644)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error on invalid checkout_mode")
	}
}

func TestLoad_AIDefaults(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "scanner.toml")
	if err := os.WriteFile(path, []byte(`
[storage]
postgres_url = "postgres://u:p@h/db"
`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.AI.Enabled {
		t.Error("ai.enabled should default to false")
	}
	if cfg.AI.Provider != "anthropic" {
		t.Errorf("provider default: %q", cfg.AI.Provider)
	}
	if cfg.AI.Model != "claude-sonnet-4-6" {
		t.Errorf("model default: %q", cfg.AI.Model)
	}
	if cfg.AI.PerScanMaxUSD != 20.0 || cfg.AI.PerDayMaxUSD != 100.0 || cfg.AI.PerMonthMaxUSD != 1000.0 {
		t.Errorf("budget defaults: %+v", cfg.AI)
	}
}

func TestLoad_AIValidation_RejectsUnknownProvider(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "scanner.toml")
	if err := os.WriteFile(path, []byte(`
[storage]
postgres_url = "postgres://u:p@h/db"
[ai]
enabled = true
provider = "bedrock"
api_key_env = "X"
`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error on unknown provider")
	}
}

func TestLoad_AIValidation_RequiresAPIKeyEnvWhenEnabled(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "scanner.toml")
	if err := os.WriteFile(path, []byte(`
[storage]
postgres_url = "postgres://u:p@h/db"
[ai]
enabled = true
provider = "anthropic"
`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error when api_key_env empty + enabled")
	}
}

func TestLoad_RegistryDefaults(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "scanner.toml")
	if err := os.WriteFile(path, []byte(`
[storage]
postgres_url = "postgres://u:p@h/db"
`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Registry.DefaultPlatform != "linux/amd64" {
		t.Errorf("default_platform: %q", cfg.Registry.DefaultPlatform)
	}
	if cfg.Registry.MaxConcurrentFetches != 4 {
		t.Errorf("max_concurrent_fetches: %d", cfg.Registry.MaxConcurrentFetches)
	}
	if cfg.Registry.MaxReferrers != 10 {
		t.Errorf("max_referrers: %d", cfg.Registry.MaxReferrers)
	}
	if cfg.Registry.MaxReferrerBytes != 1*1024*1024 {
		t.Errorf("max_referrer_bytes: %d", cfg.Registry.MaxReferrerBytes)
	}
	if cfg.Registry.EnableECR {
		t.Error("ecr helper should default to off")
	}
}
