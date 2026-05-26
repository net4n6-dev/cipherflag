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

// Package config loads the scanner-specific TOML config from scanner.toml.
//
// Note: spec §9 showed YAML; this impl uses TOML to match the existing
// cipherflag.toml convention (BurntSushi/toml is already in go.mod).
package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Storage   StorageConfig   `toml:"storage"`
	Scanner   ScannerConfig   `toml:"scanner"`
	Git       GitConfig       `toml:"git"`
	Cache     CacheConfig     `toml:"cache"`
	Detectors DetectorsConfig `toml:"detectors"`
	AI        AIConfig        `toml:"ai"`
	Metrics   MetricsConfig   `toml:"metrics"`
	Registry  RegistryConfig  `toml:"registry"`
}

type RegistryConfig struct {
	DefaultPlatform      string `toml:"default_platform"`
	MaxConcurrentFetches int    `toml:"max_concurrent_fetches"`
	MaxReferrers         int    `toml:"max_referrers"`
	MaxReferrerBytes     int64  `toml:"max_referrer_bytes"`
	WorkDirSubpath       string `toml:"work_dir_subpath"` // joined under Scanner.CloneDir

	// Credential-helper toggles.
	EnableECR      bool `toml:"enable_ecr"`
	EnableACR      bool `toml:"enable_acr"`
	EnableGCR      bool `toml:"enable_gcr"`
	EnableK8schain bool `toml:"enable_k8schain"`
}

type MetricsConfig struct {
	Enabled bool   `toml:"enabled"`
	Listen  string `toml:"listen"`
}

type AIConfig struct {
	Enabled        bool    `toml:"enabled"`
	Provider       string  `toml:"provider"`
	APIKeyEnv      string  `toml:"api_key_env"`
	Model          string  `toml:"model"`
	LicensePath    string  `toml:"license_path"`
	PerScanMaxUSD  float64 `toml:"per_scan_max_usd"`
	PerDayMaxUSD   float64 `toml:"per_day_max_usd"`
	PerMonthMaxUSD float64 `toml:"per_month_max_usd"`
	HTTPTimeoutSec int     `toml:"http_timeout_seconds"`
}

type DetectorsConfig struct {
	B1 B1Config `toml:"b1"`
}

type B1Config struct {
	// CommonPasswords extends the built-in defaults in
	// internal/scanner/detect/b1.DefaultCommonPasswords. The built-ins are
	// always tried first; this list is appended.
	CommonPasswords []string `toml:"common_passwords"`
	IncludeZIP      bool     `toml:"include_zip_recursion"`
}

type StorageConfig struct {
	PostgresURL string `toml:"postgres_url"`
}

type ScannerConfig struct {
	Workers             int    `toml:"workers"`
	CloneDir            string `toml:"clone_dir"`
	MaxBlobSizeBytes    int64  `toml:"max_blob_size_bytes"`
	BlobScanConcurrency int    `toml:"blob_scan_concurrency"`
	CloneTimeoutSeconds int    `toml:"clone_timeout_seconds"`
	ScanTimeoutSeconds  int    `toml:"scan_timeout_seconds"`
	WorkerIDPrefix      string `toml:"worker_id_prefix"`
}

type GitConfig struct {
	PartialCloneFilter string `toml:"partial_clone_filter"`
	FetchDepth         int    `toml:"fetch_depth"`
	CheckoutMode       string `toml:"checkout_mode"` // "sparse" | "full"
}

type CacheConfig struct {
	MaxRows  int    `toml:"max_rows"`
	Eviction string `toml:"eviction"` // "lru" only in v1
}

// Load parses a scanner.toml file and applies defaults for unspecified
// fields. Returns an error on unknown checkout_mode or missing postgres_url.
func Load(path string) (*Config, error) {
	cfg := &Config{}
	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return nil, fmt.Errorf("decode scanner.toml: %w", err)
	}
	applyDefaults(cfg)
	if err := validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func applyDefaults(c *Config) {
	if c.Scanner.Workers <= 0 {
		c.Scanner.Workers = 2
	}
	if c.Scanner.CloneDir == "" {
		c.Scanner.CloneDir = "/var/cache/cipherflag/scanner/clones"
	}
	if c.Scanner.MaxBlobSizeBytes <= 0 {
		c.Scanner.MaxBlobSizeBytes = 10 * 1024 * 1024
	}
	if c.Scanner.BlobScanConcurrency <= 0 {
		c.Scanner.BlobScanConcurrency = 8
	}
	if c.Scanner.CloneTimeoutSeconds <= 0 {
		c.Scanner.CloneTimeoutSeconds = 600
	}
	if c.Scanner.ScanTimeoutSeconds <= 0 {
		c.Scanner.ScanTimeoutSeconds = 3600
	}
	if c.Scanner.WorkerIDPrefix == "" {
		h, _ := os.Hostname()
		if h == "" {
			h = "scanner"
		}
		c.Scanner.WorkerIDPrefix = h
	}
	if c.Git.PartialCloneFilter == "" {
		c.Git.PartialCloneFilter = "blob:none"
	}
	if c.Git.CheckoutMode == "" {
		c.Git.CheckoutMode = "sparse"
	}
	if c.Cache.MaxRows <= 0 {
		c.Cache.MaxRows = 1_000_000
	}
	if c.Cache.Eviction == "" {
		c.Cache.Eviction = "lru"
	}
	if c.AI.Provider == "" {
		c.AI.Provider = "anthropic"
	}
	if c.AI.Model == "" {
		c.AI.Model = "claude-sonnet-4-6"
	}
	if c.AI.HTTPTimeoutSec <= 0 {
		c.AI.HTTPTimeoutSec = 30
	}
	// Per-mode budget defaults from spec §13 (enrichment-mode).
	if c.AI.PerScanMaxUSD <= 0 {
		c.AI.PerScanMaxUSD = 20.0
	}
	if c.AI.PerDayMaxUSD <= 0 {
		c.AI.PerDayMaxUSD = 100.0
	}
	if c.AI.PerMonthMaxUSD <= 0 {
		c.AI.PerMonthMaxUSD = 1000.0
	}
	if c.Metrics.Enabled && c.Metrics.Listen == "" {
		c.Metrics.Listen = "127.0.0.1:9090"
	}
	if c.Registry.DefaultPlatform == "" {
		c.Registry.DefaultPlatform = "linux/amd64"
	}
	if c.Registry.MaxConcurrentFetches <= 0 {
		c.Registry.MaxConcurrentFetches = 4
	}
	if c.Registry.MaxReferrers <= 0 {
		c.Registry.MaxReferrers = 10
	}
	if c.Registry.MaxReferrerBytes <= 0 {
		c.Registry.MaxReferrerBytes = 1 * 1024 * 1024
	}
	if c.Registry.WorkDirSubpath == "" {
		c.Registry.WorkDirSubpath = "oci-work"
	}
}

func validate(c *Config) error {
	if c.Storage.PostgresURL == "" {
		return fmt.Errorf("storage.postgres_url is required")
	}
	switch c.Git.CheckoutMode {
	case "sparse", "full":
	default:
		return fmt.Errorf("git.checkout_mode must be 'sparse' or 'full' (got %q)", c.Git.CheckoutMode)
	}
	if c.AI.Enabled && c.AI.Provider != "anthropic" {
		return fmt.Errorf("ai.provider %q not supported in v1 (anthropic only)", c.AI.Provider)
	}
	if c.AI.Enabled && c.AI.APIKeyEnv == "" {
		return fmt.Errorf("ai.enabled=true but ai.api_key_env is empty")
	}
	return nil
}
