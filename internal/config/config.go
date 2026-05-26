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
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Server    ServerConfig    `toml:"server"`
	Storage   StorageConfig   `toml:"storage"`
	Analysis  AnalysisConfig  `toml:"analysis"`
	Sources   SourcesConfig   `toml:"sources"`
	Export    ExportConfig    `toml:"export"`
	PCAP      PCAPConfig      `toml:"pcap"`
	Attrition AttritionConfig `toml:"attrition"`
	Intake    IntakeConfig    `toml:"intake"`
	CBOM      CBOMConfig      `toml:"cbom"`
	AI        AIConfig        `toml:"ai"`
	Scanners  ScannersConfig  `toml:"scanners"`
}

// AIConfig mirrors the scanner's [ai] section. The API uses it for the
// pre-flight cost gate; it does not invoke the LLM directly.
type AIConfig struct {
	Enabled        bool    `toml:"enabled"`
	Provider       string  `toml:"provider"`
	Model          string  `toml:"model"`
	LicensePath    string  `toml:"license_path"`
	PerScanMaxUSD  float64 `toml:"per_scan_max_usd"`
	PerDayMaxUSD   float64 `toml:"per_day_max_usd"`
	PerMonthMaxUSD float64 `toml:"per_month_max_usd"`
}

type ServerConfig struct {
	Listen      string `toml:"listen"`
	FrontendURL string `toml:"frontend_url"`
}

type StorageConfig struct {
	PostgresURL string `toml:"postgres_url"`
	SQLitePath  string `toml:"sqlite_path"`
}

type AnalysisConfig struct {
	RecheckIntervalHours int            `toml:"recheck_interval_hours"`
	ExpiryWarningDays    []int          `toml:"expiry_warning_days"`
	ProtocolPolicy       ProtocolPolicy `toml:"protocol_policy"`

	// Layer 4.1 additions
	ScorerEnabled      bool `toml:"scorer_enabled"`
	RuleSweepBatchSize int  `toml:"rule_sweep_batch_size"`

	// Layer 8 briefing
	BriefingIntervalSeconds int `toml:"briefing_interval_seconds"`

	// SP-2 blast-radius engine
	// BlastRadiusRefreshIntervalMinutes — how often the sweeper
	// recomputes host_blast_radius scores. Default 15.
	BlastRadiusRefreshIntervalMinutes int `toml:"blast_radius_refresh_interval_minutes"`
	// BlastRadiusMaxDepth — BFS depth bound for blast-radius engine.
	// Default 3.
	BlastRadiusMaxDepth int `toml:"blast_radius_max_depth"`

	// PQCMigrationSnapshotIntervalHours — how often the PQC migration
	// snapshot runner ticks. 0 falls back to 24h. See L4-G spec.
	PQCMigrationSnapshotIntervalHours int `toml:"pqc_migration_snapshot_interval_hours"`

	// RankFormula selects the SP-3 rank-formula. Default "blast_radius"
	// since v1.20.0 (cutover); was "legacy" v1.17.0-v1.19.x. Validator
	// at the bottom of Load accepts only "legacy" or "blast_radius".
	RankFormula string `toml:"rank_formula"`
	// RankFormulaIsDefault is loader-populated; true iff RankFormula
	// was empty in TOML and got defaulted. Surfaced to the frontend
	// via the rank-review summary endpoint to gate the v1.20.0 cutover
	// banner. The `toml:"-"` tag keeps it out of operator-visible TOML.
	RankFormulaIsDefault bool `toml:"-"`

	// PKIEdgesEnabled gates pki_issued_by edges in the blast-radius BFS
	// graph (SP-1.6). When false (default), the sweeper and one-shot
	// recompute-blast-radius CLI exclude pki_issued_by from LoadAllEdges
	// so the scoring path is unaffected until the operator opts in.
	// Set to true once PKI edge extraction has been validated in production.
	PKIEdgesEnabled bool `toml:"pki_edges_enabled"`
	// PKITrustEdgesEnabled gates pki_trusted_by edges in the blast-radius BFS
	// graph (L4-F). Independent of PKIEdgesEnabled — operators can enable
	// either, both, or neither. Default false. Always-HighImpact when on,
	// no fanout cap (per spec).
	PKITrustEdgesEnabled bool `toml:"pki_trust_edges_enabled"`
}

// ScannersConfig configures scanner-side behavior shared across the
// truststore + certfiles + sshkeys scanners.
type ScannersConfig struct {
	// JVMKeystorePasswords is the password-ladder tried in order when
	// opening JKS bundles (truststore scanner's JVM cacerts path).
	// Default: ["changeit"] — universal JVM default. Add company-specific
	// passwords if your fleet has hardened the JVM cacerts password.
	JVMKeystorePasswords []string `toml:"jvm_keystore_passwords"`
}

type ProtocolPolicy struct {
	MinTLSVersion         string   `toml:"min_tls_version"`
	RequireForwardSecrecy bool     `toml:"require_forward_secrecy"`
	RequireAEAD           bool     `toml:"require_aead"`
	BannedCiphers         []string `toml:"banned_ciphers"`
}

type SourcesConfig struct {
	ZeekFile        ZeekFileSourceConfig        `toml:"zeek_file"`
	Corelight       CorelightSourceConfig       `toml:"corelight"`
	Velociraptor    VelociraptorSourceConfig    `toml:"velociraptor"`
	Netwrix         NetwrixSourceConfig         `toml:"netwrix"`
	Defender        DefenderSourceConfig        `toml:"defender"`
	SentinelOne     SentinelOneSourceConfig     `toml:"sentinelone"`
	Tanium          TaniumSourceConfig          `toml:"tanium"`
	Absolute        AbsoluteSourceConfig        `toml:"absolute"`
	ExternalSources ExternalSourcesSourceConfig `toml:"external_sources"`
}

type ZeekFileSourceConfig struct {
	Enabled             bool   `toml:"enabled"`
	LogDir              string `toml:"log_dir"`
	PollIntervalSeconds int    `toml:"poll_interval_seconds"`
	NetworkInterface    string `toml:"network_interface"`
}

type CorelightSourceConfig struct {
	Enabled  bool   `toml:"enabled"`
	APIURL   string `toml:"api_url"`
	APIToken string `toml:"api_token"`
}

// DefenderSourceConfig configures the Microsoft Defender for Endpoint adapter
// (library discovery via Advanced Hunting API).
type DefenderSourceConfig struct {
	Enabled             bool   `toml:"enabled"`
	TenantID            string `toml:"tenant_id"`
	ClientID            string `toml:"client_id"`
	ClientSecret        string `toml:"client_secret"`
	APIBaseURL          string `toml:"api_base_url"` // optional override (sovereign clouds)
	PollIntervalSeconds int    `toml:"poll_interval_seconds"`
	HTTPTimeoutSeconds  int    `toml:"http_timeout_seconds"`
}

// NetwrixSourceConfig configures the Netwrix Auditor adapter (AD CS change feed).
type NetwrixSourceConfig struct {
	Enabled             bool   `toml:"enabled"`
	BaseURL             string `toml:"base_url"`
	Username            string `toml:"username"`
	Password            string `toml:"password"`
	InsecureSkipTLS     bool   `toml:"insecure_skip_tls"`
	PollIntervalSeconds int    `toml:"poll_interval_seconds"`
	HTTPTimeoutSeconds  int    `toml:"http_timeout_seconds"`
}

// VelociraptorSourceConfig configures the Velociraptor adapter.
type VelociraptorSourceConfig struct {
	Enabled             bool     `toml:"enabled"`
	APIClientConfigPath string   `toml:"api_client_config_path"`
	LabelSelector       string   `toml:"label_selector"`
	PollIntervalSeconds int      `toml:"poll_interval_seconds"`
	HuntTimeoutSeconds  int      `toml:"hunt_timeout_seconds"`
	Artifacts           []string `toml:"artifacts"`
}

// SentinelOneSourceConfig configures the SentinelOne adapter.
// Two discovery modes run in parallel when enabled:
//   - App Inventory: polls installed-applications for crypto library presence.
//   - RSO: executes Layer 1 discovery scripts remotely and collects NDJSON output.
type SentinelOneSourceConfig struct {
	Enabled    bool   `toml:"enabled"`
	APIToken   string `toml:"api_token"`
	ConsoleURL string `toml:"console_url"` // e.g. https://mgmt.sentinelone.net

	AppInventory SentinelOneAppInventoryConfig `toml:"app_inventory"`
	RSO          SentinelOneRSOConfig          `toml:"rso"`

	HTTPTimeoutSeconds int `toml:"http_timeout_seconds"`
}

// SentinelOneAppInventoryConfig configures the installed-applications poller.
type SentinelOneAppInventoryConfig struct {
	Enabled             bool `toml:"enabled"`
	PollIntervalSeconds int  `toml:"poll_interval_seconds"`
}

// SentinelOneRSOConfig configures remote script execution.
// v1 only supports Trigger="scheduled" and Target="all". Any other value
// causes startup to fail fast.
type SentinelOneRSOConfig struct {
	Enabled             bool   `toml:"enabled"`
	Trigger             string `toml:"trigger"` // "scheduled"; "manual" deferred
	Target              string `toml:"target"`  // "all"; group/tag filters deferred
	PollIntervalSeconds int    `toml:"poll_interval_seconds"`

	CertScriptID        string `toml:"cert_script_id"`
	SSHKeysScriptID     string `toml:"ssh_keys_script_id"`
	LibrariesScriptID   string `toml:"libraries_script_id"`
	ConfigFilesScriptID string `toml:"config_files_script_id"`
	CertFilesScriptID   string `toml:"cert_files_script_id"`
}

// TaniumSourceConfig configures the Tanium adapter (Core-only, pull via GraphQL).
// The adapter queries four CipherFlag custom sensors plus the built-in
// Installed Applications sensor on each cycle and routes results through
// UnifiedIngester.
type TaniumSourceConfig struct {
	Enabled             bool   `toml:"enabled"`
	APIToken            string `toml:"api_token"`
	ConsoleURL          string `toml:"console_url"` // e.g. https://customer-api.cloud.tanium.com
	PollIntervalSeconds int    `toml:"poll_interval_seconds"`
	HTTPTimeoutSeconds  int    `toml:"http_timeout_seconds"`
	PageSize            int    `toml:"page_size"` // GraphQL "first" param; default 500
}

// AbsoluteSourceConfig configures the Absolute Software adapter.
// Two discovery modes run in parallel when enabled:
//   - Inventory: polls installed-applications for crypto library presence (all Absolute tiers).
//   - Reach: executes Layer 1 discovery scripts remotely and collects NDJSON output (Resilience tier only).
type AbsoluteSourceConfig struct {
	Enabled    bool   `toml:"enabled"`
	TokenID    string `toml:"token_id"`
	SecretKey  string `toml:"secret_key"`
	ConsoleURL string `toml:"console_url"` // e.g. https://api.absolute.com, https://api.us.absolute.com

	Inventory AbsoluteInventoryConfig `toml:"inventory"`
	Reach     AbsoluteReachConfig     `toml:"reach"`

	HTTPTimeoutSeconds int `toml:"http_timeout_seconds"`
}

// AbsoluteInventoryConfig configures the installed-applications poller.
type AbsoluteInventoryConfig struct {
	Enabled             bool `toml:"enabled"`
	PollIntervalSeconds int  `toml:"poll_interval_seconds"`
}

// AbsoluteReachConfig configures remote script execution via Absolute Reach.
// v1 only supports Trigger="scheduled" and Target="all"; any other value
// causes startup to fail fast.
type AbsoluteReachConfig struct {
	Enabled             bool   `toml:"enabled"`
	Trigger             string `toml:"trigger"` // "scheduled"; "manual" deferred
	Target              string `toml:"target"`  // "all"; group/tag filters deferred
	PollIntervalSeconds int    `toml:"poll_interval_seconds"`

	CertScriptID      string `toml:"cert_script_id"`
	SSHKeysScriptID   string `toml:"ssh_keys_script_id"`
	LibrariesScriptID string `toml:"libraries_script_id"`
	ConfigsScriptID   string `toml:"configs_script_id"`
}

// ExternalSourcesCTKindConfig is the shared shape for per-CT-kind
// enable gating in [sources.external_sources.ct_<kind>] blocks. Each
// kind is registered conditionally on Enabled at startup — operators
// can fully hide a kind (no UI surface, no scheduler dispatch) by
// flipping the flag and restarting cipherflag serve.
//
// Plan A registers ct_crtsh + ct_static. Plan B adds ct_certspotter +
// ct_multi (their fields land here too in that plan).
type ExternalSourcesCTKindConfig struct {
	Enabled bool `toml:"enabled"`
}

// ExternalSourcesSourceConfig controls the external_sources scheduler
// that polls registered kinds (aws_account in v1.10; ct_crtsh in
// v1.11, renamed from ct_domain by migration 049 in v1.25). When
// Enabled = false, the scheduler goroutine doesn't start; rows in the
// external_sources table are inert.
//
// TickIntervalSeconds defaults to 30 (matching the Phase A scheduler's
// internal default). ShutdownGraceSeconds defaults to 60 (matching
// the Phase A follow-up's ShutdownGrace default). Zero or negative
// values fall back to the defaults at Run() entry.
type ExternalSourcesSourceConfig struct {
	Enabled              bool                        `toml:"enabled"`
	TickIntervalSeconds  int                         `toml:"tick_interval_seconds"`
	ShutdownGraceSeconds int                         `toml:"shutdown_grace_seconds"`
	CtCrtsh              ExternalSourcesCTKindConfig `toml:"ct_crtsh"`
	// CtStatic gates the ct_static kind — Sunlight-format CT log consumer;
	// see internal/ingest/ct/static/. Shipped in Plan A (v1.25.0).
	CtStatic ExternalSourcesCTKindConfig `toml:"ct_static"`
}

type ExportConfig struct {
	Venafi VenafiExportConfig `toml:"venafi"`
}

type VenafiExportConfig struct {
	Enabled  bool   `toml:"enabled"`
	Platform string `toml:"platform"`
	// Cloud settings
	APIKey string `toml:"api_key"`
	Region string `toml:"region"`
	// TPP settings
	BaseURL      string `toml:"base_url"`
	ClientID     string `toml:"client_id"`
	RefreshToken string `toml:"refresh_token"`
	// Common
	Folder              string `toml:"folder"`
	PushIntervalMinutes int    `toml:"push_interval_minutes"`
}

type PCAPConfig struct {
	MaxFileSizeMB  int    `toml:"max_file_size_mb"`
	RetentionHours int    `toml:"retention_hours"`
	InputDir       string `toml:"input_dir"`
}

type AttritionConfig struct {
	CheckIntervalMinutes  int `toml:"check_interval_minutes"`
	CycleStaleThreshold   int `toml:"cycle_stale_threshold"`
	CycleRemovedThreshold int `toml:"cycle_removed_threshold"`
	NetworkStaleDays      int `toml:"network_stale_days"`
	NetworkRemovedDays    int `toml:"network_removed_days"`
}

// IntakeConfig holds intake-layer concerns that sit between sources and
// the UnifiedIngester's per-asset dedup path.
type IntakeConfig struct {
	Dedup IntakeDedupConfig `toml:"dedup"`
}

// IntakeDedupConfig configures the in-process observation cache that
// short-circuits redundant asset writes when third-party collectors
// re-emit identical observations.
//
// Safety: even if TTLSeconds is misconfigured, the effective TTL is
// hard-capped in code at half the shortest attrition threshold, so the
// cache can never cause a false stale/attrition trigger.
type IntakeDedupConfig struct {
	Enabled    bool `toml:"enabled"`
	TTLSeconds int  `toml:"ttl_seconds"`
	MaxEntries int  `toml:"max_entries"`
}

// ── Layer 5.1 CBOM types ─────────────────────────────────────────────────────

// CBOMSigningConfig controls opt-in JSF (JSON Signature Format) signing of
// emitted BOMs. When Enabled is false (default) the Generator skips signing
// entirely and bom.Signature is never populated.
//
// Signer must be "file" or "env":
//   - "file": private key is read from Path at startup (PEM, PRIVATE KEY block,
//     Ed25519 raw seed+public, 64 bytes).
//   - "env":  private key is read from the environment variable named by EnvVar;
//     accepts PEM ("-----BEGIN …") or raw base64-standard-encoded bytes.
//
// TOML section: [cbom.signing]
// Spec ref: docs/superpowers/plans/2026-05-16-l4-d-cbom-depth-pass.md §Task 13.
type CBOMSigningConfig struct {
	Enabled bool   `toml:"enabled"`
	Signer  string `toml:"signer"`  // "file" | "env"
	Path    string `toml:"path"`    // for signer=file: path to PEM private key
	EnvVar  string `toml:"env_var"` // for signer=env: env var name
}

// CBOMConfig holds all CBOM generation and emission settings.
type CBOMConfig struct {
	Enabled          bool              `toml:"enabled"`
	OutputDir        string            `toml:"output_dir"`
	PushInterval     time.Duration     `toml:"push_interval"`
	EventPushEnabled bool              `toml:"event_push_enabled"`
	MinEmitInterval  time.Duration     `toml:"min_emit_interval"`
	Signing          CBOMSigningConfig `toml:"signing"`
	Scopes           []ScopeConfig     `toml:"scopes"`
}

// ScopeConfig describes one named scope (a group of hosts for CBOM filtering).
type ScopeConfig struct {
	Name         string       `toml:"name"`
	HostPatterns []string     `toml:"host_patterns"`
	HostIDs      []string     `toml:"host_ids"`
	AssetTypes   []string     `toml:"asset_types"`
	MinRiskScore int          `toml:"min_risk_score"`
	Sinks        []SinkConfig `toml:"sinks"`
}

// SinkConfig describes one push destination for CBOM emission. Exactly one
// of the nested sub-config pointers must be set, matching Type.
type SinkConfig struct {
	Type        string        `toml:"type"`        // "http" | "file" | "s3" | "splunk" | "syslog"
	Granularity string        `toml:"granularity"` // "cbom" | "asset" | "finding" (auto-defaulted by Type)
	Timeout     time.Duration `toml:"timeout"`
	Retries     int           `toml:"retries"`

	HTTP   *HTTPSinkConfig   `toml:"http,omitempty"`
	File   *FileSinkConfig   `toml:"file,omitempty"`
	S3     *S3SinkConfig     `toml:"s3,omitempty"`
	Splunk *SplunkSinkConfig `toml:"splunk,omitempty"`
	Syslog *SyslogSinkConfig `toml:"syslog,omitempty"`
}

// EffectiveGranularity returns the configured granularity, or the type-based
// default if Granularity is unset. "cbom" for http/file/s3, "asset" for
// splunk/syslog.
func (s SinkConfig) EffectiveGranularity() string {
	if s.Granularity != "" {
		return s.Granularity
	}
	switch s.Type {
	case "splunk", "syslog":
		return "asset"
	default:
		return "cbom"
	}
}

var scopeNameRE = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// Validate checks that the CBOMConfig is self-consistent.
// Returns an error with a human-readable location (scope name, field).
func (c *CBOMConfig) Validate() error {
	seen := make(map[string]struct{}, len(c.Scopes))
	for i, s := range c.Scopes {
		if s.Name == "" {
			return fmt.Errorf("cbom: scope[%d]: name is required", i)
		}
		if !scopeNameRE.MatchString(s.Name) {
			return fmt.Errorf("cbom: scope %q: name must match [a-zA-Z0-9._-]+", s.Name)
		}
		if _, dup := seen[s.Name]; dup {
			return fmt.Errorf("cbom: scope %q: duplicate name", s.Name)
		}
		seen[s.Name] = struct{}{}
		for j, at := range s.AssetTypes {
			switch at {
			case "certificate", "ssh_key", "crypto_library", "crypto_protocol", "crypto_config":
			default:
				return fmt.Errorf("cbom: scope %q: asset_types[%d] %q not in allowlist", s.Name, j, at)
			}
		}
		for k, sink := range s.Sinks {
			loc := fmt.Sprintf("cbom: scope %q: sinks[%d]", s.Name, k)
			if err := validateSinkConfig(sink, loc); err != nil {
				return err
			}
		}
	}
	return nil
}

// applyCBOMDefaults sets safe zero-value defaults for CBOMConfig fields.
// Called from Load() so tests can call it directly.
func applyCBOMDefaults(cfg *Config) {
	if cfg.CBOM.PushInterval == 0 {
		cfg.CBOM.PushInterval = 24 * time.Hour
	}
	if cfg.CBOM.MinEmitInterval == 0 {
		cfg.CBOM.MinEmitInterval = 5 * time.Minute
	}
	for i := range cfg.CBOM.Scopes {
		for j := range cfg.CBOM.Scopes[i].Sinks {
			if cfg.CBOM.Scopes[i].Sinks[j].Timeout == 0 {
				cfg.CBOM.Scopes[i].Sinks[j].Timeout = 30 * time.Second
			}
			if cfg.CBOM.Scopes[i].Sinks[j].Retries == 0 {
				cfg.CBOM.Scopes[i].Sinks[j].Retries = 3
			}
		}
	}
}

// validateSinkConfig checks sink-level fields and delegates to the matching
// sub-config Validate(). Enforces exactly-one-sub-config-populated rule and
// granularity/Type compatibility.
func validateSinkConfig(s SinkConfig, location string) error {
	validTypes := map[string]bool{"http": true, "file": true, "s3": true, "splunk": true, "syslog": true}
	if !validTypes[s.Type] {
		return fmt.Errorf("%s: type %q must be \"http\", \"file\", \"s3\", \"splunk\", or \"syslog\"", location, s.Type)
	}

	populated := 0
	if s.HTTP != nil {
		populated++
	}
	if s.File != nil {
		populated++
	}
	if s.S3 != nil {
		populated++
	}
	if s.Splunk != nil {
		populated++
	}
	if s.Syslog != nil {
		populated++
	}
	if populated == 0 {
		return fmt.Errorf("%s: missing [cbom.scopes.sinks.%s] sub-config block", location, s.Type)
	}
	if populated > 1 {
		return fmt.Errorf("%s: only one sub-config block may be populated per sink", location)
	}

	switch s.Granularity {
	case "", "cbom", "asset", "finding":
	default:
		return fmt.Errorf("%s: granularity %q must be \"cbom\", \"asset\", or \"finding\"", location, s.Granularity)
	}

	// SIEM sinks cannot consume a CBOM payload.
	if (s.Type == "splunk" || s.Type == "syslog") && s.Granularity == "cbom" {
		return fmt.Errorf("%s: granularity=\"cbom\" is invalid for %s sinks; use \"asset\" or \"finding\"", location, s.Type)
	}

	switch s.Type {
	case "http":
		if s.HTTP == nil {
			return fmt.Errorf("%s: type=\"http\" but a different sub-config block is populated", location)
		}
		return s.HTTP.Validate(location + ".http")
	case "file":
		if s.File == nil {
			return fmt.Errorf("%s: type=\"file\" but a different sub-config block is populated", location)
		}
		return s.File.Validate(location + ".file")
	case "s3":
		if s.S3 == nil {
			return fmt.Errorf("%s: type=\"s3\" but a different sub-config block is populated", location)
		}
		return s.S3.Validate(location + ".s3")
	case "splunk":
		if s.Splunk == nil {
			return fmt.Errorf("%s: type=\"splunk\" but a different sub-config block is populated", location)
		}
		return s.Splunk.Validate(location + ".splunk")
	case "syslog":
		if s.Syslog == nil {
			return fmt.Errorf("%s: type=\"syslog\" but a different sub-config block is populated", location)
		}
		return s.Syslog.Validate(location + ".syslog")
	}
	return nil
}

// newDefaultConfig returns a Config pre-populated with fields whose Go
// zero-value is not the correct operational default. TOML decode will
// overwrite these fields when the operator explicitly sets them; fields
// absent from the TOML retain the defaults below.
//
// This pattern is required for inverted-default booleans (e.g. CT-kind
// enable flags default to true, but Go's bool zero-value is false).
func newDefaultConfig() Config {
	return Config{
		Sources: SourcesConfig{
			ExternalSources: ExternalSourcesSourceConfig{
				// CT-kind enable flags: every registered kind is active by
				// default; operators opt out by setting enabled = false in the
				// [sources.external_sources.ct_<kind>] block and restarting
				// cipherflag serve.
				CtCrtsh:  ExternalSourcesCTKindConfig{Enabled: true},
				CtStatic: ExternalSourcesCTKindConfig{Enabled: true},
			},
		},
	}
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := newDefaultConfig()
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return nil, err
	}
	// Defaults
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = "0.0.0.0:8443"
	}
	if cfg.Analysis.RecheckIntervalHours == 0 {
		cfg.Analysis.RecheckIntervalHours = 6
	}
	if cfg.Analysis.BlastRadiusRefreshIntervalMinutes == 0 {
		cfg.Analysis.BlastRadiusRefreshIntervalMinutes = 15
	}
	if cfg.Analysis.PQCMigrationSnapshotIntervalHours == 0 {
		cfg.Analysis.PQCMigrationSnapshotIntervalHours = 24
	}
	if cfg.Analysis.BlastRadiusMaxDepth == 0 {
		cfg.Analysis.BlastRadiusMaxDepth = 3
	}
	cfg.Analysis.RankFormulaIsDefault = (cfg.Analysis.RankFormula == "")
	if cfg.Analysis.RankFormula == "" {
		cfg.Analysis.RankFormula = "blast_radius"
	}
	if cfg.Analysis.RankFormula != "legacy" && cfg.Analysis.RankFormula != "blast_radius" {
		return nil, fmt.Errorf("config: analysis.rank_formula must be \"legacy\" or \"blast_radius\", got %q", cfg.Analysis.RankFormula)
	}
	if cfg.Sources.ZeekFile.PollIntervalSeconds == 0 {
		cfg.Sources.ZeekFile.PollIntervalSeconds = 30
	}
	if cfg.Sources.ZeekFile.LogDir == "" {
		cfg.Sources.ZeekFile.LogDir = "/var/log/zeek/current"
	}
	if cfg.Sources.Velociraptor.Enabled && len(cfg.Sources.Velociraptor.Artifacts) == 0 {
		cfg.Sources.Velociraptor.Artifacts = []string{
			"CipherFlag.Crypto.Certificates.Native",
			"CipherFlag.Crypto.Certificates.Containers",
			"CipherFlag.Crypto.SSHKeys",
			"CipherFlag.Crypto.Libraries",
			"CipherFlag.Crypto.Configs",
		}
	}
	if cfg.Sources.SentinelOne.Enabled {
		if cfg.Sources.SentinelOne.AppInventory.PollIntervalSeconds == 0 {
			cfg.Sources.SentinelOne.AppInventory.PollIntervalSeconds = 3600 // 1h
		}
		if cfg.Sources.SentinelOne.RSO.PollIntervalSeconds == 0 {
			cfg.Sources.SentinelOne.RSO.PollIntervalSeconds = 86400 // 24h
		}
		if cfg.Sources.SentinelOne.RSO.Trigger == "" {
			cfg.Sources.SentinelOne.RSO.Trigger = "scheduled"
		}
		if cfg.Sources.SentinelOne.RSO.Target == "" {
			cfg.Sources.SentinelOne.RSO.Target = "all"
		}
	}
	if cfg.Sources.Tanium.Enabled {
		if cfg.Sources.Tanium.PollIntervalSeconds == 0 {
			cfg.Sources.Tanium.PollIntervalSeconds = 3600 // 1h
		}
		if cfg.Sources.Tanium.PageSize == 0 {
			cfg.Sources.Tanium.PageSize = 500
		}
	}
	if cfg.Sources.Absolute.Enabled {
		if cfg.Sources.Absolute.Inventory.PollIntervalSeconds == 0 {
			cfg.Sources.Absolute.Inventory.PollIntervalSeconds = 3600 // 1h
		}
		if cfg.Sources.Absolute.Reach.PollIntervalSeconds == 0 {
			cfg.Sources.Absolute.Reach.PollIntervalSeconds = 86400 // 24h
		}
		if cfg.Sources.Absolute.Reach.Trigger == "" {
			cfg.Sources.Absolute.Reach.Trigger = "scheduled"
		}
		if cfg.Sources.Absolute.Reach.Target == "" {
			cfg.Sources.Absolute.Reach.Target = "all"
		}
	}
	if cfg.Export.Venafi.PushIntervalMinutes == 0 {
		cfg.Export.Venafi.PushIntervalMinutes = 60
	}
	if cfg.Export.Venafi.Platform == "" {
		cfg.Export.Venafi.Platform = "cloud"
	}
	if cfg.Export.Venafi.Region == "" {
		cfg.Export.Venafi.Region = "us"
	}
	if cfg.Export.Venafi.Folder == "" {
		cfg.Export.Venafi.Folder = `\VED\Policy\Discovered\CipherFlag`
	}
	if cfg.PCAP.MaxFileSizeMB == 0 {
		cfg.PCAP.MaxFileSizeMB = 500
	}
	if cfg.PCAP.RetentionHours == 0 {
		cfg.PCAP.RetentionHours = 24
	}
	if cfg.PCAP.InputDir == "" {
		cfg.PCAP.InputDir = "/pcap-input"
	}
	if cfg.Attrition.CheckIntervalMinutes == 0 {
		cfg.Attrition.CheckIntervalMinutes = 60
	}
	if cfg.Attrition.CycleStaleThreshold == 0 {
		cfg.Attrition.CycleStaleThreshold = 3
	}
	if cfg.Attrition.CycleRemovedThreshold == 0 {
		cfg.Attrition.CycleRemovedThreshold = 7
	}
	if cfg.Attrition.NetworkStaleDays == 0 {
		cfg.Attrition.NetworkStaleDays = 7
	}
	if cfg.Attrition.NetworkRemovedDays == 0 {
		cfg.Attrition.NetworkRemovedDays = 30
	}
	// Intake dedup defaults. Operators opt in via [intake.dedup] enabled = true.
	// Conservative default: disabled (zero-risk rollout — Noop cache is
	// byte-identical to pre-cache behaviour).
	if cfg.Intake.Dedup.TTLSeconds == 0 {
		cfg.Intake.Dedup.TTLSeconds = 3600 // 1h default when enabled
	}
	if cfg.Intake.Dedup.MaxEntries == 0 {
		cfg.Intake.Dedup.MaxEntries = 500000 // ~64MB ceiling when enabled
	}
	if cfg.Intake.Dedup.MaxEntries < 1000 {
		cfg.Intake.Dedup.MaxEntries = 1000
	}
	// Layer 4.1 scorer defaults. ScorerEnabled defaults to false (zero
	// value). RuleSweepBatchSize defaults to 1000.
	if cfg.Analysis.RuleSweepBatchSize == 0 {
		cfg.Analysis.RuleSweepBatchSize = 1000
	}
	// Layer 8 briefing interval default: 60s.
	if cfg.Analysis.BriefingIntervalSeconds == 0 {
		cfg.Analysis.BriefingIntervalSeconds = 60
	}
	// Layer 5.1 CBOM defaults and validation.
	applyCBOMDefaults(&cfg)
	if cfg.CBOM.Enabled {
		if err := cfg.CBOM.Validate(); err != nil {
			return nil, err
		}
	}
	// Layer 6.1d-3 AI defaults (per spec §13 enrichment-mode).
	if cfg.AI.Provider == "" {
		cfg.AI.Provider = "anthropic"
	}
	if cfg.AI.Model == "" {
		cfg.AI.Model = "claude-sonnet-4-6"
	}
	if cfg.AI.PerScanMaxUSD <= 0 {
		cfg.AI.PerScanMaxUSD = 20.0
	}
	if cfg.AI.PerDayMaxUSD <= 0 {
		cfg.AI.PerDayMaxUSD = 100.0
	}
	if cfg.AI.PerMonthMaxUSD <= 0 {
		cfg.AI.PerMonthMaxUSD = 1000.0
	}
	// L4-F scanner defaults. PKITrustEdgesEnabled defaults to false (Go zero
	// value); no explicit default needed.
	if len(cfg.Scanners.JVMKeystorePasswords) == 0 {
		cfg.Scanners.JVMKeystorePasswords = []string{"changeit"}
	}
	return &cfg, nil
}

// Save writes the config back to a TOML file.
func Save(path string, cfg *Config) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	encoder := toml.NewEncoder(f)
	return encoder.Encode(cfg)
}
