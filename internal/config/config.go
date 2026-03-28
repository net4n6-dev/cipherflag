package config

import (
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Server   ServerConfig   `toml:"server"`
	Storage  StorageConfig  `toml:"storage"`
	Analysis AnalysisConfig `toml:"analysis"`
	Sources  SourcesConfig  `toml:"sources"`
	Export   ExportConfig   `toml:"export"`
	PCAP     PCAPConfig     `toml:"pcap"`
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
}

type ProtocolPolicy struct {
	MinTLSVersion         string   `toml:"min_tls_version"`
	RequireForwardSecrecy bool     `toml:"require_forward_secrecy"`
	RequireAEAD           bool     `toml:"require_aead"`
	BannedCiphers         []string `toml:"banned_ciphers"`
}

type SourcesConfig struct {
	ZeekFile  ZeekFileSourceConfig  `toml:"zeek_file"`
	Corelight CorelightSourceConfig `toml:"corelight"`
}

type ZeekFileSourceConfig struct {
	Enabled             bool   `toml:"enabled"`
	LogDir              string `toml:"log_dir"`
	PollIntervalSeconds int    `toml:"poll_interval_seconds"`
}

type CorelightSourceConfig struct {
	Enabled  bool   `toml:"enabled"`
	APIURL   string `toml:"api_url"`
	APIToken string `toml:"api_token"`
}

type ExportConfig struct {
	Venafi VenafiExportConfig `toml:"venafi"`
}

type VenafiExportConfig struct {
	Enabled             bool   `toml:"enabled"`
	Platform            string `toml:"platform"`
	// Cloud settings
	APIKey              string `toml:"api_key"`
	Region              string `toml:"region"`
	// TPP settings
	BaseURL             string `toml:"base_url"`
	ClientID            string `toml:"client_id"`
	RefreshToken        string `toml:"refresh_token"`
	// Common
	Folder              string `toml:"folder"`
	PushIntervalMinutes int    `toml:"push_interval_minutes"`
}

type PCAPConfig struct {
	MaxFileSizeMB  int    `toml:"max_file_size_mb"`
	RetentionHours int    `toml:"retention_hours"`
	InputDir       string `toml:"input_dir"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
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
	if cfg.Sources.ZeekFile.PollIntervalSeconds == 0 {
		cfg.Sources.ZeekFile.PollIntervalSeconds = 30
	}
	if cfg.Sources.ZeekFile.LogDir == "" {
		cfg.Sources.ZeekFile.LogDir = "/var/log/zeek/current"
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
	return &cfg, nil
}
