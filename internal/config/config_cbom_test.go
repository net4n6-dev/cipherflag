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
	"strings"
	"testing"
	"time"
)

func TestCBOMConfig_Validate_DuplicateScope(t *testing.T) {
	cfg := CBOMConfig{
		Enabled: true,
		Scopes: []ScopeConfig{
			{Name: "prod", HostPatterns: []string{"web-*.prod"}},
			{Name: "prod", HostPatterns: []string{"db-*.prod"}},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for duplicate scope name")
	}
}

func TestCBOMConfig_Validate_InvalidScopeName(t *testing.T) {
	cfg := CBOMConfig{
		Enabled: true,
		Scopes:  []ScopeConfig{{Name: "bad name!"}},
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "name must match") {
		t.Fatalf("expected name-format error, got %v", err)
	}
}

func TestCBOMConfig_Validate_InvalidAssetType(t *testing.T) {
	cfg := CBOMConfig{
		Enabled: true,
		Scopes:  []ScopeConfig{{Name: "s1", AssetTypes: []string{"widget"}}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for unknown asset type")
	}
}

func TestCBOMConfig_Validate_HTTPSinkMissingURL(t *testing.T) {
	cfg := CBOMConfig{
		Enabled: true,
		Scopes: []ScopeConfig{{
			Name:  "s1",
			Sinks: []SinkConfig{{Type: "http", HTTP: &HTTPSinkConfig{}}},
		}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for http sink missing url")
	}
}

func TestCBOMConfig_Validate_FileSinkMissingTemplate(t *testing.T) {
	cfg := CBOMConfig{
		Enabled: true,
		Scopes: []ScopeConfig{{
			Name:  "s1",
			Sinks: []SinkConfig{{Type: "file", File: &FileSinkConfig{}}},
		}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for file sink missing path_template")
	}
}

func TestCBOMConfig_Validate_UnknownSinkType(t *testing.T) {
	cfg := CBOMConfig{
		Enabled: true,
		Scopes: []ScopeConfig{{
			Name:  "s1",
			Sinks: []SinkConfig{{Type: "ftp"}},
		}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for unknown sink type")
	}
}

func TestCBOMConfig_Validate_Valid(t *testing.T) {
	cfg := CBOMConfig{
		Enabled: true,
		Scopes: []ScopeConfig{
			{
				Name:         "prod",
				HostPatterns: []string{"web-*.prod"},
				AssetTypes:   []string{"certificate", "ssh_key"},
				Sinks: []SinkConfig{
					{Type: "http", HTTP: &HTTPSinkConfig{URL: "https://dtrack.corp/api/v1/bom"}},
					{Type: "file", File: &FileSinkConfig{PathTemplate: "{output_dir}/{scope}/{timestamp}.cdx.json"}},
				},
			},
			{
				Name:    "dmz",
				HostIDs: []string{"550e8400-e29b-41d4-a716-446655440000"},
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoad_CBOMDefaults(t *testing.T) {
	cfg := &Config{
		CBOM: CBOMConfig{Enabled: true},
	}
	applyCBOMDefaults(cfg)
	if cfg.CBOM.PushInterval != 24*time.Hour {
		t.Errorf("PushInterval = %v, want 24h", cfg.CBOM.PushInterval)
	}
	if cfg.CBOM.MinEmitInterval != 5*time.Minute {
		t.Errorf("MinEmitInterval = %v, want 5m", cfg.CBOM.MinEmitInterval)
	}

	// Test sink-level defaults
	cfg2 := &Config{
		CBOM: CBOMConfig{
			Enabled: true,
			Scopes: []ScopeConfig{{
				Name:  "test",
				Sinks: []SinkConfig{{Type: "http", HTTP: &HTTPSinkConfig{URL: "http://example.com"}}},
			}},
		},
	}
	applyCBOMDefaults(cfg2)
	sink := cfg2.CBOM.Scopes[0].Sinks[0]
	if sink.Timeout != 30*time.Second {
		t.Errorf("sink Timeout = %v, want 30s", sink.Timeout)
	}
	if sink.Retries != 3 {
		t.Errorf("sink Retries = %d, want 3", sink.Retries)
	}
}
