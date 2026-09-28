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
	"regexp"
	"testing"
)

func loadFromString(t *testing.T, body string) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cipherflag.toml")
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

// Scoring is the only writer of health_reports, so a config that says nothing
// about it must still score.
func TestLoad_ScorerEnabledByDefault(t *testing.T) {
	cfg := loadFromString(t, "[server]\nlisten = \"0.0.0.0:8443\"\n")
	if !cfg.Analysis.ScorerEnabled {
		t.Error("Analysis.ScorerEnabled = false for a config that omits scorer_enabled, want true")
	}
}

func TestLoad_ScorerEnabledOptOut(t *testing.T) {
	cfg := loadFromString(t, "[analysis]\nscorer_enabled = false\n")
	if cfg.Analysis.ScorerEnabled {
		t.Error("Analysis.ScorerEnabled = true after an explicit scorer_enabled = false, want false")
	}
}

func TestShippedSampleConfigsEnableScoring(t *testing.T) {
	for _, name := range []string{"cipherflag.toml", "cipherflag.docker.toml"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", "config", name))
			if err != nil {
				t.Fatal(err)
			}
			if !regexp.MustCompile(`(?m)^scorer_enabled\s*=\s*true\b`).Match(data) {
				t.Errorf("config/%s must set scorer_enabled = true explicitly", name)
			}
		})
	}
}
