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

package store

import (
	"context"
	"fmt"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

func TestUpsertAndListCryptoConfigs(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := seedHost(t, st)

	cfg := &model.CryptoConfig{
		HostID:     host.ID,
		ConfigType: "sshd_config",
		FilePath:   "/etc/ssh/sshd_config",
		Settings: map[string]string{
			"Protocol":               "2",
			"PermitRootLogin":        "no",
			"PasswordAuthentication": "no",
		},
		Findings: []model.ConfigIssue{
			{Setting: "Ciphers", Value: "aes128-cbc", Issue: "CBC mode cipher", Severity: "medium"},
		},
		Source:          "agent",
		DiscoveryStatus: "active",
	}

	if err := st.UpsertCryptoConfig(ctx, cfg); err != nil {
		t.Fatalf("UpsertCryptoConfig: %v", err)
	}
	if cfg.ID == "" {
		t.Fatal("expected config ID to be populated after upsert")
	}

	result, err := st.ListCryptoConfigs(ctx, ConfigSearchQuery{HostID: host.ID, Limit: 10})
	if err != nil {
		t.Fatalf("ListCryptoConfigs: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("total = %d, want 1", result.Total)
	}
	if len(result.Configs) != 1 {
		t.Fatalf("configs count = %d, want 1", len(result.Configs))
	}
	if result.Configs[0].ConfigType != "sshd_config" {
		t.Errorf("config_type = %q, want sshd_config", result.Configs[0].ConfigType)
	}
	if result.Configs[0].Settings["PermitRootLogin"] != "no" {
		t.Errorf("settings[PermitRootLogin] = %q, want no", result.Configs[0].Settings["PermitRootLogin"])
	}
	if len(result.Configs[0].Findings) != 1 {
		t.Errorf("findings count = %d, want 1", len(result.Configs[0].Findings))
	}
}

func TestUpsertCryptoConfig_Dedup(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := seedHost(t, st)

	cfg1 := &model.CryptoConfig{
		HostID: host.ID, ConfigType: "sshd_config", FilePath: "/etc/ssh/sshd_config",
		Settings: map[string]string{"Protocol": "2"},
		Findings: []model.ConfigIssue{},
		Source: "agent", DiscoveryStatus: "active",
	}
	if err := st.UpsertCryptoConfig(ctx, cfg1); err != nil {
		t.Fatalf("first UpsertCryptoConfig: %v", err)
	}

	// Upsert same path with updated settings
	cfg2 := &model.CryptoConfig{
		HostID: host.ID, ConfigType: "sshd_config", FilePath: "/etc/ssh/sshd_config",
		Settings: map[string]string{"Protocol": "2", "PermitRootLogin": "no"},
		Findings: []model.ConfigIssue{{Setting: "Ciphers", Value: "weak", Issue: "bad", Severity: "high"}},
		Source: "agent", DiscoveryStatus: "active",
	}
	if err := st.UpsertCryptoConfig(ctx, cfg2); err != nil {
		t.Fatalf("second UpsertCryptoConfig: %v", err)
	}

	result, err := st.ListCryptoConfigs(ctx, ConfigSearchQuery{HostID: host.ID, Limit: 10})
	if err != nil {
		t.Fatalf("ListCryptoConfigs: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("total after dedup = %d, want 1", result.Total)
	}
	if result.Configs[0].Settings["PermitRootLogin"] != "no" {
		t.Error("expected settings to be updated on conflict")
	}
	if len(result.Configs[0].Findings) != 1 {
		t.Error("expected findings to be updated on conflict")
	}
}

func TestListCryptoConfigs_Search(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := seedHost(t, st)

	rows := []*model.CryptoConfig{
		{
			HostID: host.ID, ConfigType: "sshd_config",
			FilePath: "/etc/ssh/sshd_config",
			Settings: map[string]string{}, Findings: []model.ConfigIssue{},
			Source:   "agent", DiscoveryStatus: "active",
		},
		{
			HostID: host.ID, ConfigType: "openssl_cnf",
			FilePath: "/etc/ssl/openssl.cnf",
			Settings: map[string]string{}, Findings: []model.ConfigIssue{},
			Source:   "agent", DiscoveryStatus: "active",
		},
		{
			HostID: host.ID, ConfigType: "nginx_tls",
			FilePath: "/etc/nginx/sites-available/secure.conf",
			Settings: map[string]string{}, Findings: []model.ConfigIssue{},
			Source:   "agent", DiscoveryStatus: "active",
		},
	}
	for _, c := range rows {
		if err := st.UpsertCryptoConfig(ctx, c); err != nil {
			t.Fatalf("UpsertCryptoConfig: %v", err)
		}
	}

	cases := []struct {
		name   string
		search string
		want   int
	}{
		{"config type — sshd", "sshd", 1},
		{"path — /etc/nginx", "/etc/nginx", 1},
		{"path — /etc/ssl", "/etc/ssl", 1},
		{"case insensitive — NGINX", "NGINX", 1},
		{"broad match — /etc/", "/etc/", 3},
		{"no match", "nonexistent", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result, err := st.ListCryptoConfigs(ctx,
				ConfigSearchQuery{HostID: host.ID, Search: c.search, Limit: 10})
			if err != nil {
				t.Fatalf("ListCryptoConfigs: %v", err)
			}
			if result.Total != c.want {
				t.Errorf("total = %d, want %d", result.Total, c.want)
			}
		})
	}
}

func TestListCryptoConfigs_FilterByType(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := seedHost(t, st)

	for i, ct := range []string{"sshd_config", "openssl_cnf", "sshd_config"} {
		cfg := &model.CryptoConfig{
			HostID: host.ID, ConfigType: ct,
			FilePath: fmt.Sprintf("/etc/%s/%d", ct, i),
			Settings: map[string]string{}, Findings: []model.ConfigIssue{},
			Source: "agent", DiscoveryStatus: "active",
		}
		if err := st.UpsertCryptoConfig(ctx, cfg); err != nil {
			t.Fatalf("UpsertCryptoConfig %s: %v", ct, err)
		}
	}

	result, err := st.ListCryptoConfigs(ctx, ConfigSearchQuery{ConfigType: "sshd_config", Limit: 10})
	if err != nil {
		t.Fatalf("ListCryptoConfigs filtered: %v", err)
	}
	if result.Total != 2 {
		t.Errorf("filtered total = %d, want 2", result.Total)
	}
}
