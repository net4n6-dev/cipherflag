// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package defender

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func testdataDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "testdata")
}

// loadResponseRows reads the fixture, extracts Results[], and returns each
// as a QueryRow.
func loadResponseRows(t *testing.T, name string) []QueryRow {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(testdataDir(), name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var resp struct {
		Results []map[string]any `json:"Results"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("unmarshal fixture %s: %v", name, err)
	}
	out := make([]QueryRow, 0, len(resp.Results))
	for _, r := range resp.Results {
		out = append(out, QueryRow{Columns: r})
	}
	return out
}

func TestCanonicalLibraryName(t *testing.T) {
	tests := []struct {
		software string
		want     string
	}{
		{"OpenSSL", "openssl"},
		{"openssl", "openssl"},
		{"libssl3", "openssl"},
		{"libssl1.1", "openssl"},
		{"libssl", "openssl"},
		{"GnuTLS", "gnutls"},
		{"libgnutls", "gnutls"},
		{"NSS", "nss"},
		{"libnss", "nss"},
		{"libgcrypt", "libgcrypt"},
		{"libsodium", "libsodium"},
		{"wolfSSL", "wolfssl"},
		{"Bouncy Castle", "bouncycastle"},
		{"bouncycastle", "bouncycastle"},
		{"LibreSSL", "libressl"},
		{"mbedTLS", "mbedtls"},
		{"Nettle", "nettle"},
		{"some-other-thing", "some-other-thing"},
	}
	for _, tt := range tests {
		got := canonicalLibraryName(tt.software)
		if got != tt.want {
			t.Errorf("canonicalLibraryName(%q) = %q, want %q", tt.software, got, tt.want)
		}
	}
}

func TestMapRow_OpenSSL(t *testing.T) {
	rows := loadResponseRows(t, "advanced_hunting_response.json")
	if len(rows) < 1 {
		t.Fatal("fixture has no rows")
	}

	disc, err := MapRow(rows[0])
	if err != nil {
		t.Fatalf("MapRow: %v", err)
	}
	if disc.LibraryName != "openssl" {
		t.Errorf("LibraryName = %q, want openssl", disc.LibraryName)
	}
	if disc.Version != "3.0.14" {
		t.Errorf("Version = %q", disc.Version)
	}
	if disc.PackageName != "OpenSSL" {
		t.Errorf("PackageName = %q", disc.PackageName)
	}
	if disc.PackageManager != "microsoft-defender" {
		t.Errorf("PackageManager = %q", disc.PackageManager)
	}
}

func TestMapRow_BouncyCastle(t *testing.T) {
	rows := loadResponseRows(t, "advanced_hunting_response.json")
	if len(rows) < 2 {
		t.Fatal("fixture has fewer than 2 rows")
	}

	disc, err := MapRow(rows[1])
	if err != nil {
		t.Fatalf("MapRow: %v", err)
	}
	if disc.LibraryName != "bouncycastle" {
		t.Errorf("LibraryName = %q, want bouncycastle", disc.LibraryName)
	}
	if disc.Version != "1.78" {
		t.Errorf("Version = %q", disc.Version)
	}
}

func TestMapRow_MissingDeviceId(t *testing.T) {
	row := QueryRow{Columns: map[string]any{
		"SoftwareName":    "OpenSSL",
		"SoftwareVersion": "3.0.14",
	}}
	_, err := MapRow(row)
	if err == nil {
		t.Fatal("expected error for row missing DeviceId")
	}
}

func TestMapRow_EmptyVersion(t *testing.T) {
	row := QueryRow{Columns: map[string]any{
		"DeviceId":     "d1",
		"SoftwareName": "OpenSSL",
	}}
	_, err := MapRow(row)
	if err == nil {
		t.Fatal("expected error for row missing SoftwareVersion (version is part of dedup identity)")
	}
}

func TestGroupRowsByDevice(t *testing.T) {
	rows := loadResponseRows(t, "advanced_hunting_response.json")
	groups := GroupRowsByDevice(rows)
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2 (device-001 and device-002)", len(groups))
	}
	if len(groups["device-001"]) != 2 {
		t.Errorf("device-001 should have 2 rows, got %d", len(groups["device-001"]))
	}
	if len(groups["device-002"]) != 1 {
		t.Errorf("device-002 should have 1 row, got %d", len(groups["device-002"]))
	}
}

func TestExtractDeviceMetadata(t *testing.T) {
	row := QueryRow{Columns: map[string]any{
		"DeviceId":   "d1",
		"DeviceName": "lin-app-02",
		"OSPlatform": "Ubuntu",
	}}
	meta := ExtractDeviceMetadata(row)
	if meta.DeviceID != "d1" {
		t.Errorf("DeviceID = %q", meta.DeviceID)
	}
	if meta.DeviceName != "lin-app-02" {
		t.Errorf("DeviceName = %q", meta.DeviceName)
	}
	if meta.OSFamily != "linux" {
		t.Errorf("OSFamily = %q, want linux (normalized from Ubuntu)", meta.OSFamily)
	}
}
