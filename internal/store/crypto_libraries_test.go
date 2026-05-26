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
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

func TestUpsertAndListCryptoLibraries(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := seedHost(t, st)

	lib := &model.CryptoLibrary{
		HostID:          host.ID,
		LibraryName:     "openssl",
		Version:         "3.0.12",
		PackageName:     "libssl3",
		PackageManager:  "apt",
		InstallPath:     "/usr/lib/x86_64-linux-gnu/libssl.so.3",
		PQCCapable:      false,
		Source:          "osquery",
		DiscoveryStatus: "active",
	}

	if err := st.UpsertCryptoLibrary(ctx, lib); err != nil {
		t.Fatalf("UpsertCryptoLibrary: %v", err)
	}
	if lib.ID == "" {
		t.Fatal("expected library ID to be populated after upsert")
	}

	result, err := st.ListCryptoLibraries(ctx, LibrarySearchQuery{HostID: host.ID, Limit: 10})
	if err != nil {
		t.Fatalf("ListCryptoLibraries: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("total = %d, want 1", result.Total)
	}
	if len(result.Libraries) != 1 {
		t.Fatalf("libraries count = %d, want 1", len(result.Libraries))
	}
	if result.Libraries[0].LibraryName != "openssl" {
		t.Errorf("library_name = %q, want openssl", result.Libraries[0].LibraryName)
	}
	if result.Libraries[0].PackageName != "libssl3" {
		t.Errorf("package_name = %q, want libssl3", result.Libraries[0].PackageName)
	}
}

func TestUpsertCryptoLibrary_Dedup(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := seedHost(t, st)

	lib1 := &model.CryptoLibrary{
		HostID: host.ID, LibraryName: "openssl", Version: "3.0.12",
		PQCCapable: false, Source: "osquery", DiscoveryStatus: "active",
	}
	if err := st.UpsertCryptoLibrary(ctx, lib1); err != nil {
		t.Fatalf("first UpsertCryptoLibrary: %v", err)
	}
	firstID := lib1.ID

	// Upsert same library with updated pqc_capable
	lib2 := &model.CryptoLibrary{
		HostID: host.ID, LibraryName: "openssl", Version: "3.0.12",
		PQCCapable: true, Source: "osquery", DiscoveryStatus: "active",
	}
	if err := st.UpsertCryptoLibrary(ctx, lib2); err != nil {
		t.Fatalf("second UpsertCryptoLibrary: %v", err)
	}

	// Should still be one row
	result, err := st.ListCryptoLibraries(ctx, LibrarySearchQuery{HostID: host.ID, Limit: 10})
	if err != nil {
		t.Fatalf("ListCryptoLibraries: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("total after dedup = %d, want 1", result.Total)
	}
	if result.Libraries[0].ID != firstID {
		t.Errorf("ID changed after dedup: %q vs %q", result.Libraries[0].ID, firstID)
	}
	if !result.Libraries[0].PQCCapable {
		t.Error("expected pqc_capable to be updated to true on conflict")
	}
}

func TestListCryptoLibraries_FilterByName(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := seedHost(t, st)

	entries := []struct{ name, version string }{
		{"openssl", "1.0.0"},
		{"gnutls", "3.7.0"},
		{"openssl", "3.0.12"},
	}
	for _, e := range entries {
		lib := &model.CryptoLibrary{
			HostID: host.ID, LibraryName: e.name, Version: e.version,
			Source: "osquery", DiscoveryStatus: "active",
		}
		if err := st.UpsertCryptoLibrary(ctx, lib); err != nil {
			t.Fatalf("UpsertCryptoLibrary %s: %v", e.name, err)
		}
	}

	result, err := st.ListCryptoLibraries(ctx, LibrarySearchQuery{LibraryName: "openssl", Limit: 10})
	if err != nil {
		t.Fatalf("ListCryptoLibraries filtered: %v", err)
	}
	// Two openssl rows (different versions)
	if result.Total != 2 {
		t.Errorf("filtered total = %d, want 2", result.Total)
	}
}

func TestListCryptoLibraries_Search(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := seedHost(t, st)

	rows := []*model.CryptoLibrary{
		{
			HostID: host.ID, LibraryName: "openssl", Version: "3.0.12",
			PackageName: "libssl3", InstallPath: "/usr/lib/libssl.so.3",
			Source: "osquery", DiscoveryStatus: "active",
		},
		{
			HostID: host.ID, LibraryName: "gnutls", Version: "3.7.0",
			PackageName: "libgnutls30", InstallPath: "/usr/lib/libgnutls.so.30",
			Source: "osquery", DiscoveryStatus: "active",
		},
		{
			HostID: host.ID, LibraryName: "libsodium", Version: "1.0.18",
			PackageName: "libsodium23", InstallPath: "/usr/lib/libsodium.so.23",
			Source: "osquery", DiscoveryStatus: "active",
		},
	}
	for _, l := range rows {
		if err := st.UpsertCryptoLibrary(ctx, l); err != nil {
			t.Fatalf("UpsertCryptoLibrary %s: %v", l.LibraryName, err)
		}
	}

	cases := []struct {
		name   string
		search string
		want   int
	}{
		{"name match — ssl", "ssl", 1},
		{"version substring — 3.7", "3.7", 1},
		{"package name — gnutls", "gnutls", 1},
		{"install path — libsodium", "libsodium", 1},
		{"case insensitive — OPENSSL", "OPENSSL", 1},
		{"broad match — /usr/lib", "/usr/lib", 3},
		{"no match", "nonexistent", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result, err := st.ListCryptoLibraries(ctx,
				LibrarySearchQuery{HostID: host.ID, Search: c.search, Limit: 10})
			if err != nil {
				t.Fatalf("ListCryptoLibraries: %v", err)
			}
			if result.Total != c.want {
				t.Errorf("total = %d, want %d", result.Total, c.want)
			}
		})
	}
}

func TestGetCryptoLibraryCVEs(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// Insert a CVE directly
	_, err := st.pool.Exec(ctx, `
		INSERT INTO crypto_library_cves (library_name, version_range, cve_id, severity, description)
		VALUES ('openssl', '>=1.1.0,<1.1.1t', 'CVE-2023-0286', 'HIGH', 'X.400 address type confusion')
		ON CONFLICT (library_name, cve_id) DO NOTHING
	`)
	if err != nil {
		t.Fatalf("insert CVE: %v", err)
	}

	cves, err := st.GetCryptoLibraryCVEs(ctx, "openssl", "1.1.1s")
	if err != nil {
		t.Fatalf("GetCryptoLibraryCVEs: %v", err)
	}
	if len(cves) != 1 {
		t.Fatalf("cves count = %d, want 1", len(cves))
	}
	if cves[0].CVEID != "CVE-2023-0286" {
		t.Errorf("cve_id = %q, want CVE-2023-0286", cves[0].CVEID)
	}
}

func TestGetCryptoLibraryCVEs_Empty(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	cves, err := st.GetCryptoLibraryCVEs(ctx, "nonexistent-lib", "1.0.0")
	if err != nil {
		t.Fatalf("GetCryptoLibraryCVEs: %v", err)
	}
	if len(cves) != 0 {
		t.Errorf("expected empty CVE list, got %d", len(cves))
	}
}
