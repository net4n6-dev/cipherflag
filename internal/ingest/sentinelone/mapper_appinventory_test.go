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
package sentinelone

import (
	"testing"
	"time"
)

func TestCryptoLibFilters_ContainsKnownLibraries(t *testing.T) {
	filters := CryptoLibFilters()
	want := []string{"openssl", "gnutls", "nss", "libgcrypt", "libsodium", "wolfssl", "bouncycastle", "libressl", "mbedtls", "nettle"}
	got := map[string]bool{}
	for _, f := range filters {
		got[f] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("CryptoLibFilters missing %q", w)
		}
	}
}

func TestCanonicalLibraryName(t *testing.T) {
	cases := map[string]string{
		"OpenSSL":        "openssl",
		"libssl3":        "openssl",
		"OpenSSL 3.0.14": "openssl",
		"Bouncy Castle":  "bouncycastle",
		"unknown-lib":    "unknown-lib",
		"  GnuTLS  ":     "gnutls",
	}
	for in, want := range cases {
		got := canonicalLibraryName(in)
		if got != want {
			t.Errorf("canonicalLibraryName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMapAppRecord_RequiresIdentity(t *testing.T) {
	_, err := MapAppRecord(AppRecord{AppVersion: "1.0"})
	if err == nil {
		t.Error("expected error when AppName missing")
	}
	_, err = MapAppRecord(AppRecord{AppName: "openssl"})
	if err == nil {
		t.Error("expected error when AppVersion missing")
	}
}

func TestMapAppRecord_PopulatesLibraryDiscovery(t *testing.T) {
	rec := AppRecord{
		AgentUUID:   "u-1",
		AgentName:   "host-1",
		OSType:      "linux",
		AppName:     "OpenSSL 3.0.14",
		AppVendor:   "OpenSSL Project",
		AppVersion:  "3.0.14",
		InstalledAt: time.Now(),
	}
	disc, err := MapAppRecord(rec)
	if err != nil {
		t.Fatalf("MapAppRecord: %v", err)
	}
	if disc.LibraryName != "openssl" {
		t.Errorf("LibraryName = %q", disc.LibraryName)
	}
	if disc.Version != "3.0.14" {
		t.Errorf("Version = %q", disc.Version)
	}
	if disc.PackageManager != "sentinelone-inventory" {
		t.Errorf("PackageManager = %q", disc.PackageManager)
	}
}

func TestGroupAppsByAgent_DropsMissingUUIDs(t *testing.T) {
	apps := []AppRecord{
		{AgentUUID: "u1", AppName: "a"},
		{AgentUUID: "", AppName: "b"},
		{AgentUUID: "u1", AppName: "c"},
		{AgentUUID: "u2", AppName: "d"},
	}
	g := GroupAppsByAgent(apps)
	if len(g["u1"]) != 2 {
		t.Errorf("u1 = %d", len(g["u1"]))
	}
	if len(g["u2"]) != 1 {
		t.Errorf("u2 = %d", len(g["u2"]))
	}
	if _, ok := g[""]; ok {
		t.Error("empty UUID group should be dropped")
	}
}
