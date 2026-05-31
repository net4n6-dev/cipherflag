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

package absolute

import (
	"testing"
)

func TestCryptoLibFilters_ContainsKnownLibraries(t *testing.T) {
	filters := CryptoLibFilters()
	got := map[string]bool{}
	for _, f := range filters {
		got[f] = true
	}
	for _, w := range []string{"openssl", "gnutls", "nss", "libgcrypt", "libsodium", "wolfssl", "bouncycastle", "libressl", "mbedtls", "nettle"} {
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

func TestMapDeviceApp_RequiresIdentity(t *testing.T) {
	_, err := MapDeviceApp(DeviceApp{AppVersion: "1.0"})
	if err == nil {
		t.Error("expected error when AppName missing")
	}
	_, err = MapDeviceApp(DeviceApp{AppName: "openssl"})
	if err == nil {
		t.Error("expected error when AppVersion missing")
	}
}

func TestMapDeviceApp_PopulatesLibraryDiscovery(t *testing.T) {
	app := DeviceApp{
		DeviceID:   "dev-1",
		DeviceName: "host-1",
		OSPlatform: "Linux",
		AppName:    "OpenSSL 3.0.14",
		AppVendor:  "OpenSSL Project",
		AppVersion: "3.0.14",
	}
	disc, err := MapDeviceApp(app)
	if err != nil {
		t.Fatalf("MapDeviceApp: %v", err)
	}
	if disc.LibraryName != "openssl" {
		t.Errorf("LibraryName = %q", disc.LibraryName)
	}
	if disc.Version != "3.0.14" {
		t.Errorf("Version = %q", disc.Version)
	}
	if disc.PackageManager != "absolute-inventory" {
		t.Errorf("PackageManager = %q", disc.PackageManager)
	}
}

func TestGroupAppsByDevice_DropsMissingIDs(t *testing.T) {
	apps := []DeviceApp{
		{DeviceID: "d1", AppName: "a"},
		{DeviceID: "", AppName: "b"},
		{DeviceID: "d1", AppName: "c"},
		{DeviceID: "d2", AppName: "d"},
	}
	g := GroupAppsByDevice(apps)
	if len(g["d1"]) != 2 {
		t.Errorf("d1 = %d", len(g["d1"]))
	}
	if len(g["d2"]) != 1 {
		t.Errorf("d2 = %d", len(g["d2"]))
	}
	if _, ok := g[""]; ok {
		t.Error("empty ID group should be dropped")
	}
}
