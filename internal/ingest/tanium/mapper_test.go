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
package tanium

import (
	"os"
	"strings"
	"testing"
)

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

func TestBuildDiscoveryResult_CustomSensorNDJSON(t *testing.T) {
	data, err := os.ReadFile("testdata/custom_sensor_output.ndjson")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	ep := EndpointResult{
		EndpointID: "e-1",
		Hostname:   "host-1",
		IPAddress:  "10.0.0.1",
		OSPlatform: "Linux",
		Sensors: []SensorReading{
			{
				SensorName: "CipherFlag.Crypto.Certificates",
				Columns:    []SensorColumn{{Name: "output", Values: lines}},
			},
		},
	}
	result := BuildDiscoveryResult(ep)
	if result.Source != "tanium" {
		t.Errorf("Source = %q", result.Source)
	}
	if result.SourceHostID != "e-1" {
		t.Errorf("SourceHostID = %q", result.SourceHostID)
	}
	if result.Hostname != "host-1" {
		t.Errorf("Hostname = %q", result.Hostname)
	}
	if len(result.IPAddresses) != 1 || result.IPAddresses[0] != "10.0.0.1" {
		t.Errorf("IPAddresses = %+v", result.IPAddresses)
	}
	if result.OSFamily != "linux" {
		t.Errorf("OSFamily = %q, want linux", result.OSFamily)
	}
	if len(result.Libraries) != 1 || result.Libraries[0].LibraryName != "openssl" {
		t.Errorf("libraries = %+v", result.Libraries)
	}
	if len(result.SSHKeys) != 1 || result.SSHKeys[0].FilePath != "/home/alice/.ssh/id_ed25519" {
		t.Errorf("ssh_keys = %+v", result.SSHKeys)
	}
	if len(result.Certificates) != 1 || result.Certificates[0].FingerprintSHA256 != "def" {
		t.Errorf("certs = %+v", result.Certificates)
	}
}

func TestBuildDiscoveryResult_InstalledApplicationsFiltersCryptoLibs(t *testing.T) {
	ep := EndpointResult{
		EndpointID: "e-2",
		Hostname:   "host-2",
		OSPlatform: "Windows",
		Sensors: []SensorReading{
			{
				SensorName: "Installed Applications",
				Columns: []SensorColumn{
					{Name: "Name", Values: []string{"OpenSSL 3.0.14", "Notepad++", "GnuTLS", "Microsoft Edge"}},
					{Name: "Version", Values: []string{"3.0.14", "8.6.0", "3.7.11", "120.0"}},
					{Name: "Publisher", Values: []string{"OpenSSL Project", "Don Ho", "GnuTLS", "Microsoft"}},
				},
			},
		},
	}
	result := BuildDiscoveryResult(ep)
	if len(result.Libraries) != 2 {
		t.Fatalf("libraries = %d, want 2 (openssl + gnutls), got %+v", len(result.Libraries), result.Libraries)
	}
	names := map[string]bool{}
	for _, lib := range result.Libraries {
		names[lib.LibraryName] = true
		if lib.PackageManager != "tanium-inventory" {
			t.Errorf("PackageManager = %q", lib.PackageManager)
		}
	}
	if !names["openssl"] || !names["gnutls"] {
		t.Errorf("expected openssl + gnutls, got %+v", names)
	}
}

func TestBuildDiscoveryResult_MultipleSensorsMerge(t *testing.T) {
	ep := EndpointResult{
		EndpointID: "e-3", Hostname: "host-3", OSPlatform: "Linux",
		Sensors: []SensorReading{
			{
				SensorName: "CipherFlag.Crypto.Libraries",
				Columns:    []SensorColumn{{Name: "output", Values: []string{`{"type":"library","name":"openssl","version":"3.0.14"}`}}},
			},
			{
				SensorName: "CipherFlag.Crypto.SSHKeys",
				Columns:    []SensorColumn{{Name: "output", Values: []string{`{"type":"ssh_key","file_path":"/root/.ssh/id_rsa","key_type":"ssh-rsa"}`}}},
			},
			{
				SensorName: "Installed Applications",
				Columns: []SensorColumn{
					{Name: "Name", Values: []string{"nettle"}},
					{Name: "Version", Values: []string{"3.9.1"}},
					{Name: "Publisher", Values: []string{"GNU"}},
				},
			},
		},
	}
	result := BuildDiscoveryResult(ep)
	if len(result.Libraries) != 2 {
		t.Errorf("libraries = %d, want 2 (custom sensor openssl + installed-app nettle)", len(result.Libraries))
	}
	if len(result.SSHKeys) != 1 {
		t.Errorf("ssh_keys = %d, want 1", len(result.SSHKeys))
	}
}

func TestBuildDiscoveryResult_MalformedNDJSONLinesAreSkipped(t *testing.T) {
	ep := EndpointResult{
		EndpointID: "e-4", Hostname: "host-4",
		Sensors: []SensorReading{
			{
				SensorName: "CipherFlag.Crypto.Libraries",
				Columns: []SensorColumn{{Name: "output", Values: []string{
					`{"type":"library","name":"openssl","version":"3"}`,
					`{broken json`,
					`{"type":"library","name":"gnutls","version":"3.7"}`,
				}}},
			},
		},
	}
	result := BuildDiscoveryResult(ep)
	if len(result.Libraries) != 2 {
		t.Errorf("libraries = %d, want 2 (malformed line dropped)", len(result.Libraries))
	}
}
