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

package zeek

import (
	"testing"
)

func TestParseSSHRecord(t *testing.T) {
	input := []byte(`{"ts":1712000000.000000,"uid":"CAbcde","id.orig_h":"10.0.0.5","id.orig_p":54321,"id.resp_h":"192.168.1.10","id.resp_p":22,"version":2,"auth_success":true,"auth_attempts":1,"direction":"INBOUND","cipher_alg":"chacha20-poly1305@openssh.com","mac_alg":"umac-64-etm@openssh.com","kex_alg":"curve25519-sha256","host_key_alg":"ssh-ed25519","host_key":"AAAAC3NzaC1lZDI1NTE5AAAA","hassh":"abc123","hasshServer":"def456"}`)

	rec, err := ParseSSHRecord(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.ClientIP != "10.0.0.5" {
		t.Errorf("ClientIP = %q", rec.ClientIP)
	}
	if rec.ServerIP != "192.168.1.10" {
		t.Errorf("ServerIP = %q", rec.ServerIP)
	}
	if rec.ServerPort != 22 {
		t.Errorf("ServerPort = %d", rec.ServerPort)
	}
	if rec.Version != 2 {
		t.Errorf("Version = %d", rec.Version)
	}
	if !rec.AuthSuccess {
		t.Error("expected AuthSuccess = true")
	}
	if rec.Cipher != "chacha20-poly1305@openssh.com" {
		t.Errorf("Cipher = %q", rec.Cipher)
	}
	if rec.KexAlg != "curve25519-sha256" {
		t.Errorf("KexAlg = %q", rec.KexAlg)
	}
	if rec.HostKeyAlg != "ssh-ed25519" {
		t.Errorf("HostKeyAlg = %q", rec.HostKeyAlg)
	}
	if rec.HASSH != "abc123" {
		t.Errorf("HASSH = %q", rec.HASSH)
	}
	if rec.HASSHServer != "def456" {
		t.Errorf("HASSHServer = %q", rec.HASSHServer)
	}
}

func TestParseSSHRecord_WeakAlgorithms(t *testing.T) {
	input := []byte(`{"ts":1712000001.000000,"uid":"CFghij","id.orig_h":"10.0.0.6","id.orig_p":54322,"id.resp_h":"192.168.1.11","id.resp_p":22,"version":2,"auth_success":false,"auth_attempts":3,"direction":"INBOUND","cipher_alg":"aes128-cbc","mac_alg":"hmac-sha1","kex_alg":"diffie-hellman-group1-sha1","host_key_alg":"ssh-rsa","host_key":"AAAAB3NzaC1yc2EAAAA","hassh":"ghi789","hasshServer":"jkl012"}`)

	rec, err := ParseSSHRecord(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.AuthSuccess {
		t.Error("expected AuthSuccess = false")
	}
	if rec.AuthAttempts != 3 {
		t.Errorf("AuthAttempts = %d", rec.AuthAttempts)
	}
	if rec.Cipher != "aes128-cbc" {
		t.Errorf("Cipher = %q", rec.Cipher)
	}
	if rec.KexAlg != "diffie-hellman-group1-sha1" {
		t.Errorf("KexAlg = %q", rec.KexAlg)
	}
}

func TestParseSSHRecord_InvalidJSON(t *testing.T) {
	_, err := ParseSSHRecord([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
