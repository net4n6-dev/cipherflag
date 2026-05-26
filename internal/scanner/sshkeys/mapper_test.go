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

package sshkeys

import (
	"testing"
	"time"
)

func TestMapFindings(t *testing.T) {
	findings := []SSHKeyFinding{
		{
			KeyType:           "rsa",
			KeySizeBits:       4096,
			FingerprintSHA256: "SHA256:abc123def456",
			FilePath:          "/home/admin/.ssh/id_rsa",
			OwnerUser:         "admin",
			IsPrivateKey:      true,
			IsProtected:       true,
			IsAuthorized:      false,
			GrantsRoot:        false,
			FileMode:          0600,
			ModifiedAt:        time.Now(),
		},
		{
			KeyType:           "ed25519",
			KeySizeBits:       256,
			FingerprintSHA256: "SHA256:xyz789",
			FilePath:          "/root/.ssh/authorized_keys",
			OwnerUser:         "root",
			IsPrivateKey:      false,
			IsProtected:       false,
			IsAuthorized:      true,
			GrantsRoot:        true,
			FileMode:          0644,
			ModifiedAt:        time.Now(),
		},
	}

	discoveries := MapFindings(findings)

	if len(discoveries) != 2 {
		t.Fatalf("got %d discoveries, want 2", len(discoveries))
	}

	d0 := discoveries[0]
	if d0.KeyType != "rsa" {
		t.Errorf("d0.KeyType = %q, want rsa", d0.KeyType)
	}
	if d0.KeySizeBits != 4096 {
		t.Errorf("d0.KeySizeBits = %d, want 4096", d0.KeySizeBits)
	}
	if d0.FingerprintSHA256 != "SHA256:abc123def456" {
		t.Errorf("d0.FingerprintSHA256 = %q", d0.FingerprintSHA256)
	}
	if d0.FilePath != "/home/admin/.ssh/id_rsa" {
		t.Errorf("d0.FilePath = %q", d0.FilePath)
	}
	if d0.OwnerUser != "admin" {
		t.Errorf("d0.OwnerUser = %q", d0.OwnerUser)
	}
	if d0.IsAuthorized != false {
		t.Error("d0.IsAuthorized should be false")
	}
	if d0.IsProtected != true {
		t.Error("d0.IsProtected should be true")
	}
	if d0.GrantsRoot != false {
		t.Error("d0.GrantsRoot should be false")
	}

	d1 := discoveries[1]
	if d1.KeyType != "ed25519" {
		t.Errorf("d1.KeyType = %q, want ed25519", d1.KeyType)
	}
	if d1.IsAuthorized != true {
		t.Error("d1.IsAuthorized should be true")
	}
	if d1.GrantsRoot != true {
		t.Error("d1.GrantsRoot should be true")
	}
}

func TestMapFindings_Empty(t *testing.T) {
	discoveries := MapFindings(nil)
	if len(discoveries) != 0 {
		t.Errorf("got %d discoveries for nil input, want 0", len(discoveries))
	}
}
