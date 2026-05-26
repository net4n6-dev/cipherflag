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

package b1

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

func genAuthorizedKeys(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("pub: %v", err)
	}
	return ssh.MarshalAuthorizedKey(sshPub)
}

func TestSSHDetector_StemMatchWithoutArmour_Critical(t *testing.T) {
	// SSHDetector OWNS the case where the filename stem matches but the
	// file content is NOT PEM-armoured (e.g., binary placeholder, truncated
	// id_rsa from a legacy commit). When armour IS present, SSHDetector
	// defers to PEMDetector to keep dispatcher dedup simple.
	d := &SSHDetector{}
	blob := enumerate.Blob{Path: "home/user/.ssh/id_ed25519", Size: 16}
	data := []byte("\x00\x01binary placeholder")
	findings, err := d.Detect(context.Background(), blob, data)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1, got %d", len(findings))
	}
	if findings[0].Severity != finding.SeverityCritical {
		t.Errorf("severity: %q", findings[0].Severity)
	}
	if findings[0].RuleID != "KEY-MAT-SSH-PRIVKEY-IN-REPO" {
		t.Errorf("rule_id: %q", findings[0].RuleID)
	}
}

func TestSSHDetector_DefersToPEMWhenArmourPresent(t *testing.T) {
	d := &SSHDetector{}
	blob := enumerate.Blob{Path: "keys/id_rsa", Size: 100}
	data := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n")
	findings, _ := d.Detect(context.Background(), blob, data)
	if len(findings) != 0 {
		t.Errorf("SSHDetector should defer to PEMDetector when armour present; got %d findings", len(findings))
	}
}

func TestSSHDetector_AuthorizedKeys_Low(t *testing.T) {
	d := &SSHDetector{}
	body := genAuthorizedKeys(t)
	blob := enumerate.Blob{Path: "root/.ssh/authorized_keys", Size: int64(len(body))}
	findings, err := d.Detect(context.Background(), blob, body)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("want >=1")
	}
	f := findings[0]
	if f.RuleID != "KEY-MAT-SSH-AUTHKEYS-IN-REPO" {
		t.Errorf("rule_id: %q", f.RuleID)
	}
	if f.Severity != finding.SeverityLow {
		t.Errorf("authorized_keys is not sensitive like a private key; want Low, got %q", f.Severity)
	}
	if f.Fingerprint == "" {
		t.Error("fingerprint empty for SSH public key")
	}
}

func TestSSHDetector_KnownHosts_Info(t *testing.T) {
	d := &SSHDetector{}
	body := []byte("|1|hashed|hashed ssh-rsa AAAAB3NzaC1yc2E=\n")
	blob := enumerate.Blob{Path: ".ssh/known_hosts", Size: int64(len(body))}
	findings, _ := d.Detect(context.Background(), blob, body)
	if len(findings) != 1 {
		t.Fatalf("want 1, got %d", len(findings))
	}
	if !strings.Contains(findings[0].RuleID, "SSH-KNOWNHOSTS") {
		t.Errorf("rule_id: %q", findings[0].RuleID)
	}
	if findings[0].Severity != finding.SeverityInfo {
		t.Errorf("severity: %q", findings[0].Severity)
	}
}

func TestSSHDetector_IgnoresUnrelatedFiles(t *testing.T) {
	d := &SSHDetector{}
	blob := enumerate.Blob{Path: "README.md", Size: 5}
	findings, _ := d.Detect(context.Background(), blob, []byte("hello"))
	if len(findings) != 0 {
		t.Error("unrelated file should produce 0 findings")
	}
}
