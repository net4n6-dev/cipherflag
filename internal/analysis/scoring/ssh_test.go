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

package scoring

import (
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

func sshKeyWith(apply func(*model.SSHKey)) *model.SSHKey {
	k := &model.SSHKey{
		ID:          "test-ssh-id",
		KeyType:     "ssh-ed25519",
		KeySizeBits: 256,
		FirstSeen:   time.Now(),
		LastSeen:    time.Now(),
	}
	if apply != nil {
		apply(k)
	}
	return k
}

func findFinding(r *model.AssetHealthReport, ruleID string) *model.HealthFinding {
	for i := range r.Findings {
		if r.Findings[i].RuleID == ruleID {
			return &r.Findings[i]
		}
	}
	return nil
}

func TestSSH001_DSAKeyImmediateFail(t *testing.T) {
	r := ScoreSSHKey(sshKeyWith(func(k *model.SSHKey) { k.KeyType = "ssh-dss" }))
	f := findFinding(r, "SSH-001")
	if f == nil {
		t.Fatal("SSH-001 did not fire")
	}
	if f.Severity != model.SeverityCritical {
		t.Errorf("SSH-001 severity = %s, want Critical", f.Severity)
	}
	if !f.ImmediateFail {
		t.Error("SSH-001 should be immediate-fail")
	}
	if r.Grade != string(model.GradeF) {
		t.Errorf("grade = %s, want F", r.Grade)
	}
}

func TestSSH002_RSASmall(t *testing.T) {
	r := ScoreSSHKey(sshKeyWith(func(k *model.SSHKey) {
		k.KeyType = "ssh-rsa"
		k.KeySizeBits = 1024
	}))
	if findFinding(r, "SSH-002") == nil {
		t.Fatal("SSH-002 did not fire")
	}
	if findFinding(r, "SSH-003") != nil {
		t.Error("SSH-003 fired alongside SSH-002")
	}
}

func TestSSH003_RSABelowRecommended(t *testing.T) {
	r := ScoreSSHKey(sshKeyWith(func(k *model.SSHKey) {
		k.KeyType = "ssh-rsa"
		k.KeySizeBits = 2048
	}))
	if findFinding(r, "SSH-003") == nil {
		t.Fatal("SSH-003 did not fire for RSA 2048")
	}
	if findFinding(r, "SSH-002") != nil {
		t.Error("SSH-002 fired for RSA 2048")
	}
}

func TestSSH004_KeyAgeMedium(t *testing.T) {
	r := ScoreSSHKey(sshKeyWith(func(k *model.SSHKey) {
		k.FirstSeen = time.Now().Add(-400 * 24 * time.Hour)
	}))
	if findFinding(r, "SSH-004") == nil {
		t.Fatal("SSH-004 did not fire for 400-day-old key")
	}
	if findFinding(r, "SSH-005") != nil {
		t.Error("SSH-005 fired for 400-day-old key (threshold is 1095)")
	}
}

func TestSSH005_KeyAgeHigh(t *testing.T) {
	r := ScoreSSHKey(sshKeyWith(func(k *model.SSHKey) {
		k.FirstSeen = time.Now().Add(-1500 * 24 * time.Hour)
	}))
	if findFinding(r, "SSH-005") == nil {
		t.Fatal("SSH-005 did not fire for 1500-day-old key")
	}
	if findFinding(r, "SSH-004") != nil {
		t.Error("SSH-004 fired alongside SSH-005")
	}
}

func TestSSH006_NoPassphrase(t *testing.T) {
	r := ScoreSSHKey(sshKeyWith(func(k *model.SSHKey) {
		k.IsProtected = false
		k.IsAuthorized = false
	}))
	if findFinding(r, "SSH-006") == nil {
		t.Fatal("SSH-006 did not fire for unprotected private key")
	}
}

func TestSSH006_DoesNotFireForAuthorizedKey(t *testing.T) {
	r := ScoreSSHKey(sshKeyWith(func(k *model.SSHKey) {
		k.IsProtected = false
		k.IsAuthorized = true
	}))
	if findFinding(r, "SSH-006") != nil {
		t.Error("SSH-006 fired for IsAuthorized=true; should only score private keys")
	}
}

func TestSSH007_AuthorizedKeyGrantsRoot(t *testing.T) {
	r := ScoreSSHKey(sshKeyWith(func(k *model.SSHKey) {
		k.IsAuthorized = true
		k.GrantsRoot = true
	}))
	if findFinding(r, "SSH-007") == nil {
		t.Fatal("SSH-007 did not fire")
	}
}

func TestSSH008_Ed25519IsInfo(t *testing.T) {
	r := ScoreSSHKey(sshKeyWith(func(k *model.SSHKey) { k.KeyType = "ssh-ed25519" }))
	f := findFinding(r, "SSH-008")
	if f == nil {
		t.Fatal("SSH-008 did not fire for Ed25519")
	}
	if f.Severity != model.SeverityInfo {
		t.Errorf("SSH-008 severity = %s, want Info", f.Severity)
	}
	if f.Deduction != 0 {
		t.Errorf("SSH-008 deduction = %d, want 0", f.Deduction)
	}
}

func TestScoreSSHKey_SetsAssetTypeAndID(t *testing.T) {
	r := ScoreSSHKey(sshKeyWith(func(k *model.SSHKey) { k.ID = "my-ssh-id" }))
	if r.AssetType != "ssh_key" {
		t.Errorf("AssetType = %s, want ssh_key", r.AssetType)
	}
	if r.AssetID != "my-ssh-id" {
		t.Errorf("AssetID = %s, want my-ssh-id", r.AssetID)
	}
}
