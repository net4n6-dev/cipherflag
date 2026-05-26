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
	"strings"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

const (
	sshAgeDays365  = 365 * 24 * time.Hour
	sshAgeDays1095 = 1095 * 24 * time.Hour
)

// ScoreSSHKey evaluates an SSH key and produces an AssetHealthReport.
// Rules: SSH-001..008.
func ScoreSSHKey(k *model.SSHKey) *model.AssetHealthReport {
	var findings []model.HealthFinding
	score := 100
	immediateFail := false

	findings = append(findings, checkSSHKeyType(k)...)
	findings = append(findings, checkSSHKeySize(k)...)
	findings = append(findings, checkSSHKeyAge(k)...)
	findings = append(findings, checkSSHKeyProtection(k)...)
	findings = append(findings, checkSSHKeyAuthorization(k)...)
	findings = append(findings, checkSSHKeyPositiveIndicators(k)...)

	for _, f := range findings {
		score -= f.Deduction
		if f.ImmediateFail {
			immediateFail = true
		}
	}
	if score < 0 {
		score = 0
	}

	return &model.AssetHealthReport{
		AssetType: "ssh_key",
		AssetID:   k.ID,
		Grade:     string(model.ScoreToGrade(score, immediateFail)),
		Score:     score,
		Findings:  findings,
		PQCStatus: ForSSHKey(k),
		ScoredAt:  time.Now(),
	}
}

// SSH-001: DSA key type (deprecated).
func checkSSHKeyType(k *model.SSHKey) []model.HealthFinding {
	lower := strings.ToLower(k.KeyType)
	if strings.Contains(lower, "dss") || strings.Contains(lower, "dsa") {
		return []model.HealthFinding{{
			RuleID:        "SSH-001",
			Title:         "DSA key type is deprecated",
			Severity:      model.SeverityCritical,
			Category:      model.CategoryKeyStrength,
			Detail:        "DSA keys are cryptographically deprecated and broken by Shor's algorithm on quantum hardware.",
			Remediation:   "Replace with Ed25519 or RSA >= 3072 bits.",
			Deduction:     100,
			ImmediateFail: true,
		}}
	}
	return nil
}

// SSH-002: RSA key < 2048 bits (High).
// SSH-003: RSA key < 3072 bits (Medium) — only if SSH-002 didn't fire.
func checkSSHKeySize(k *model.SSHKey) []model.HealthFinding {
	keyType := strings.ToLower(k.KeyType)
	if !strings.Contains(keyType, "rsa") {
		return nil
	}
	if k.KeySizeBits > 0 && k.KeySizeBits < 2048 {
		return []model.HealthFinding{{
			RuleID:      "SSH-002",
			Title:       "RSA key shorter than 2048 bits",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryKeyStrength,
			Detail:      "RSA keys below 2048 bits are considered broken.",
			Remediation: "Regenerate with RSA >= 3072 bits or migrate to Ed25519.",
			Deduction:   40,
		}}
	}
	if k.KeySizeBits >= 2048 && k.KeySizeBits < 3072 {
		return []model.HealthFinding{{
			RuleID:      "SSH-003",
			Title:       "RSA key below 3072-bit recommendation",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryKeyStrength,
			Detail:      "Current best practice recommends RSA >= 3072 bits for long-term security.",
			Remediation: "Consider regenerating with RSA 3072+ or migrating to Ed25519.",
			Deduction:   15,
		}}
	}
	return nil
}

// SSH-004: Key age > 365 days (Medium).
// SSH-005: Key age > 1095 days (High) — supersedes SSH-004.
func checkSSHKeyAge(k *model.SSHKey) []model.HealthFinding {
	if k.FirstSeen.IsZero() {
		return nil
	}
	age := time.Since(k.FirstSeen)
	if age > sshAgeDays1095 {
		return []model.HealthFinding{{
			RuleID:      "SSH-005",
			Title:       "SSH key older than 3 years without rotation",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryGovernance,
			Detail:      "Long-lived SSH keys accumulate exposure risk; rotation best practice is annual.",
			Remediation: "Generate a new key, update deployments, revoke the old key from authorized_keys entries.",
			Deduction:   30,
		}}
	}
	if age > sshAgeDays365 {
		return []model.HealthFinding{{
			RuleID:      "SSH-004",
			Title:       "SSH key older than 1 year without rotation",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryGovernance,
			Detail:      "SSH key has not been rotated within the past year.",
			Remediation: "Schedule key rotation; generate new keypair and update authorized_keys.",
			Deduction:   10,
		}}
	}
	return nil
}

// SSH-006: No passphrase protection on private key (Medium).
// Only scores private keys — authorized_keys entries don't have
// private-key protection by definition.
func checkSSHKeyProtection(k *model.SSHKey) []model.HealthFinding {
	if k.IsAuthorized {
		return nil
	}
	if !k.IsProtected {
		return []model.HealthFinding{{
			RuleID:      "SSH-006",
			Title:       "SSH private key has no passphrase",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryKeyStrength,
			Detail:      "Unprotected private key on disk allows any filesystem-level read to compromise the key.",
			Remediation: "Re-encrypt the key with a passphrase or move to hardware-backed storage.",
			Deduction:   15,
		}}
	}
	return nil
}

// SSH-007: Authorized key grants root access (High).
func checkSSHKeyAuthorization(k *model.SSHKey) []model.HealthFinding {
	if k.IsAuthorized && k.GrantsRoot {
		return []model.HealthFinding{{
			RuleID:      "SSH-007",
			Title:       "Authorized key grants root access",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryGovernance,
			Detail:      "This authorized_keys entry permits direct root login; loss of the private key compromises the host.",
			Remediation: "Remove root access from this key entry; require named user + sudo instead.",
			Deduction:   35,
		}}
	}
	return nil
}

// SSH-008: Ed25519 key — positive indicator (Info, deduction 0).
func checkSSHKeyPositiveIndicators(k *model.SSHKey) []model.HealthFinding {
	if strings.Contains(strings.ToLower(k.KeyType), "ed25519") {
		return []model.HealthFinding{{
			RuleID:   "SSH-008",
			Title:    "Ed25519 key — modern signature algorithm",
			Severity: model.SeverityInfo,
			Category: model.CategoryKeyStrength,
			Detail:   "Ed25519 is a modern, fast, 128-bit-security elliptic-curve signature scheme.",
		}}
	}
	return nil
}
