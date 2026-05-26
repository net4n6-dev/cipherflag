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

	"github.com/net4n6-dev/cipherflag/internal/analysis/pqc"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

// ScoreConfig evaluates a crypto configuration and produces an
// AssetHealthReport. Rules: CFG-001..004.
func ScoreConfig(cfg *model.CryptoConfig) *model.AssetHealthReport {
	var findings []model.HealthFinding
	score := 100
	immediateFail := false

	findings = append(findings, checkConfigOpenSSLLegacy(cfg)...)
	findings = append(findings, checkConfigSSHDPasswordAuth(cfg)...)
	findings = append(findings, checkConfigSSHDWeakAlgorithms(cfg)...)
	findings = append(findings, checkConfigJavaDisabledAlgorithms(cfg)...)

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
		AssetType: "crypto_config",
		AssetID:   cfg.ID,
		Grade:     string(model.ScoreToGrade(score, immediateFail)),
		Score:     score,
		Findings:  findings,
		PQCStatus: ForConfig(cfg),
		ScoredAt:  time.Now(),
	}
}

// CFG-001: OpenSSL legacy provider enabled.
func checkConfigOpenSSLLegacy(cfg *model.CryptoConfig) []model.HealthFinding {
	if cfg.ConfigType != "openssl" {
		return nil
	}
	provider := strings.ToLower(cfg.Settings["provider"])
	activate := cfg.Settings["activate"]
	if provider == "legacy" && (activate == "1" || activate == "yes" || activate == "true") {
		return []model.HealthFinding{{
			RuleID:      "CFG-001",
			Title:       "OpenSSL legacy provider is active",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryCipher,
			Detail:      "The legacy provider exposes deprecated algorithms (MD4, DES, RC4).",
			Remediation: "Disable the legacy provider unless required; prefer the default and FIPS providers.",
			Deduction:   15,
		}}
	}
	return nil
}

// CFG-002: SSHD allows password authentication.
func checkConfigSSHDPasswordAuth(cfg *model.CryptoConfig) []model.HealthFinding {
	if cfg.ConfigType != "sshd" {
		return nil
	}
	val := strings.ToLower(strings.TrimSpace(cfg.Settings["PasswordAuthentication"]))
	if val == "yes" {
		return []model.HealthFinding{{
			RuleID:      "CFG-002",
			Title:       "SSHD allows password authentication",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryGovernance,
			Detail:      "Password auth enables brute-force risk; keys (or MFA'd keys) are preferred.",
			Remediation: "Set 'PasswordAuthentication no' and 'PermitRootLogin prohibit-password' in sshd_config.",
			Deduction:   10,
		}}
	}
	return nil
}

// CFG-003: SSHD allows weak ciphers / MACs / kex.
// Evaluates each algorithm via pqc.Classify; fires if any is
// Vulnerable or Weakened.
func checkConfigSSHDWeakAlgorithms(cfg *model.CryptoConfig) []model.HealthFinding {
	if cfg.ConfigType != "sshd" {
		return nil
	}
	keys := []string{"Ciphers", "MACs", "KexAlgorithms"}
	var weak []string
	for _, k := range keys {
		list := cfg.Settings[k]
		if list == "" {
			continue
		}
		for _, alg := range strings.Split(list, ",") {
			alg = strings.TrimSpace(alg)
			if alg == "" {
				continue
			}
			status := pqc.StatusOf(alg)
			if status == pqc.QuantumVulnerable || status == pqc.QuantumWeakened {
				weak = append(weak, alg)
			}
		}
	}
	if len(weak) == 0 {
		return nil
	}
	return []model.HealthFinding{{
		RuleID:      "CFG-003",
		Title:       "SSHD allows weak ciphers / MACs / kex algorithms",
		Severity:    model.SeverityHigh,
		Category:    model.CategoryCipher,
		Detail:      "Configured algorithms include known-weak or quantum-vulnerable entries: " + strings.Join(weak, ", "),
		Remediation: "Remove weak algorithms; use modern defaults (aes-256-gcm, hmac-sha2-512, curve25519-sha256).",
		Deduction:   30,
	}}
}

// CFG-004: Java disabled-algorithms list empty / missing.
func checkConfigJavaDisabledAlgorithms(cfg *model.CryptoConfig) []model.HealthFinding {
	if cfg.ConfigType != "java-security" {
		return nil
	}
	val, present := cfg.Settings["jdk.tls.disabledAlgorithms"]
	if !present || strings.TrimSpace(val) == "" {
		return []model.HealthFinding{{
			RuleID:      "CFG-004",
			Title:       "Java disabledAlgorithms list is empty or missing",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryGovernance,
			Detail:      "jdk.tls.disabledAlgorithms has been cleared or removed. Without it, JVM allows deprecated protocols and weak algorithms.",
			Remediation: "Restore the Oracle/OpenJDK default disabledAlgorithms list or a hardened superset.",
			Deduction:   15,
		}}
	}
	return nil
}
