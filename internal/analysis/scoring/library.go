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

// ScoreLibrary evaluates a crypto library and produces an
// AssetHealthReport. Rules: LIB-001, LIB-002 (CVE-based),
// LIB-003 (EOL), LIB-004 (PQC), LIB-005 (FIPS).
func ScoreLibrary(lib *model.CryptoLibrary, cves []model.CryptoLibraryCVE) *model.AssetHealthReport {
	var findings []model.HealthFinding
	score := 100
	immediateFail := false

	findings = append(findings, checkLibraryCVE(lib, cves)...)
	findings = append(findings, checkLibraryEOL(lib)...)
	findings = append(findings, checkLibraryPQC(lib)...)
	findings = append(findings, checkLibraryFIPS(lib)...)

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
		AssetType: "crypto_library",
		AssetID:   lib.ID,
		Grade:     string(model.ScoreToGrade(score, immediateFail)),
		Score:     score,
		Findings:  findings,
		PQCStatus: ForLibrary(lib),
		ScoredAt:  time.Now(),
	}
}

// LIB-001: Critical CVE in crypto library (ImmediateFail).
// LIB-002: High or medium CVE in crypto library.
// At most one of LIB-001 or LIB-002 fires per call; LIB-001 suppresses LIB-002.
//
// ScopeDeadline is derived from the finding severity:
//   Critical → now + 7d, High/Medium → now + 30d. Operators can reset the
//   default by editing the finding's deadline after scoring (future phase).
func checkLibraryCVE(lib *model.CryptoLibrary, cves []model.CryptoLibraryCVE) []model.HealthFinding {
	var critical, other []model.CryptoLibraryCVE
	for _, cve := range cves {
		if !matchesVersionRange(lib.Version, cve.VersionRange) {
			continue
		}
		switch cve.Severity {
		case "Critical":
			critical = append(critical, cve)
		case "High", "Medium":
			other = append(other, cve)
		}
	}
	if len(critical) > 0 {
		deadline := time.Now().Add(7 * 24 * time.Hour)
		return []model.HealthFinding{{
			RuleID:        "LIB-001",
			Title:         "Critical CVE in crypto library",
			Severity:      model.SeverityCritical,
			Category:      model.CategoryAgility,
			Detail:        formatCVEList(critical),
			Remediation:   "Patch to the vendor-recommended fixed version immediately.",
			Deduction:     50,
			ImmediateFail: true,
			ScopeDeadline: &deadline,
		}}
	}
	if len(other) > 0 {
		deadline := time.Now().Add(30 * 24 * time.Hour)
		return []model.HealthFinding{{
			RuleID:        "LIB-002",
			Title:         "High or medium CVE in crypto library",
			Severity:      model.SeverityHigh,
			Category:      model.CategoryAgility,
			Detail:        formatCVEList(other),
			Remediation:   "Review CVE advisories and upgrade to the fixed release.",
			Deduction:     25,
			ScopeDeadline: &deadline,
		}}
	}
	return nil
}

// formatCVEList builds the Detail string for LIB-001 / LIB-002.
// Format: "CVE-YYYY-NNNNN (description); CVE-YYYY-NNNNN (description)"
func formatCVEList(cves []model.CryptoLibraryCVE) string {
	parts := make([]string, len(cves))
	for i, c := range cves {
		if c.Description != "" {
			parts[i] = c.CVEID + " (" + c.Description + ")"
		} else {
			parts[i] = c.CVEID
		}
	}
	return strings.Join(parts, "; ")
}

// LIB-003: Library version is EOL / deprecated.
// ScopeDeadline defaults to now + 90 days — EOL libraries aren't
// emergency but should be remediated within a quarter.
func checkLibraryEOL(lib *model.CryptoLibrary) []model.HealthFinding {
	name := strings.ToLower(lib.LibraryName)
	for _, entry := range eolStarterMap {
		if entry.LibraryName == name && strings.HasPrefix(lib.Version, entry.VersionPrefix) {
			deadline := time.Now().Add(90 * 24 * time.Hour)
			return []model.HealthFinding{{
				RuleID:        "LIB-003",
				Title:         "Library version is EOL / deprecated",
				Severity:      model.SeverityHigh,
				Category:      model.CategoryAgility,
				Detail:        entry.Reason,
				Remediation:   "Upgrade to a supported release; check upstream security advisories for migration notes.",
				Deduction:     35,
				ScopeDeadline: &deadline,
				Evidence:      map[string]any{"source_url": entry.Source},
			}}
		}
	}
	return nil
}

// LIB-004: Library does not support PQC algorithms.
func checkLibraryPQC(lib *model.CryptoLibrary) []model.HealthFinding {
	if !lib.PQCCapable {
		return []model.HealthFinding{{
			RuleID:      "LIB-004",
			Title:       "Library does not support post-quantum algorithms",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryAgility,
			Detail:      "The library was not discovered with PQC algorithm support.",
			Remediation: "Track upstream PQC support or consider a PQC-capable alternative (e.g., liboqs-integrated OpenSSL 3.2+).",
			Deduction:   10,
		}}
	}
	return nil
}

// LIB-005: FIPS-validated library (positive indicator).
func checkLibraryFIPS(lib *model.CryptoLibrary) []model.HealthFinding {
	name := strings.ToLower(lib.LibraryName)
	for _, entry := range fipsStarterMap {
		if entry.LibraryName == name && fipsVersionMatch(entry.VersionPrefix, lib.Version) {
			return []model.HealthFinding{{
				RuleID:   "LIB-005",
				Title:    "FIPS-validated library version",
				Severity: model.SeverityInfo,
				Category: model.CategoryGovernance,
				Detail:   entry.Note,
				Evidence: map[string]any{"source_url": entry.Source},
			}}
		}
	}
	return nil
}
