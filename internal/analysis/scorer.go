package analysis

import (
	"strings"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// ScoreCertificate evaluates a certificate and produces a HealthReport.
func ScoreCertificate(cert *model.Certificate) *model.HealthReport {
	var findings []model.HealthFinding
	score := 100
	immediateFail := false

	// ── Expiration rules ────────────────────────────────────────────
	findings = append(findings, checkExpiration(cert)...)

	// ── Key strength rules ──────────────────────────────────────────
	findings = append(findings, checkKeyStrength(cert)...)

	// ── Signature algorithm rules ───────────────────────────────────
	findings = append(findings, checkSignature(cert)...)

	// ── Chain/trust rules ───────────────────────────────────────────
	findings = append(findings, checkChainBasic(cert)...)

	// ── Revocation infrastructure ───────────────────────────────────
	findings = append(findings, checkRevocation(cert)...)

	// ── Certificate Transparency ────────────────────────────────────
	findings = append(findings, checkTransparency(cert)...)

	// ── Wildcard & infrastructure ───────────────────────────────────
	findings = append(findings, checkWildcard(cert)...)

	// ── Crypto agility ──────────────────────────────────────────────
	findings = append(findings, checkAgility(cert)...)

	// Apply deductions
	for _, f := range findings {
		score -= f.Deduction
		if f.ImmediateFail {
			immediateFail = true
		}
	}
	if score < 0 {
		score = 0
	}

	grade := model.ScoreToGrade(score, immediateFail)

	return &model.HealthReport{
		CertFingerprint: cert.FingerprintSHA256,
		Grade:           grade,
		Score:           score,
		Findings:        findings,
		ScoredAt:        time.Now(),
	}
}

// ── Expiration ──────────────────────────────────────────────────────────────

func checkExpiration(cert *model.Certificate) []model.HealthFinding {
	var findings []model.HealthFinding
	days := cert.DaysUntilExpiry()

	if cert.IsExpired() {
		findings = append(findings, model.HealthFinding{
			RuleID:        "EXP-001",
			Title:         "Certificate has expired",
			Severity:      model.SeverityCritical,
			Category:      model.CategoryExpiration,
			Detail:        "This certificate is no longer valid.",
			Remediation:   "Renew the certificate immediately.",
			Deduction:     100,
			ImmediateFail: true,
		})
	} else if days <= 7 {
		findings = append(findings, model.HealthFinding{
			RuleID:      "EXP-002",
			Title:       "Certificate expires within 7 days",
			Severity:    model.SeverityCritical,
			Category:    model.CategoryExpiration,
			Detail:      "Expiration is imminent.",
			Remediation: "Renew the certificate immediately.",
			Deduction:   40,
		})
	} else if days <= 30 {
		findings = append(findings, model.HealthFinding{
			RuleID:      "EXP-003",
			Title:       "Certificate expires within 30 days",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryExpiration,
			Detail:      "Certificate will expire soon.",
			Remediation: "Plan certificate renewal.",
			Deduction:   20,
		})
	} else if days <= 90 {
		findings = append(findings, model.HealthFinding{
			RuleID:      "EXP-004",
			Title:       "Certificate expires within 90 days",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryExpiration,
			Detail:      "Certificate approaching expiration.",
			Remediation: "Schedule certificate renewal.",
			Deduction:   5,
		})
	}

	// Check overly long validity
	validityDays := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
	if validityDays > 398 && !cert.IsCA {
		findings = append(findings, model.HealthFinding{
			RuleID:      "EXP-005",
			Title:       "Certificate validity exceeds 398 days",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryExpiration,
			Detail:      "Apple, Mozilla, and Google reject certs with >398 day validity.",
			Remediation: "Issue shorter-lived certificates.",
			Deduction:   10,
		})
	}
	// 200-day limit (2026 industry direction)
	if validityDays > 200 && validityDays <= 398 && !cert.IsCA {
		findings = append(findings, model.HealthFinding{
			RuleID:      "EXP-006",
			Title:       "Certificate validity exceeds 200 days",
			Severity:    model.SeverityLow,
			Category:    model.CategoryExpiration,
			Detail:      "Industry is moving toward 200-day maximum validity. Certificates over 200 days reduce crypto-agility.",
			Remediation: "Consider issuing shorter-lived certificates to prepare for upcoming CA/B Forum requirements.",
			Deduction:   3,
		})
	}

	return findings
}

// ── Key Strength ────────────────────────────────────────────────────────────

func checkKeyStrength(cert *model.Certificate) []model.HealthFinding {
	var findings []model.HealthFinding

	switch cert.KeyAlgorithm {
	case model.KeyRSA:
		if cert.KeySizeBits < 2048 {
			findings = append(findings, model.HealthFinding{
				RuleID:        "KEY-001",
				Title:         "RSA key is less than 2048 bits",
				Severity:      model.SeverityCritical,
				Category:      model.CategoryKeyStrength,
				Detail:        "RSA keys under 2048 bits are considered insecure.",
				Remediation:   "Reissue with at least 2048-bit RSA key or switch to ECDSA.",
				Deduction:     50,
				ImmediateFail: true,
			})
		} else if cert.KeySizeBits < 3072 {
			findings = append(findings, model.HealthFinding{
				RuleID:      "KEY-002",
				Title:       "RSA key is 2048 bits (below 2026 recommendation)",
				Severity:    model.SeverityLow,
				Category:    model.CategoryKeyStrength,
				Detail:      "2048-bit RSA meets minimum requirements but 3072-bit is the 2026 NIST recommendation.",
				Remediation: "Upgrade to 3072-bit or 4096-bit RSA, or switch to ECDSA P-256+.",
				Deduction:   3,
			})
		} else if cert.KeySizeBits < 4096 {
			findings = append(findings, model.HealthFinding{
				RuleID:      "KEY-005",
				Title:       "RSA key is 3072 bits (good, not maximum)",
				Severity:    model.SeverityInfo,
				Category:    model.CategoryKeyStrength,
				Detail:      "3072-bit RSA meets 2026 recommendations. 4096-bit provides additional margin.",
				Remediation: "No action required. Consider 4096-bit for high-value certificates.",
				Deduction:   0,
			})
		}
	case model.KeyECDSA:
		if cert.KeySizeBits < 256 {
			findings = append(findings, model.HealthFinding{
				RuleID:        "KEY-003",
				Title:         "ECDSA key is less than 256 bits",
				Severity:      model.SeverityCritical,
				Category:      model.CategoryKeyStrength,
				Detail:        "ECDSA keys under 256 bits provide insufficient security.",
				Remediation:   "Reissue with at least P-256 curve.",
				Deduction:     50,
				ImmediateFail: true,
			})
		}
	case model.KeyUnknown:
		findings = append(findings, model.HealthFinding{
			RuleID:      "KEY-004",
			Title:       "Unknown key algorithm",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryKeyStrength,
			Detail:      "Could not determine key algorithm.",
			Remediation: "Verify the certificate key algorithm manually.",
			Deduction:   10,
		})
	}

	return findings
}

// ── Signature Algorithm ─────────────────────────────────────────────────────

func checkSignature(cert *model.Certificate) []model.HealthFinding {
	var findings []model.HealthFinding

	switch cert.SignatureAlgorithm {
	case model.SigSHA1WithRSA:
		findings = append(findings, model.HealthFinding{
			RuleID:        "SIG-001",
			Title:         "Certificate uses SHA-1 signature",
			Severity:      model.SeverityCritical,
			Category:      model.CategorySignature,
			Detail:        "SHA-1 is cryptographically broken and rejected by all major browsers.",
			Remediation:   "Reissue certificate with SHA-256 or stronger signature.",
			Deduction:     50,
			ImmediateFail: true,
		})
	case model.SigMD5WithRSA:
		findings = append(findings, model.HealthFinding{
			RuleID:        "SIG-002",
			Title:         "Certificate uses MD5 signature",
			Severity:      model.SeverityCritical,
			Category:      model.CategorySignature,
			Detail:        "MD5 has known collision attacks and is completely insecure.",
			Remediation:   "Reissue certificate with SHA-256 or stronger signature.",
			Deduction:     100,
			ImmediateFail: true,
		})
	case model.SigUnknown:
		findings = append(findings, model.HealthFinding{
			RuleID:      "SIG-003",
			Title:       "Unknown signature algorithm",
			Severity:    model.SeverityMedium,
			Category:    model.CategorySignature,
			Detail:      "Could not determine signature algorithm.",
			Remediation: "Verify the certificate signature algorithm manually.",
			Deduction:   10,
		})
	}

	return findings
}

// ── Chain/Trust ──────────────────────────────────────────────────────────────

func checkChainBasic(cert *model.Certificate) []model.HealthFinding {
	var findings []model.HealthFinding

	if cert.IsSelfSigned() && !cert.IsCA {
		findings = append(findings, model.HealthFinding{
			RuleID:      "CHN-001",
			Title:       "Self-signed end-entity certificate",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryChain,
			Detail:      "Self-signed certificates are not trusted by browsers or clients.",
			Remediation: "Obtain a certificate from a trusted Certificate Authority.",
			Deduction:   30,
		})
	}

	return findings
}

// ── Revocation ──────────────────────────────────────────────────────────────

func checkRevocation(cert *model.Certificate) []model.HealthFinding {
	var findings []model.HealthFinding

	hasOCSP := len(cert.OCSPResponderURLs) > 0
	hasCRL := len(cert.CRLDistributionPoints) > 0

	if !cert.IsCA && !hasOCSP && !hasCRL {
		findings = append(findings, model.HealthFinding{
			RuleID:      "REV-001",
			Title:       "No revocation mechanism configured",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryRevocation,
			Detail:      "Certificate has neither OCSP nor CRL distribution points.",
			Remediation: "Ensure issuing CA provides OCSP and/or CRL endpoints.",
			Deduction:   15,
		})
	} else if !cert.IsCA && !hasOCSP {
		findings = append(findings, model.HealthFinding{
			RuleID:      "REV-002",
			Title:       "No OCSP responder configured",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryRevocation,
			Detail:      "OCSP provides faster revocation checking than CRL.",
			Remediation: "Ensure issuing CA provides OCSP responder URLs.",
			Deduction:   5,
		})
	}

	return findings
}

// ── Certificate Transparency ────────────────────────────────────────────────

func checkTransparency(cert *model.Certificate) []model.HealthFinding {
	var findings []model.HealthFinding

	if !cert.IsCA && len(cert.SCTs) == 0 {
		findings = append(findings, model.HealthFinding{
			RuleID:      "SCT-001",
			Title:       "No Signed Certificate Timestamps (SCTs)",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryTransparency,
			Detail:      "Chrome requires SCTs for Certificate Transparency compliance.",
			Remediation: "Ensure your CA logs certificates to CT logs.",
			Deduction:   10,
		})
	}

	return findings
}

// ── Wildcard & Infrastructure ──────────────────────────────────────────────

func checkWildcard(cert *model.Certificate) []model.HealthFinding {
	var findings []model.HealthFinding

	if cert.IsCA {
		return findings
	}

	// Check CN for wildcard
	hasWildcard := strings.HasPrefix(cert.Subject.CommonName, "*.")

	// Check SANs for wildcards
	wildcardSANs := 0
	for _, san := range cert.SubjectAltNames {
		if strings.HasPrefix(san, "*.") {
			hasWildcard = true
			wildcardSANs++
		}
	}

	if hasWildcard {
		detail := "Wildcard certificate detected."
		if wildcardSANs > 1 {
			detail = "Wildcard certificate with multiple wildcard SANs. Each wildcard SAN increases the blast radius if the private key is compromised."
		}
		severity := model.SeverityMedium
		deduction := 5
		if wildcardSANs > 3 {
			severity = model.SeverityHigh
			deduction = 10
		}

		findings = append(findings, model.HealthFinding{
			RuleID:      "WLD-001",
			Title:       "Wildcard certificate",
			Severity:    severity,
			Category:    model.CategoryWildcard,
			Detail:      detail,
			Remediation: "Consider using specific domain certificates instead of wildcards to reduce blast radius. Use separate certificates per service.",
			Deduction:   deduction,
		})
	}

	// Check for overly broad wildcard (e.g., *.com, *.co.uk — only one label before TLD)
	if hasWildcard {
		cn := cert.Subject.CommonName
		if strings.HasPrefix(cn, "*.") {
			parts := strings.Split(cn[2:], ".")
			if len(parts) <= 1 {
				findings = append(findings, model.HealthFinding{
					RuleID:        "WLD-002",
					Title:         "Overly broad wildcard certificate",
					Severity:      model.SeverityCritical,
					Category:      model.CategoryWildcard,
					Detail:        "Wildcard covers an entire TLD or very broad domain.",
					Remediation:   "Issue certificates for specific subdomains.",
					Deduction:     30,
					ImmediateFail: true,
				})
			}
		}
	}

	return findings
}

// ── Crypto Agility ─────────────────────────────────────────────────────────

func checkAgility(cert *model.Certificate) []model.HealthFinding {
	var findings []model.HealthFinding

	if cert.IsCA {
		return findings
	}

	// Check if certificate is likely ACME-managed (Let's Encrypt, ZeroSSL, Buypass Go)
	issuerOrg := strings.ToLower(cert.Issuer.Organization)
	issuerCN := strings.ToLower(cert.Issuer.CommonName)
	isACME := strings.Contains(issuerOrg, "let's encrypt") ||
		strings.Contains(issuerOrg, "zerossl") ||
		strings.Contains(issuerOrg, "buypass") ||
		strings.Contains(issuerCN, "let's encrypt") ||
		strings.Contains(issuerCN, "zerossl")

	// Certificates with > 1 year validity are likely not automated
	validityDays := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
	if validityDays > 365 && !isACME {
		findings = append(findings, model.HealthFinding{
			RuleID:      "AGI-001",
			Title:       "Certificate not using automated issuance",
			Severity:    model.SeverityLow,
			Category:    model.CategoryAgility,
			Detail:      "Certificate has >1 year validity and is not from an ACME CA, suggesting manual issuance. Industry is moving toward 45-day certificates requiring automation.",
			Remediation: "Implement ACME-based certificate automation (Let's Encrypt, ZeroSSL) or integrate with your CLM platform's auto-renewal.",
			Deduction:   2,
		})
	}

	// Short-lived certs from ACME CAs are good — no finding needed.
	// But flag ACME certs with unusually long validity (> 90 days means something is off)
	if isACME && validityDays > 100 {
		findings = append(findings, model.HealthFinding{
			RuleID:      "AGI-002",
			Title:       "ACME certificate with unusually long validity",
			Severity:    model.SeverityLow,
			Category:    model.CategoryAgility,
			Detail:      "This certificate appears to be from an ACME CA but has >100 day validity, which is unusual for automated issuance.",
			Remediation: "Verify ACME renewal is configured correctly.",
			Deduction:   2,
		})
	}

	// FIPS 140-3 readiness: flag legacy curves and algorithms
	if cert.KeyAlgorithm == model.KeyECDSA && cert.KeySizeBits < 256 {
		// Already caught by KEY-003, skip
	} else if cert.SignatureAlgorithm == model.SigSHA384WithRSA || cert.SignatureAlgorithm == model.SigSHA512WithRSA {
		// Strong signatures, FIPS-ready — no finding
	} else if cert.SignatureAlgorithm == model.SigSHA256WithRSA || cert.SignatureAlgorithm == model.SigECDSAWithSHA256 || cert.SignatureAlgorithm == model.SigECDSAWithSHA384 || cert.SignatureAlgorithm == model.SigEd25519Sig {
		// Acceptable for FIPS 140-3 — no finding
	} else if cert.SignatureAlgorithm != model.SigSHA1WithRSA && cert.SignatureAlgorithm != model.SigMD5WithRSA && cert.SignatureAlgorithm != model.SigUnknown {
		// Catch anything not in the known-good or known-bad list
		findings = append(findings, model.HealthFinding{
			RuleID:      "AGI-003",
			Title:       "Non-standard signature algorithm",
			Severity:    model.SeverityLow,
			Category:    model.CategoryAgility,
			Detail:      "Signature algorithm may not be FIPS 140-3 validated.",
			Remediation: "Verify this algorithm is approved for your compliance requirements.",
			Deduction:   2,
		})
	}

	return findings
}
