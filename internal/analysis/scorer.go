package analysis

import (
	"time"

	"github.com/cyberflag-ai/cipherflag/internal/model"
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
		} else if cert.KeySizeBits < 4096 {
			findings = append(findings, model.HealthFinding{
				RuleID:      "KEY-002",
				Title:       "RSA key is 2048 bits (acceptable, not ideal)",
				Severity:    model.SeverityLow,
				Category:    model.CategoryKeyStrength,
				Detail:      "2048-bit RSA meets minimum requirements but 4096-bit is recommended.",
				Remediation: "Consider upgrading to 4096-bit RSA or ECDSA P-256+.",
				Deduction:   2,
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
