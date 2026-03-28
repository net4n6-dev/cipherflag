package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cyberflag-ai/cipherflag/internal/model"
)

// ── Domain Report ───────────────────────────────────────────────────────────

func (s *PostgresStore) GetDomainReport(ctx context.Context, domain string) (*model.DomainReport, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))

	// Extract parent domain for wildcard matching (e.g., api.acme.com → acme.com)
	parent := domain
	if parts := strings.SplitN(domain, ".", 2); len(parts) == 2 {
		parent = parts[1]
	}

	report := &model.DomainReport{
		Summary:      model.DomainReportSummary{Domain: domain},
		Certificates: []model.DomainReportCert{},
		Deployments:  []model.DomainReportDeployment{},
		Findings:     []model.DomainReportFinding{},
		Wildcards:    []model.DomainReportWildcard{},
	}

	// Query matching certificates with match_type classification
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT ON (c.fingerprint_sha256)
			c.fingerprint_sha256,
			c.subject_cn,
			c.issuer_cn,
			COALESCE(h.grade, '?'),
			c.key_algorithm,
			c.key_size_bits,
			to_char(c.not_after, 'YYYY-MM-DD'),
			EXTRACT(DAY FROM c.not_after - NOW())::int,
			to_char(c.first_seen, 'YYYY-MM-DD'),
			to_char(c.last_seen, 'YYYY-MM-DD'),
			CASE
				WHEN LOWER(c.subject_cn) = $1 THEN 'exact'
				WHEN LOWER(c.subject_cn) LIKE '*.' || $2 THEN 'wildcard'
				WHEN EXISTS (
					SELECT 1 FROM jsonb_array_elements_text(c.subject_alt_names) san
					WHERE san ILIKE '%' || $1 || '%'
				) THEN 'san'
				ELSE 'subdomain'
			END as match_type,
			c.source_discovery
		FROM certificates c
		LEFT JOIN health_reports h ON c.fingerprint_sha256 = h.cert_fingerprint
		WHERE LOWER(c.subject_cn) = $1
		   OR LOWER(c.subject_cn) LIKE '*.' || $2
		   OR EXISTS (
				SELECT 1 FROM jsonb_array_elements_text(c.subject_alt_names) san
				WHERE san ILIKE '%' || $1 || '%'
		   )
		   OR LOWER(c.subject_cn) LIKE '%.' || $1
		ORDER BY c.fingerprint_sha256
	`, domain, parent)
	if err != nil {
		return nil, fmt.Errorf("domain report certs: %w", err)
	}
	defer rows.Close()

	var fingerprints []string
	for rows.Next() {
		var cert model.DomainReportCert
		if err := rows.Scan(
			&cert.Fingerprint, &cert.SubjectCN, &cert.IssuerCN, &cert.Grade,
			&cert.KeyAlgorithm, &cert.KeySizeBits, &cert.NotAfter, &cert.DaysRemaining,
			&cert.FirstSeen, &cert.LastSeen, &cert.MatchType, &cert.Source,
		); err != nil {
			return nil, fmt.Errorf("domain report scan cert: %w", err)
		}
		report.Certificates = append(report.Certificates, cert)
		fingerprints = append(fingerprints, cert.Fingerprint)
	}

	if len(fingerprints) == 0 {
		return report, nil
	}

	// Query deployments for matched certificates
	depRows, err := s.pool.Query(ctx, `
		SELECT
			o.cert_fingerprint,
			COALESCE(o.server_name, ''),
			o.server_ip,
			o.server_port,
			COALESCE(o.negotiated_version, ''),
			COALESCE(o.negotiated_cipher, ''),
			to_char(o.observed_at, 'YYYY-MM-DD')
		FROM observations o
		WHERE o.cert_fingerprint = ANY($1)
		ORDER BY o.observed_at DESC
	`, fingerprints)
	if err != nil {
		return nil, fmt.Errorf("domain report deployments: %w", err)
	}
	defer depRows.Close()

	for depRows.Next() {
		var dep model.DomainReportDeployment
		if err := depRows.Scan(
			&dep.CertFingerprint, &dep.ServerName, &dep.ServerIP,
			&dep.ServerPort, &dep.TLSVersion, &dep.Cipher, &dep.LastObserved,
		); err != nil {
			return nil, fmt.Errorf("domain report scan deployment: %w", err)
		}
		report.Deployments = append(report.Deployments, dep)
	}

	// Aggregate findings from health reports
	findRows, err := s.pool.Query(ctx, `
		SELECT findings FROM health_reports
		WHERE cert_fingerprint = ANY($1) AND findings IS NOT NULL
	`, fingerprints)
	if err != nil {
		return nil, fmt.Errorf("domain report findings query: %w", err)
	}
	defer findRows.Close()

	type findingKey struct {
		Title    string
		Severity string
		Category string
	}
	findingAgg := map[findingKey]*model.DomainReportFinding{}

	for findRows.Next() {
		var findingsJSON []byte
		if err := findRows.Scan(&findingsJSON); err != nil {
			return nil, fmt.Errorf("domain report scan findings: %w", err)
		}
		var findings []model.HealthFinding
		if err := json.Unmarshal(findingsJSON, &findings); err != nil {
			continue
		}
		for _, f := range findings {
			key := findingKey{Title: f.Title, Severity: string(f.Severity), Category: string(f.Category)}
			if agg, ok := findingAgg[key]; ok {
				agg.AffectedCount++
				agg.TotalDeduction += f.Deduction
			} else {
				findingAgg[key] = &model.DomainReportFinding{
					Title:          f.Title,
					Severity:       string(f.Severity),
					Category:       string(f.Category),
					AffectedCount:  1,
					TotalDeduction: f.Deduction,
				}
			}
		}
	}

	for _, f := range findingAgg {
		report.Findings = append(report.Findings, *f)
	}

	// Filter wildcards from matched certs
	for _, cert := range report.Certificates {
		if strings.HasPrefix(cert.SubjectCN, "*.") {
			// Fetch SANs for this wildcard cert
			var sansJSON []byte
			s.pool.QueryRow(ctx,
				"SELECT COALESCE(subject_alt_names, '[]'::jsonb) FROM certificates WHERE fingerprint_sha256 = $1",
				cert.Fingerprint,
			).Scan(&sansJSON)
			var sans []string
			json.Unmarshal(sansJSON, &sans)
			if sans == nil {
				sans = []string{}
			}
			report.Wildcards = append(report.Wildcards, model.DomainReportWildcard{
				Fingerprint: cert.Fingerprint,
				SubjectCN:   cert.SubjectCN,
				SANs:        sans,
				Grade:       cert.Grade,
				NotAfter:    cert.NotAfter,
			})
		}
	}

	// Build summary
	report.Summary.TotalCerts = len(report.Certificates)
	report.Summary.WildcardCount = len(report.Wildcards)
	worstGrade := "A+"
	for _, cert := range report.Certificates {
		if cert.DaysRemaining < 0 {
			report.Summary.Expired++
		} else if cert.DaysRemaining <= 30 {
			report.Summary.Expiring30d++
		}
		if isWorseGrade(cert.Grade, worstGrade) {
			worstGrade = cert.Grade
		}
	}
	report.Summary.WorstGrade = worstGrade

	return report, nil
}

// isWorseGrade returns true if a is a worse grade than b.
func isWorseGrade(a, b string) bool {
	order := map[string]int{"A+": 0, "A": 1, "B": 2, "C": 3, "D": 4, "F": 5, "?": 6}
	ao, aOk := order[a]
	bo, bOk := order[b]
	if !aOk {
		ao = 6
	}
	if !bOk {
		bo = 6
	}
	return ao > bo
}

// ── CA Report ───────────────────────────────────────────────────────────────

func (s *PostgresStore) GetCAReport(ctx context.Context, fingerprint string, issuerCN string) (*model.CAReport, error) {
	report := &model.CAReport{
		Summary: model.CAReportSummary{
			GradeDistribution: map[string]int{},
		},
		Certificates: []model.CAReportCert{},
		Crypto: model.CAReportCrypto{
			KeyAlgorithms:      map[string]int{},
			SignatureAlgorithms: map[string]int{},
			KeySizes:           map[string]int{},
		},
		Chain: model.CAReportChain{
			IssuesTo: []model.CAReportChainEntry{},
		},
		Findings: []model.DomainReportFinding{},
	}

	// Find the CA certificate
	var caFP, caCN, caOrg, caKeyAlg, caIssuerCN string
	var caKeySize int
	var caNotBefore, caNotAfter, caGrade string
	var caIsCA bool

	var caQuery string
	var caArgs []any
	if fingerprint != "" {
		caQuery = `
			SELECT c.fingerprint_sha256, c.subject_cn, COALESCE(NULLIF(c.subject_org, ''), ''),
				c.key_algorithm, c.key_size_bits,
				to_char(c.not_before, 'YYYY-MM-DD'), to_char(c.not_after, 'YYYY-MM-DD'),
				COALESCE(h.grade, '?'), c.is_ca, c.issuer_cn
			FROM certificates c
			LEFT JOIN health_reports h ON c.fingerprint_sha256 = h.cert_fingerprint
			WHERE c.fingerprint_sha256 = $1
		`
		caArgs = []any{fingerprint}
	} else {
		caQuery = `
			SELECT c.fingerprint_sha256, c.subject_cn, COALESCE(NULLIF(c.subject_org, ''), ''),
				c.key_algorithm, c.key_size_bits,
				to_char(c.not_before, 'YYYY-MM-DD'), to_char(c.not_after, 'YYYY-MM-DD'),
				COALESCE(h.grade, '?'), c.is_ca, c.issuer_cn
			FROM certificates c
			LEFT JOIN health_reports h ON c.fingerprint_sha256 = h.cert_fingerprint
			WHERE c.subject_cn ILIKE $1 AND c.is_ca = true
			ORDER BY c.subject_cn
			LIMIT 1
		`
		caArgs = []any{"%" + issuerCN + "%"}
	}

	err := s.pool.QueryRow(ctx, caQuery, caArgs...).Scan(
		&caFP, &caCN, &caOrg, &caKeyAlg, &caKeySize,
		&caNotBefore, &caNotAfter, &caGrade, &caIsCA, &caIssuerCN,
	)
	if err != nil {
		return nil, fmt.Errorf("ca report: CA not found: %w", err)
	}

	isSelfSigned := caCN == caIssuerCN
	chainPosition := "intermediate"
	if isSelfSigned {
		chainPosition = "root"
	}

	report.CA = model.CAReportIdentity{
		Fingerprint:   caFP,
		SubjectCN:     caCN,
		Organization:  caOrg,
		KeyAlgorithm:  caKeyAlg,
		KeySizeBits:   caKeySize,
		NotBefore:     caNotBefore,
		NotAfter:      caNotAfter,
		Grade:         caGrade,
		IsSelfSigned:  isSelfSigned,
		ChainPosition: chainPosition,
	}

	// Query all certs issued by this CA
	issuedRows, err := s.pool.Query(ctx, `
		SELECT
			c.fingerprint_sha256,
			c.subject_cn,
			COALESCE(h.grade, '?'),
			c.key_algorithm,
			c.key_size_bits,
			to_char(c.not_after, 'YYYY-MM-DD'),
			EXTRACT(DAY FROM c.not_after - NOW())::int,
			to_char(c.first_seen, 'YYYY-MM-DD'),
			to_char(c.last_seen, 'YYYY-MM-DD'),
			c.source_discovery,
			c.subject_cn LIKE '*.%' as is_wildcard,
			c.signature_algorithm
		FROM certificates c
		LEFT JOIN health_reports h ON c.fingerprint_sha256 = h.cert_fingerprint
		WHERE c.issuer_cn = $1 AND c.fingerprint_sha256 != $2
		ORDER BY c.not_after ASC
	`, caCN, caFP)
	if err != nil {
		return nil, fmt.Errorf("ca report issued certs: %w", err)
	}
	defer issuedRows.Close()

	var issuedFingerprints []string
	for issuedRows.Next() {
		var cert model.CAReportCert
		var sigAlg string
		if err := issuedRows.Scan(
			&cert.Fingerprint, &cert.SubjectCN, &cert.Grade,
			&cert.KeyAlgorithm, &cert.KeySizeBits, &cert.NotAfter,
			&cert.DaysRemaining, &cert.FirstSeen, &cert.LastSeen,
			&cert.Source, &cert.IsWildcard, &sigAlg,
		); err != nil {
			return nil, fmt.Errorf("ca report scan cert: %w", err)
		}
		report.Certificates = append(report.Certificates, cert)
		issuedFingerprints = append(issuedFingerprints, cert.Fingerprint)

		// Aggregate summary
		report.Summary.GradeDistribution[cert.Grade]++
		if cert.DaysRemaining < 0 {
			report.Summary.Expired++
		} else if cert.DaysRemaining <= 30 {
			report.Summary.Expiring30d++
		} else if cert.DaysRemaining <= 90 {
			report.Summary.Expiring90d++
		}
		if cert.IsWildcard {
			report.Summary.WildcardCount++
		}

		// Crypto aggregation
		report.Crypto.KeyAlgorithms[cert.KeyAlgorithm]++
		report.Crypto.SignatureAlgorithms[sigAlg]++
		report.Crypto.KeySizes[fmt.Sprintf("%d", cert.KeySizeBits)]++
	}

	report.Summary.TotalIssued = len(report.Certificates)

	// Aggregate findings from health reports of issued certs
	if len(issuedFingerprints) > 0 {
		findRows, err := s.pool.Query(ctx, `
			SELECT findings FROM health_reports
			WHERE cert_fingerprint = ANY($1) AND findings IS NOT NULL
		`, issuedFingerprints)
		if err != nil {
			return nil, fmt.Errorf("ca report findings: %w", err)
		}
		defer findRows.Close()

		type findingKey struct {
			Title    string
			Severity string
			Category string
		}
		findingAgg := map[findingKey]*model.DomainReportFinding{}

		for findRows.Next() {
			var findingsJSON []byte
			if err := findRows.Scan(&findingsJSON); err != nil {
				continue
			}
			var findings []model.HealthFinding
			if err := json.Unmarshal(findingsJSON, &findings); err != nil {
				continue
			}
			for _, f := range findings {
				key := findingKey{Title: f.Title, Severity: string(f.Severity), Category: string(f.Category)}
				if agg, ok := findingAgg[key]; ok {
					agg.AffectedCount++
					agg.TotalDeduction += f.Deduction
				} else {
					findingAgg[key] = &model.DomainReportFinding{
						Title:          f.Title,
						Severity:       string(f.Severity),
						Category:       string(f.Category),
						AffectedCount:  1,
						TotalDeduction: f.Deduction,
					}
				}
			}
		}

		for _, f := range findingAgg {
			report.Findings = append(report.Findings, *f)
		}
	}

	// Chain: find who issued this CA
	if !isSelfSigned {
		var issuerFP, issuerCNVal string
		err := s.pool.QueryRow(ctx, `
			SELECT fingerprint_sha256, subject_cn FROM certificates
			WHERE subject_cn = $1 AND is_ca = true AND fingerprint_sha256 != $2
			LIMIT 1
		`, caIssuerCN, caFP).Scan(&issuerFP, &issuerCNVal)
		if err == nil {
			nodeType := "root"
			// Check if the issuer is itself issued by someone else (intermediate)
			var issuerIssuerCN string
			s.pool.QueryRow(ctx, "SELECT issuer_cn FROM certificates WHERE fingerprint_sha256 = $1", issuerFP).Scan(&issuerIssuerCN)
			if issuerIssuerCN != issuerCNVal {
				nodeType = "intermediate"
			}
			report.Chain.IssuedBy = &model.CAReportChainEntry{
				Fingerprint: issuerFP,
				SubjectCN:   issuerCNVal,
				NodeType:    nodeType,
			}
		}
	}

	// Chain: find issued intermediates
	intRows, err := s.pool.Query(ctx, `
		SELECT fingerprint_sha256, subject_cn FROM certificates
		WHERE issuer_cn = $1 AND is_ca = true AND fingerprint_sha256 != $2
	`, caCN, caFP)
	if err == nil {
		defer intRows.Close()
		for intRows.Next() {
			var entry model.CAReportChainEntry
			if err := intRows.Scan(&entry.Fingerprint, &entry.SubjectCN); err == nil {
				entry.NodeType = "intermediate"
				report.Chain.IssuesTo = append(report.Chain.IssuesTo, entry)
			}
		}
	}

	return report, nil
}

// ── Compliance Report ───────────────────────────────────────────────────────

func (s *PostgresStore) GetComplianceReport(ctx context.Context) (*model.ComplianceReport, error) {
	report := &model.ComplianceReport{
		CriticalIssues: []model.ComplianceReportIssue{},
		Priorities:     []model.ComplianceReportPriority{},
		NonAgile:       []model.ComplianceReportNonAgile{},
		Wildcards:      []model.ComplianceReportWildcard{},
		ByCategory:     map[string]int{},
	}

	// Get total cert count
	s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM certificates").Scan(&report.TotalCerts)

	// Query all health reports with findings
	rows, err := s.pool.Query(ctx, `
		SELECT h.cert_fingerprint, c.subject_cn, h.grade, h.score, h.findings
		FROM health_reports h
		JOIN certificates c ON c.fingerprint_sha256 = h.cert_fingerprint
		WHERE h.findings IS NOT NULL
	`)
	if err != nil {
		return nil, fmt.Errorf("compliance report query: %w", err)
	}
	defer rows.Close()

	type priorityKey struct {
		RuleID string
	}
	priorityAgg := map[priorityKey]*model.ComplianceReportPriority{}
	nonAgileFingerprints := map[string]bool{}
	compliant := 0
	nonCompliant := 0

	for rows.Next() {
		var fp, cn, grade string
		var score int
		var findingsJSON []byte
		if err := rows.Scan(&fp, &cn, &grade, &score, &findingsJSON); err != nil {
			return nil, fmt.Errorf("compliance report scan: %w", err)
		}

		var findings []model.HealthFinding
		if err := json.Unmarshal(findingsJSON, &findings); err != nil {
			continue
		}

		hasCriticalHigh := false
		for _, f := range findings {
			sev := string(f.Severity)
			cat := string(f.Category)

			report.ByCategory[cat]++

			if sev == "Critical" || sev == "High" {
				hasCriticalHigh = true
				report.CriticalIssues = append(report.CriticalIssues, model.ComplianceReportIssue{
					Fingerprint: fp,
					SubjectCN:   cn,
					Grade:       grade,
					RuleID:      f.RuleID,
					Title:       f.Title,
					Severity:    sev,
					Category:    cat,
					Remediation: f.Remediation,
				})
			}

			// Aggregate by rule_id for priorities
			key := priorityKey{RuleID: f.RuleID}
			if agg, ok := priorityAgg[key]; ok {
				agg.AffectedCount++
				agg.TotalDeduction += f.Deduction
			} else {
				priorityAgg[key] = &model.ComplianceReportPriority{
					RuleID:         f.RuleID,
					Title:          f.Title,
					Severity:       sev,
					AffectedCount:  1,
					TotalDeduction: f.Deduction,
					Remediation:    f.Remediation,
				}
			}

			// Track non-agile certs
			if f.RuleID == "AGI-001" {
				nonAgileFingerprints[fp] = true
			}
		}

		// Determine compliant: score >= 85 AND no critical/high in key categories
		if score >= 85 && !hasCriticalHigh {
			compliant++
		} else {
			nonCompliant++
		}
	}

	report.Compliant = compliant
	report.NonCompliant = nonCompliant
	if report.TotalCerts > 0 {
		report.ComplianceScore = float64(compliant) / float64(report.TotalCerts) * 100
	}

	// Build priorities list
	for _, p := range priorityAgg {
		report.Priorities = append(report.Priorities, *p)
	}

	// Query non-agile certs
	if len(nonAgileFingerprints) > 0 {
		fps := make([]string, 0, len(nonAgileFingerprints))
		for fp := range nonAgileFingerprints {
			fps = append(fps, fp)
		}
		naRows, err := s.pool.Query(ctx, `
			SELECT
				c.fingerprint_sha256,
				c.subject_cn,
				c.issuer_cn,
				EXTRACT(DAY FROM c.not_after - c.not_before)::int as validity_days,
				c.key_algorithm,
				c.source_discovery
			FROM certificates c
			WHERE c.fingerprint_sha256 = ANY($1)
		`, fps)
		if err == nil {
			defer naRows.Close()
			for naRows.Next() {
				var na model.ComplianceReportNonAgile
				if err := naRows.Scan(
					&na.Fingerprint, &na.SubjectCN, &na.IssuerCN,
					&na.ValidityDays, &na.KeyAlgorithm, &na.Source,
				); err == nil {
					report.NonAgile = append(report.NonAgile, na)
				}
			}
		}
	}

	// Query wildcard certs
	wcRows, err := s.pool.Query(ctx, `
		SELECT
			c.fingerprint_sha256,
			c.subject_cn,
			COALESCE(jsonb_array_length(c.subject_alt_names), 0) as san_count,
			COALESCE(h.grade, '?'),
			to_char(c.not_after, 'YYYY-MM-DD'),
			c.issuer_cn
		FROM certificates c
		LEFT JOIN health_reports h ON c.fingerprint_sha256 = h.cert_fingerprint
		WHERE c.subject_cn LIKE '*.%'
		ORDER BY c.not_after ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("compliance report wildcards: %w", err)
	}
	defer wcRows.Close()

	for wcRows.Next() {
		var wc model.ComplianceReportWildcard
		if err := wcRows.Scan(
			&wc.Fingerprint, &wc.SubjectCN, &wc.SANCount,
			&wc.Grade, &wc.NotAfter, &wc.IssuerCN,
		); err == nil {
			report.Wildcards = append(report.Wildcards, wc)
		}
	}

	return report, nil
}

// ── Expiry Risk Report ──────────────────────────────────────────────────────

func (s *PostgresStore) GetExpiryReport(ctx context.Context, days int) (*model.ExpiryReport, error) {
	report := &model.ExpiryReport{
		Days:              days,
		Certificates:      []model.ExpiryReportCert{},
		ByIssuer:          []model.ExpiryReportByIssuer{},
		ByOwner:           []model.ExpiryReportByOwner{},
		AlreadyExpired:    []model.ExpiryReportGhost{},
		DeploymentsAtRisk: []model.ExpiryReportDeployment{},
	}

	interval := fmt.Sprintf("%d days", days)

	// Query expiring certificates
	rows, err := s.pool.Query(ctx, `
		SELECT
			c.fingerprint_sha256,
			c.subject_cn,
			c.issuer_cn,
			COALESCE(h.grade, '?'),
			EXTRACT(DAY FROM c.not_after - NOW())::int,
			COALESCE(NULLIF(c.subject_org, ''), 'Unknown'),
			COALESCE(NULLIF(c.subject_ou, ''), ''),
			c.key_algorithm,
			c.source_discovery,
			to_char(c.first_seen, 'YYYY-MM-DD'),
			to_char(c.last_seen, 'YYYY-MM-DD')
		FROM certificates c
		LEFT JOIN health_reports h ON c.fingerprint_sha256 = h.cert_fingerprint
		WHERE c.not_after BETWEEN NOW() AND NOW() + $1::interval
		ORDER BY c.not_after ASC
	`, interval)
	if err != nil {
		return nil, fmt.Errorf("expiry report certs: %w", err)
	}
	defer rows.Close()

	var expiringFingerprints []string
	for rows.Next() {
		var cert model.ExpiryReportCert
		if err := rows.Scan(
			&cert.Fingerprint, &cert.SubjectCN, &cert.IssuerCN, &cert.Grade,
			&cert.DaysRemaining, &cert.SubjectOrg, &cert.SubjectOU,
			&cert.KeyAlgorithm, &cert.Source, &cert.FirstSeen, &cert.LastSeen,
		); err != nil {
			return nil, fmt.Errorf("expiry report scan cert: %w", err)
		}
		report.Certificates = append(report.Certificates, cert)
		expiringFingerprints = append(expiringFingerprints, cert.Fingerprint)
	}

	report.TotalExpiring = len(report.Certificates)

	// Group by issuer org
	issuerRows, err := s.pool.Query(ctx, `
		SELECT
			COALESCE(NULLIF(c.issuer_org, ''), 'Unknown') as issuer_org,
			COUNT(*) as cnt,
			COALESCE(MIN(CASE
				WHEN h.grade = 'F' THEN 'F'
				WHEN h.grade = 'D' THEN 'D'
				WHEN h.grade = 'C' THEN 'C'
				WHEN h.grade = 'B' THEN 'B'
				WHEN h.grade = 'A' THEN 'A'
				WHEN h.grade = 'A+' THEN 'A+'
				ELSE '?'
			END), '?') as worst_grade
		FROM certificates c
		LEFT JOIN health_reports h ON c.fingerprint_sha256 = h.cert_fingerprint
		WHERE c.not_after BETWEEN NOW() AND NOW() + $1::interval
		GROUP BY issuer_org
		ORDER BY cnt DESC
	`, interval)
	if err != nil {
		return nil, fmt.Errorf("expiry report by issuer: %w", err)
	}
	defer issuerRows.Close()

	for issuerRows.Next() {
		var bi model.ExpiryReportByIssuer
		if err := issuerRows.Scan(&bi.IssuerOrg, &bi.Count, &bi.WorstGrade); err == nil {
			report.ByIssuer = append(report.ByIssuer, bi)
		}
	}

	// Group by owner (subject_org, subject_ou)
	ownerRows, err := s.pool.Query(ctx, `
		SELECT
			COALESCE(NULLIF(c.subject_org, ''), 'Unknown') as subject_org,
			COALESCE(NULLIF(c.subject_ou, ''), '') as subject_ou,
			COUNT(*) as cnt
		FROM certificates c
		WHERE c.not_after BETWEEN NOW() AND NOW() + $1::interval
		GROUP BY subject_org, subject_ou
		ORDER BY cnt DESC
	`, interval)
	if err != nil {
		return nil, fmt.Errorf("expiry report by owner: %w", err)
	}
	defer ownerRows.Close()

	for ownerRows.Next() {
		var bo model.ExpiryReportByOwner
		if err := ownerRows.Scan(&bo.SubjectOrg, &bo.SubjectOU, &bo.Count); err == nil {
			report.ByOwner = append(report.ByOwner, bo)
		}
	}

	// Ghost certs: expired but observed within last 30 days
	ghostRows, err := s.pool.Query(ctx, `
		SELECT DISTINCT ON (c.fingerprint_sha256)
			c.fingerprint_sha256,
			c.subject_cn,
			c.issuer_cn,
			EXTRACT(DAY FROM NOW() - c.not_after)::int as expired_days_ago,
			to_char(o.observed_at, 'YYYY-MM-DD') as last_observed,
			COALESCE(o.server_name, ''),
			o.server_ip
		FROM certificates c
		JOIN observations o ON c.fingerprint_sha256 = o.cert_fingerprint
		WHERE c.not_after < NOW()
		  AND o.observed_at >= NOW() - INTERVAL '30 days'
		ORDER BY c.fingerprint_sha256, o.observed_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("expiry report ghosts: %w", err)
	}
	defer ghostRows.Close()

	for ghostRows.Next() {
		var ghost model.ExpiryReportGhost
		if err := ghostRows.Scan(
			&ghost.Fingerprint, &ghost.SubjectCN, &ghost.IssuerCN,
			&ghost.ExpiredDaysAgo, &ghost.LastObserved, &ghost.ServerName, &ghost.ServerIP,
		); err == nil {
			report.AlreadyExpired = append(report.AlreadyExpired, ghost)
		}
	}

	// Deployments at risk: observations for expiring certs
	if len(expiringFingerprints) > 0 {
		depRows, err := s.pool.Query(ctx, `
			SELECT DISTINCT ON (o.server_ip, o.server_port, o.cert_fingerprint)
				COALESCE(o.server_name, ''),
				o.server_ip,
				o.server_port,
				c.subject_cn,
				EXTRACT(DAY FROM c.not_after - NOW())::int
			FROM observations o
			JOIN certificates c ON o.cert_fingerprint = c.fingerprint_sha256
			WHERE o.cert_fingerprint = ANY($1)
			ORDER BY o.server_ip, o.server_port, o.cert_fingerprint, o.observed_at DESC
		`, expiringFingerprints)
		if err != nil {
			return nil, fmt.Errorf("expiry report deployments: %w", err)
		}
		defer depRows.Close()

		for depRows.Next() {
			var dep model.ExpiryReportDeployment
			if err := depRows.Scan(
				&dep.ServerName, &dep.ServerIP, &dep.ServerPort,
				&dep.CertCN, &dep.DaysRemaining,
			); err == nil {
				report.DeploymentsAtRisk = append(report.DeploymentsAtRisk, dep)
			}
		}
	}

	return report, nil
}
