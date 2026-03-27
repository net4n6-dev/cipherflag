package store

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyberflag-ai/cipherflag/internal/model"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(ctx context.Context, connString string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &PostgresStore{pool: pool}, nil
}

func (s *PostgresStore) Migrate(ctx context.Context) error {
	// Ensure the schema_migrations tracking table exists.
	if _, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("create schema_migrations table: %w", err)
	}

	// Read all .sql files from the embedded migrations directory.
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}

	// Collect and sort migration filenames alphabetically.
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	// Apply each migration that hasn't been applied yet.
	for _, name := range names {
		var exists bool
		if err := s.pool.QueryRow(ctx,
			"SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)", name,
		).Scan(&exists); err != nil {
			return fmt.Errorf("check migration %s: %w", name, err)
		}
		if exists {
			continue
		}

		sql, err := fs.ReadFile(migrationsFS, "migrations/"+name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}

		if _, err := s.pool.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("execute migration %s: %w", name, err)
		}

		if _, err := s.pool.Exec(ctx,
			"INSERT INTO schema_migrations (version) VALUES ($1)", name,
		); err != nil {
			return fmt.Errorf("record migration %s: %w", name, err)
		}
	}

	return nil
}

func (s *PostgresStore) Close() error {
	s.pool.Close()
	return nil
}

// ── Certificates ────────────────────────────────────────────────────────────

func (s *PostgresStore) UpsertCertificate(ctx context.Context, cert *model.Certificate) error {
	sans, _ := json.Marshal(cert.SubjectAltNames)
	ku, _ := json.Marshal(cert.KeyUsage)
	eku, _ := json.Marshal(cert.ExtendedKeyUsage)
	ocsp, _ := json.Marshal(cert.OCSPResponderURLs)
	crl, _ := json.Marshal(cert.CRLDistributionPoints)
	scts, _ := json.Marshal(cert.SCTs)

	_, err := s.pool.Exec(ctx, `
		INSERT INTO certificates (
			fingerprint_sha256, subject_cn, subject_org, subject_ou,
			subject_country, subject_state, subject_locality, subject_full,
			issuer_cn, issuer_org, issuer_ou, issuer_country, issuer_full,
			serial_number, not_before, not_after,
			key_algorithm, key_size_bits, signature_algorithm,
			subject_alt_names, is_ca, basic_constraints_path_len,
			key_usage, extended_key_usage,
			ocsp_responder_urls, crl_distribution_points, scts,
			source_discovery, first_seen, last_seen, raw_pem
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, $12, $13,
			$14, $15, $16,
			$17, $18, $19,
			$20, $21, $22,
			$23, $24, $25, $26, $27,
			$28, $29, $30, $31
		)
		ON CONFLICT (fingerprint_sha256) DO UPDATE SET
			last_seen = EXCLUDED.last_seen,
			source_discovery = EXCLUDED.source_discovery,
			raw_pem = COALESCE(NULLIF(EXCLUDED.raw_pem, ''), certificates.raw_pem)
	`,
		cert.FingerprintSHA256,
		cert.Subject.CommonName, cert.Subject.Organization, cert.Subject.OrganizationalUnit,
		cert.Subject.Country, cert.Subject.State, cert.Subject.Locality, cert.Subject.Full,
		cert.Issuer.CommonName, cert.Issuer.Organization, cert.Issuer.OrganizationalUnit,
		cert.Issuer.Country, cert.Issuer.Full,
		cert.SerialNumber, cert.NotBefore, cert.NotAfter,
		string(cert.KeyAlgorithm), cert.KeySizeBits, string(cert.SignatureAlgorithm),
		sans, cert.IsCA, cert.BasicConstraintsPathLen,
		ku, eku, ocsp, crl, scts,
		string(cert.SourceDiscovery), cert.FirstSeen, cert.LastSeen, cert.RawPEM,
	)
	return err
}

func (s *PostgresStore) GetCertificate(ctx context.Context, fingerprint string) (*model.Certificate, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, fingerprint_sha256,
			subject_cn, subject_org, subject_ou, subject_country, subject_state, subject_locality, subject_full,
			issuer_cn, issuer_org, issuer_ou, issuer_country, issuer_full,
			serial_number, not_before, not_after,
			key_algorithm, key_size_bits, signature_algorithm,
			subject_alt_names, is_ca, basic_constraints_path_len,
			key_usage, extended_key_usage,
			ocsp_responder_urls, crl_distribution_points, scts,
			source_discovery, first_seen, last_seen, raw_pem
		FROM certificates WHERE fingerprint_sha256 = $1
	`, fingerprint)
	return scanCertificate(row)
}

func (s *PostgresStore) SearchCertificates(ctx context.Context, q CertSearchQuery) (*CertSearchResult, error) {
	if q.Page < 1 {
		q.Page = 1
	}
	if q.PageSize < 1 || q.PageSize > 500 {
		q.PageSize = 50
	}

	var conditions []string
	var args []any
	argN := 1

	if q.Search != "" {
		conditions = append(conditions, fmt.Sprintf("search_vector @@ plainto_tsquery('english', $%d)", argN))
		args = append(args, q.Search)
		argN++
	}
	if q.Grade != "" {
		grades := strings.Split(q.Grade, ",")
		placeholders := make([]string, len(grades))
		for i, g := range grades {
			placeholders[i] = fmt.Sprintf("$%d", argN)
			args = append(args, strings.TrimSpace(g))
			argN++
		}
		conditions = append(conditions, fmt.Sprintf("h.grade IN (%s)", strings.Join(placeholders, ",")))
	}
	if q.Source != "" {
		conditions = append(conditions, fmt.Sprintf("c.source_discovery = $%d", argN))
		args = append(args, q.Source)
		argN++
	}
	if q.IssuerCN != "" {
		conditions = append(conditions, fmt.Sprintf("c.issuer_cn = $%d", argN))
		args = append(args, q.IssuerCN)
		argN++
	}
	if q.IsCA != nil {
		conditions = append(conditions, fmt.Sprintf("c.is_ca = $%d", argN))
		args = append(args, *q.IsCA)
		argN++
	}
	if q.Expired != nil && *q.Expired {
		conditions = append(conditions, "c.not_after < NOW()")
	}
	if q.ExpiringWithinDays != nil {
		conditions = append(conditions, fmt.Sprintf("c.not_after BETWEEN NOW() AND NOW() + INTERVAL '%d days'", *q.ExpiringWithinDays))
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	orderBy := "c.not_after ASC"
	switch q.SortBy {
	case "grade":
		orderBy = "h.score ASC"
	case "cn":
		orderBy = "c.subject_cn ASC"
	case "last_seen":
		orderBy = "c.last_seen DESC"
	case "expiry":
		orderBy = "c.not_after ASC"
	}
	if q.SortDir == "desc" {
		orderBy = strings.Replace(orderBy, "ASC", "DESC", 1)
	}

	// Count
	countSQL := fmt.Sprintf("SELECT COUNT(*) FROM certificates c LEFT JOIN health_reports h ON c.fingerprint_sha256 = h.cert_fingerprint %s", where)
	var total int
	if err := s.pool.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, err
	}

	// Fetch
	offset := (q.Page - 1) * q.PageSize
	dataSQL := fmt.Sprintf(`
		SELECT c.id, c.fingerprint_sha256,
			c.subject_cn, c.subject_org, c.subject_ou, c.subject_country, c.subject_state, c.subject_locality, c.subject_full,
			c.issuer_cn, c.issuer_org, c.issuer_ou, c.issuer_country, c.issuer_full,
			c.serial_number, c.not_before, c.not_after,
			c.key_algorithm, c.key_size_bits, c.signature_algorithm,
			c.subject_alt_names, c.is_ca, c.basic_constraints_path_len,
			c.key_usage, c.extended_key_usage,
			c.ocsp_responder_urls, c.crl_distribution_points, c.scts,
			c.source_discovery, c.first_seen, c.last_seen, c.raw_pem
		FROM certificates c
		LEFT JOIN health_reports h ON c.fingerprint_sha256 = h.cert_fingerprint
		%s
		ORDER BY %s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, argN, argN+1)
	args = append(args, q.PageSize, offset)

	rows, err := s.pool.Query(ctx, dataSQL, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []model.Certificate
	for rows.Next() {
		c, err := scanCertificateRows(rows)
		if err != nil {
			return nil, err
		}
		certs = append(certs, *c)
	}

	return &CertSearchResult{
		Certificates: certs,
		Total:        total,
		Page:         q.Page,
		PageSize:     q.PageSize,
	}, nil
}

func (s *PostgresStore) BatchUpsertCertificates(ctx context.Context, certs []*model.Certificate) error {
	if len(certs) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, cert := range certs {
		sans, _ := json.Marshal(cert.SubjectAltNames)
		ku, _ := json.Marshal(cert.KeyUsage)
		eku, _ := json.Marshal(cert.ExtendedKeyUsage)
		ocsp, _ := json.Marshal(cert.OCSPResponderURLs)
		crl, _ := json.Marshal(cert.CRLDistributionPoints)
		scts, _ := json.Marshal(cert.SCTs)

		batch.Queue(`
			INSERT INTO certificates (
				fingerprint_sha256, subject_cn, subject_org, subject_ou,
				subject_country, subject_state, subject_locality, subject_full,
				issuer_cn, issuer_org, issuer_ou, issuer_country, issuer_full,
				serial_number, not_before, not_after,
				key_algorithm, key_size_bits, signature_algorithm,
				subject_alt_names, is_ca, basic_constraints_path_len,
				key_usage, extended_key_usage,
				ocsp_responder_urls, crl_distribution_points, scts,
				source_discovery, first_seen, last_seen, raw_pem
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8,
				$9, $10, $11, $12, $13,
				$14, $15, $16,
				$17, $18, $19,
				$20, $21, $22,
				$23, $24, $25, $26, $27,
				$28, $29, $30, $31
			)
			ON CONFLICT (fingerprint_sha256) DO UPDATE SET
				last_seen = EXCLUDED.last_seen,
				source_discovery = EXCLUDED.source_discovery,
				raw_pem = COALESCE(NULLIF(EXCLUDED.raw_pem, ''), certificates.raw_pem)
		`,
			cert.FingerprintSHA256,
			cert.Subject.CommonName, cert.Subject.Organization, cert.Subject.OrganizationalUnit,
			cert.Subject.Country, cert.Subject.State, cert.Subject.Locality, cert.Subject.Full,
			cert.Issuer.CommonName, cert.Issuer.Organization, cert.Issuer.OrganizationalUnit,
			cert.Issuer.Country, cert.Issuer.Full,
			cert.SerialNumber, cert.NotBefore, cert.NotAfter,
			string(cert.KeyAlgorithm), cert.KeySizeBits, string(cert.SignatureAlgorithm),
			sans, cert.IsCA, cert.BasicConstraintsPathLen,
			ku, eku, ocsp, crl, scts,
			string(cert.SourceDiscovery), cert.FirstSeen, cert.LastSeen, cert.RawPEM,
		)
	}
	br := s.pool.SendBatch(ctx, batch)
	defer br.Close()
	for range certs {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("batch upsert: %w", err)
		}
	}
	return nil
}

func (s *PostgresStore) GetAllCertificatesForGraph(ctx context.Context) ([]model.Certificate, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT c.id, c.fingerprint_sha256,
			c.subject_cn, c.subject_org, c.subject_ou, c.subject_country, c.subject_state, c.subject_locality, c.subject_full,
			c.issuer_cn, c.issuer_org, c.issuer_ou, c.issuer_country, c.issuer_full,
			c.serial_number, c.not_before, c.not_after,
			c.key_algorithm, c.key_size_bits, c.signature_algorithm,
			c.subject_alt_names, c.is_ca, c.basic_constraints_path_len,
			c.key_usage, c.extended_key_usage,
			c.ocsp_responder_urls, c.crl_distribution_points, c.scts,
			c.source_discovery, c.first_seen, c.last_seen, c.raw_pem
		FROM certificates c
		ORDER BY c.is_ca DESC, c.subject_cn ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []model.Certificate
	for rows.Next() {
		c, err := scanCertificateRows(rows)
		if err != nil {
			return nil, err
		}
		certs = append(certs, *c)
	}
	return certs, nil
}

func (s *PostgresStore) GetAggregatedLandscape(ctx context.Context) (*model.AggregatedLandscapeResponse, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			ca.fingerprint_sha256,
			ca.subject_cn,
			ca.subject_org,
			ca.issuer_cn,
			ca.key_algorithm,
			ca.key_size_bits,
			CASE WHEN ca.subject_cn = ca.issuer_cn OR ca.issuer_cn = '' THEN 'root' ELSE 'intermediate' END as node_type,
			COALESCE(h.grade, '?') as ca_grade,
			(SELECT COUNT(*) FROM certificates ch WHERE ch.issuer_cn = ca.subject_cn AND ch.fingerprint_sha256 != ca.fingerprint_sha256) as cert_count,
			COALESCE((
				SELECT MAX(h2.grade) FROM certificates ch2
				JOIN health_reports h2 ON ch2.fingerprint_sha256 = h2.cert_fingerprint
				WHERE ch2.issuer_cn = ca.subject_cn AND ch2.fingerprint_sha256 != ca.fingerprint_sha256
			), COALESCE(h.grade, '?')) as worst_grade,
			COALESCE((
				SELECT AVG(h2.score)::numeric(5,1) FROM certificates ch2
				JOIN health_reports h2 ON ch2.fingerprint_sha256 = h2.cert_fingerprint
				WHERE ch2.issuer_cn = ca.subject_cn AND ch2.fingerprint_sha256 != ca.fingerprint_sha256
			), COALESCE(h.score, 0)) as avg_score,
			(SELECT COUNT(*) FROM certificates ch3 WHERE ch3.issuer_cn = ca.subject_cn AND ch3.not_after < NOW() AND ch3.fingerprint_sha256 != ca.fingerprint_sha256) as expired_count,
			(SELECT COUNT(*) FROM certificates ch4 WHERE ch4.issuer_cn = ca.subject_cn AND ch4.not_after BETWEEN NOW() AND NOW() + INTERVAL '30 days' AND ch4.fingerprint_sha256 != ca.fingerprint_sha256) as expiring_30d_count
		FROM certificates ca
		LEFT JOIN health_reports h ON ca.fingerprint_sha256 = h.cert_fingerprint
		WHERE ca.is_ca = true
		ORDER BY cert_count DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	resp := &model.AggregatedLandscapeResponse{
		Nodes: []model.AggregatedGraphNode{},
		Edges: []model.AggregatedGraphEdge{},
	}

	caSubjects := map[string]bool{}
	type caRow struct {
		node     model.AggregatedGraphNode
		issuerCN string
	}
	var cas []caRow

	for rows.Next() {
		var r caRow
		var issuerCN string
		if err := rows.Scan(
			&r.node.Fingerprint, &r.node.CommonName, &r.node.Organization,
			&issuerCN, &r.node.KeyAlgorithm, &r.node.KeySizeBits,
			&r.node.NodeType, new(string),
			&r.node.CertCount, &r.node.WorstGrade, &r.node.AvgScore,
			&r.node.ExpiredCount, &r.node.Expiring30dCount,
		); err != nil {
			return nil, err
		}
		r.issuerCN = issuerCN
		cas = append(cas, r)
		caSubjects[r.node.CommonName] = true
	}

	for _, ca := range cas {
		resp.Nodes = append(resp.Nodes, ca.node)
		if ca.node.NodeType == "intermediate" && caSubjects[ca.issuerCN] && ca.issuerCN != ca.node.CommonName {
			for _, parent := range cas {
				if parent.node.CommonName == ca.issuerCN {
					resp.Edges = append(resp.Edges, model.AggregatedGraphEdge{
						Source: parent.node.Fingerprint,
						Target: ca.node.Fingerprint,
						ChildGrade: ca.node.WorstGrade,
					})
					break
				}
			}
		}
	}

	return resp, nil
}

func (s *PostgresStore) GetCAChildren(ctx context.Context, fingerprint string, limit, offset int) (*model.CAChildrenResponse, error) {
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	var parentCN string
	err := s.pool.QueryRow(ctx, "SELECT subject_cn FROM certificates WHERE fingerprint_sha256 = $1", fingerprint).Scan(&parentCN)
	if err != nil {
		return nil, fmt.Errorf("parent CA not found: %w", err)
	}

	var total int
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM certificates
		WHERE issuer_cn = $1 AND fingerprint_sha256 != $2
	`, parentCN, fingerprint).Scan(&total); err != nil {
		return nil, fmt.Errorf("count children: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT
			c.fingerprint_sha256,
			c.subject_cn,
			c.subject_org,
			c.key_algorithm,
			c.key_size_bits,
			c.is_ca,
			c.not_after,
			COALESCE(h.grade, '?') as grade,
			COALESCE(h.score, 0) as score,
			CASE WHEN c.is_ca THEN
				(SELECT COUNT(*) FROM certificates ch WHERE ch.issuer_cn = c.subject_cn AND ch.fingerprint_sha256 != c.fingerprint_sha256)
			ELSE 0 END as child_count,
			CASE WHEN c.is_ca THEN COALESCE((
				SELECT MAX(h2.grade) FROM certificates ch2
				JOIN health_reports h2 ON ch2.fingerprint_sha256 = h2.cert_fingerprint
				WHERE ch2.issuer_cn = c.subject_cn AND ch2.fingerprint_sha256 != c.fingerprint_sha256
			), COALESCE(h.grade, '?')) ELSE COALESCE(h.grade, '?') END as worst_grade,
			CASE WHEN c.is_ca THEN COALESCE((
				SELECT AVG(h2.score)::numeric(5,1) FROM certificates ch2
				JOIN health_reports h2 ON ch2.fingerprint_sha256 = h2.cert_fingerprint
				WHERE ch2.issuer_cn = c.subject_cn AND ch2.fingerprint_sha256 != c.fingerprint_sha256
			), COALESCE(h.score, 0)) ELSE COALESCE(h.score, 0) END as avg_score,
			CASE WHEN c.is_ca THEN
				(SELECT COUNT(*) FROM certificates ch3 WHERE ch3.issuer_cn = c.subject_cn AND ch3.not_after < NOW() AND ch3.fingerprint_sha256 != c.fingerprint_sha256)
			ELSE CASE WHEN c.not_after < NOW() THEN 1 ELSE 0 END END as expired_count,
			CASE WHEN c.is_ca THEN
				(SELECT COUNT(*) FROM certificates ch4 WHERE ch4.issuer_cn = c.subject_cn AND ch4.not_after BETWEEN NOW() AND NOW() + INTERVAL '30 days' AND ch4.fingerprint_sha256 != c.fingerprint_sha256)
			ELSE CASE WHEN c.not_after BETWEEN NOW() AND NOW() + INTERVAL '30 days' THEN 1 ELSE 0 END END as expiring_30d_count
		FROM certificates c
		LEFT JOIN health_reports h ON c.fingerprint_sha256 = h.cert_fingerprint
		WHERE c.issuer_cn = $1 AND c.fingerprint_sha256 != $2
		ORDER BY c.is_ca DESC, c.subject_cn ASC
		LIMIT $3 OFFSET $4
	`, parentCN, fingerprint, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	resp := &model.CAChildrenResponse{
		ParentFingerprint: fingerprint,
		Nodes:             []model.AggregatedGraphNode{},
		Edges:             []model.AggregatedGraphEdge{},
		Total:             total,
		HasMore:           offset+limit < total,
	}

	for rows.Next() {
		var fp, cn, org, keyAlg, grade, worstGrade string
		var keyBits, score, childCount, expiredCount, expiring30d int
		var isCA bool
		var notAfter time.Time
		var avgScore float64

		if err := rows.Scan(
			&fp, &cn, &org, &keyAlg, &keyBits, &isCA, &notAfter,
			&grade, &score, &childCount, &worstGrade, &avgScore,
			&expiredCount, &expiring30d,
		); err != nil {
			return nil, err
		}

		nodeType := "leaf"
		if isCA {
			nodeType = "intermediate"
		}

		node := model.AggregatedGraphNode{
			Fingerprint:      fp,
			CommonName:       cn,
			Organization:     org,
			NodeType:         nodeType,
			CertCount:        childCount,
			WorstGrade:       worstGrade,
			AvgScore:         avgScore,
			ExpiredCount:     expiredCount,
			Expiring30dCount: expiring30d,
			KeyAlgorithm:     keyAlg,
			KeySizeBits:      keyBits,
		}
		resp.Nodes = append(resp.Nodes, node)
		resp.Edges = append(resp.Edges, model.AggregatedGraphEdge{
			Source:     fingerprint,
			Target:     fp,
			ChildGrade: worstGrade,
		})
	}

	return resp, nil
}

func (s *PostgresStore) GetBlastRadius(ctx context.Context, fingerprint string, limit int) (*model.BlastRadiusResponse, error) {
	if limit <= 0 {
		limit = 500
	}

	rows, err := s.pool.Query(ctx, `
		WITH RECURSIVE descendants AS (
			SELECT c.fingerprint_sha256, c.subject_cn, c.subject_org,
				c.issuer_cn, c.key_algorithm, c.key_size_bits, c.is_ca, c.not_after,
				1 as depth
			FROM certificates c
			JOIN certificates parent ON parent.fingerprint_sha256 = $1 AND c.issuer_cn = parent.subject_cn
			WHERE c.fingerprint_sha256 != $1

			UNION ALL

			SELECT c.fingerprint_sha256, c.subject_cn, c.subject_org,
				c.issuer_cn, c.key_algorithm, c.key_size_bits, c.is_ca, c.not_after,
				d.depth + 1
			FROM certificates c
			JOIN descendants d ON c.issuer_cn = d.subject_cn AND d.is_ca = true
			WHERE c.fingerprint_sha256 != d.fingerprint_sha256
			AND d.depth < 10
		)
		SELECT DISTINCT ON (d.fingerprint_sha256)
			d.fingerprint_sha256, d.subject_cn, d.subject_org,
			d.issuer_cn, d.key_algorithm, d.key_size_bits, d.is_ca, d.not_after,
			COALESCE(h.grade, '?') as grade,
			COALESCE(h.score, 0) as score
		FROM descendants d
		LEFT JOIN health_reports h ON d.fingerprint_sha256 = h.cert_fingerprint
		ORDER BY d.fingerprint_sha256, d.depth
		LIMIT $2
	`, fingerprint, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	resp := &model.BlastRadiusResponse{
		RootFingerprint: fingerprint,
		Nodes:           []model.AggregatedGraphNode{},
		Edges:           []model.AggregatedGraphEdge{},
	}

	caFPBySubject := map[string]string{}
	var rootCN string
	if err := s.pool.QueryRow(ctx, "SELECT subject_cn FROM certificates WHERE fingerprint_sha256 = $1", fingerprint).Scan(&rootCN); err != nil {
		return nil, fmt.Errorf("root CA not found: %w", err)
	}
	caFPBySubject[rootCN] = fingerprint

	type blastRow struct {
		fp, cn, org, issuerCN, keyAlg, grade string
		keyBits, score                        int
		isCA                                  bool
		notAfter                              time.Time
	}
	var allRows []blastRow

	for rows.Next() {
		var r blastRow
		if err := rows.Scan(
			&r.fp, &r.cn, &r.org, &r.issuerCN, &r.keyAlg, &r.keyBits,
			&r.isCA, &r.notAfter, &r.grade, &r.score,
		); err != nil {
			return nil, err
		}
		allRows = append(allRows, r)
		if r.isCA {
			caFPBySubject[r.cn] = r.fp
		}
	}

	// Build summary from ALL rows (before truncation) so counts are accurate
	summary := model.BlastRadiusSummary{}
	for _, r := range allRows {
		summary.TotalCerts++
		if r.notAfter.Before(time.Now()) {
			summary.Expired++
		} else if r.notAfter.Before(time.Now().Add(30 * 24 * time.Hour)) {
			summary.Expiring30d++
		}
		if r.grade == "F" {
			summary.GradeF++
		}
		if r.isCA {
			summary.Intermediates++
		}
	}
	resp.Summary = summary

	// Truncate after computing summary
	if len(allRows) > limit {
		resp.Truncated = true
		allRows = allRows[:limit]
	}

	// Build nodes + edges
	for _, r := range allRows {
		nodeType := "leaf"
		if r.isCA {
			nodeType = "intermediate"
		}

		now := time.Now()
		expiredCount := 0
		expiring30d := 0
		if r.notAfter.Before(now) {
			expiredCount = 1
		} else if r.notAfter.Before(now.Add(30 * 24 * time.Hour)) {
			expiring30d = 1
		}

		resp.Nodes = append(resp.Nodes, model.AggregatedGraphNode{
			Fingerprint:      r.fp,
			CommonName:       r.cn,
			Organization:     r.org,
			NodeType:         nodeType,
			WorstGrade:       r.grade,
			AvgScore:         float64(r.score),
			KeyAlgorithm:     r.keyAlg,
			KeySizeBits:      r.keyBits,
			ExpiredCount:     expiredCount,
			Expiring30dCount: expiring30d,
		})

		if issuerFP, ok := caFPBySubject[r.issuerCN]; ok {
			resp.Edges = append(resp.Edges, model.AggregatedGraphEdge{
				Source:     issuerFP,
				Target:     r.fp,
				ChildGrade: r.grade,
			})
		}
	}

	return resp, nil
}

// ── Observations ────────────────────────────────────────────────────────────

func (s *PostgresStore) RecordObservation(ctx context.Context, obs *model.CertificateObservation) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO observations (cert_fingerprint, server_ip, server_port, server_name, client_ip,
			negotiated_version, negotiated_cipher, cipher_strength,
			ja3_fingerprint, ja3s_fingerprint, source, observed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`,
		obs.CertFingerprint, obs.ServerIP, obs.ServerPort, obs.ServerName, obs.ClientIP,
		string(obs.NegotiatedVersion), obs.NegotiatedCipher, string(obs.CipherStrength),
		obs.JA3Fingerprint, obs.JA3SFingerprint, string(obs.Source), obs.ObservedAt,
	)
	return err
}

func (s *PostgresStore) GetObservations(ctx context.Context, fingerprint string, limit int) ([]model.CertificateObservation, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, cert_fingerprint, server_ip, server_port, server_name, client_ip,
			negotiated_version, negotiated_cipher, cipher_strength,
			ja3_fingerprint, ja3s_fingerprint, source, observed_at
		FROM observations
		WHERE cert_fingerprint = $1
		ORDER BY observed_at DESC
		LIMIT $2
	`, fingerprint, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var obs []model.CertificateObservation
	for rows.Next() {
		var o model.CertificateObservation
		if err := rows.Scan(&o.ID, &o.CertFingerprint, &o.ServerIP, &o.ServerPort, &o.ServerName, &o.ClientIP,
			&o.NegotiatedVersion, &o.NegotiatedCipher, &o.CipherStrength,
			&o.JA3Fingerprint, &o.JA3SFingerprint, &o.Source, &o.ObservedAt); err != nil {
			return nil, err
		}
		obs = append(obs, o)
	}
	return obs, nil
}

func (s *PostgresStore) BatchRecordObservations(ctx context.Context, observations []*model.CertificateObservation) error {
	for _, o := range observations {
		if err := s.RecordObservation(ctx, o); err != nil {
			return err
		}
	}
	return nil
}

// ── Endpoint Profiles ───────────────────────────────────────────────────────

func (s *PostgresStore) UpsertEndpointProfile(ctx context.Context, ep *model.EndpointProfile) error {
	suites, _ := json.Marshal(ep.CipherSuites)
	_, err := s.pool.Exec(ctx, `
		INSERT INTO endpoint_profiles (server_ip, server_port, server_name, cert_fingerprint,
			min_tls_version, max_tls_version, cipher_suites,
			supports_forward_secrecy, supports_aead, has_weak_ciphers,
			observation_count, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (server_ip, server_port) DO UPDATE SET
			server_name = EXCLUDED.server_name,
			cert_fingerprint = EXCLUDED.cert_fingerprint,
			min_tls_version = EXCLUDED.min_tls_version,
			max_tls_version = EXCLUDED.max_tls_version,
			cipher_suites = EXCLUDED.cipher_suites,
			supports_forward_secrecy = EXCLUDED.supports_forward_secrecy,
			supports_aead = EXCLUDED.supports_aead,
			has_weak_ciphers = EXCLUDED.has_weak_ciphers,
			observation_count = EXCLUDED.observation_count,
			last_seen = EXCLUDED.last_seen
	`,
		ep.ServerIP, ep.ServerPort, ep.ServerName, ep.CertFingerprint,
		string(ep.MinTLSVersion), string(ep.MaxTLSVersion), suites,
		ep.SupportsForwardSecrecy, ep.SupportsAEAD, ep.HasWeakCiphers,
		ep.ObservationCount, ep.FirstSeen, ep.LastSeen,
	)
	return err
}

func (s *PostgresStore) GetEndpointProfile(ctx context.Context, ip string, port int) (*model.EndpointProfile, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT server_ip, server_port, server_name, cert_fingerprint,
			min_tls_version, max_tls_version, cipher_suites,
			supports_forward_secrecy, supports_aead, has_weak_ciphers,
			observation_count, first_seen, last_seen
		FROM endpoint_profiles WHERE server_ip = $1 AND server_port = $2
	`, ip, port)
	return scanEndpointProfile(row)
}

func (s *PostgresStore) GetAllEndpointProfiles(ctx context.Context) ([]model.EndpointProfile, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT server_ip, server_port, server_name, cert_fingerprint,
			min_tls_version, max_tls_version, cipher_suites,
			supports_forward_secrecy, supports_aead, has_weak_ciphers,
			observation_count, first_seen, last_seen
		FROM endpoint_profiles ORDER BY last_seen DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var profiles []model.EndpointProfile
	for rows.Next() {
		ep, err := scanEndpointProfileRows(rows)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, *ep)
	}
	return profiles, nil
}

// ── Health Reports ──────────────────────────────────────────────────────────

func (s *PostgresStore) SaveHealthReport(ctx context.Context, report *model.HealthReport) error {
	findings, _ := json.Marshal(report.Findings)
	_, err := s.pool.Exec(ctx, `
		INSERT INTO health_reports (cert_fingerprint, grade, score, findings, scored_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (cert_fingerprint) DO UPDATE SET
			grade = EXCLUDED.grade,
			score = EXCLUDED.score,
			findings = EXCLUDED.findings,
			scored_at = EXCLUDED.scored_at
	`, report.CertFingerprint, string(report.Grade), report.Score, findings, report.ScoredAt)
	return err
}

func (s *PostgresStore) GetHealthReport(ctx context.Context, fingerprint string) (*model.HealthReport, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT cert_fingerprint, grade, score, findings, scored_at
		FROM health_reports WHERE cert_fingerprint = $1
	`, fingerprint)

	var r model.HealthReport
	var findingsJSON []byte
	if err := row.Scan(&r.CertFingerprint, &r.Grade, &r.Score, &findingsJSON, &r.ScoredAt); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	json.Unmarshal(findingsJSON, &r.Findings)
	return &r, nil
}

func (s *PostgresStore) GetAllHealthReports(ctx context.Context) ([]model.HealthReport, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT cert_fingerprint, grade, score, findings, scored_at
		FROM health_reports ORDER BY score ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reports []model.HealthReport
	for rows.Next() {
		var r model.HealthReport
		var findingsJSON []byte
		if err := rows.Scan(&r.CertFingerprint, &r.Grade, &r.Score, &findingsJSON, &r.ScoredAt); err != nil {
			return nil, err
		}
		json.Unmarshal(findingsJSON, &r.Findings)
		reports = append(reports, r)
	}
	return reports, nil
}

// ── Aggregations ────────────────────────────────────────────────────────────

func (s *PostgresStore) GetSummaryStats(ctx context.Context) (*SummaryStats, error) {
	stats := &SummaryStats{
		GradeDistribution: make(map[string]int),
		SourceStats:       make(map[string]int),
	}

	s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM certificates").Scan(&stats.TotalCerts)
	s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM observations").Scan(&stats.TotalObservations)
	s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM certificates WHERE not_after < NOW()").Scan(&stats.Expired)
	s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM certificates WHERE not_after BETWEEN NOW() AND NOW() + INTERVAL '30 days'").Scan(&stats.ExpiringIn30Days)
	s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM certificates WHERE not_after BETWEEN NOW() AND NOW() + INTERVAL '90 days'").Scan(&stats.ExpiringIn90Days)

	// Grade distribution
	rows, err := s.pool.Query(ctx, "SELECT grade, COUNT(*) FROM health_reports GROUP BY grade")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var g string
			var c int
			rows.Scan(&g, &c)
			stats.GradeDistribution[g] = c
		}
	}

	// Findings
	s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM health_reports WHERE score < 70").Scan(&stats.TotalFindings)
	s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM health_reports WHERE grade = 'F'").Scan(&stats.CriticalFindings)

	// Source stats
	rows2, err := s.pool.Query(ctx, "SELECT source_discovery, COUNT(*) FROM certificates GROUP BY source_discovery")
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var src string
			var c int
			rows2.Scan(&src, &c)
			stats.SourceStats[src] = c
		}
	}

	return stats, nil
}

func (s *PostgresStore) GetCipherStats(ctx context.Context) (*CipherStats, error) {
	cs := &CipherStats{
		StrengthDistribution: make(map[string]int),
		TLSVersionDist:       make(map[string]int),
	}

	// Suite distribution
	rows, _ := s.pool.Query(ctx, `
		SELECT negotiated_cipher, cipher_strength, COUNT(*)
		FROM observations
		WHERE negotiated_cipher != ''
		GROUP BY negotiated_cipher, cipher_strength
		ORDER BY COUNT(*) DESC
	`)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var cc CipherCount
			rows.Scan(&cc.Suite, &cc.Strength, &cc.Count)
			cs.SuiteDistribution = append(cs.SuiteDistribution, cc)
		}
	}

	// Strength distribution
	rows2, _ := s.pool.Query(ctx, `
		SELECT cipher_strength, COUNT(*) FROM observations
		WHERE cipher_strength != '' GROUP BY cipher_strength
	`)
	if rows2 != nil {
		defer rows2.Close()
		for rows2.Next() {
			var str string
			var c int
			rows2.Scan(&str, &c)
			cs.StrengthDistribution[str] = c
		}
	}

	// TLS version distribution
	rows3, _ := s.pool.Query(ctx, `
		SELECT negotiated_version, COUNT(*) FROM observations
		WHERE negotiated_version != '' GROUP BY negotiated_version
	`)
	if rows3 != nil {
		defer rows3.Close()
		for rows3.Next() {
			var v string
			var c int
			rows3.Scan(&v, &c)
			cs.TLSVersionDist[v] = c
		}
	}

	// TLS×cipher matrix
	rows4, _ := s.pool.Query(ctx, `
		SELECT negotiated_version, cipher_strength, COUNT(*)
		FROM observations
		WHERE negotiated_version != '' AND cipher_strength != ''
		GROUP BY negotiated_version, cipher_strength
	`)
	if rows4 != nil {
		defer rows4.Close()
		for rows4.Next() {
			var r TLSCipherRow
			rows4.Scan(&r.TLSVersion, &r.Strength, &r.Count)
			cs.TLSCipherMatrix = append(cs.TLSCipherMatrix, r)
		}
	}

	return cs, nil
}

// ── PKI Tree + Analytics ────────────────────────────────────────────────────

func (s *PostgresStore) GetPKITree(ctx context.Context) (*PKITreeResponse, error) {
	// Get all CAs with their health reports
	rows, err := s.pool.Query(ctx, `
		SELECT c.fingerprint_sha256, c.subject_cn, c.subject_org, c.subject_country,
			c.issuer_cn, c.key_algorithm, c.key_size_bits, c.not_after,
			COALESCE(h.grade, '?') as grade, COALESCE(h.score, 0) as score,
			(SELECT COUNT(*) FROM certificates lf WHERE lf.issuer_cn = c.subject_cn AND lf.is_ca = false) as leaf_count
		FROM certificates c
		LEFT JOIN health_reports h ON c.fingerprint_sha256 = h.cert_fingerprint
		WHERE c.is_ca = true
		ORDER BY c.subject_cn
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type caRow struct {
		fp, cn, org, country, issuerCN, keyAlg string
		keyBits                                 int
		notAfter                                time.Time
		grade                                   string
		score, leafCount                        int
	}
	var cas []caRow
	for rows.Next() {
		var r caRow
		if err := rows.Scan(&r.fp, &r.cn, &r.org, &r.country, &r.issuerCN,
			&r.keyAlg, &r.keyBits, &r.notAfter, &r.grade, &r.score, &r.leafCount); err != nil {
			return nil, err
		}
		cas = append(cas, r)
	}

	// Build lookup: subject_cn → [caRow indices]
	cnIndex := map[string][]int{}
	for i, ca := range cas {
		cnIndex[ca.cn] = append(cnIndex[ca.cn], i)
	}

	// Identify roots: self-signed or issuer_cn not in our CA set
	isCASubject := map[string]bool{}
	for _, ca := range cas {
		isCASubject[ca.cn] = true
	}

	toNode := func(r caRow, nodeType string) PKITreeNode {
		return PKITreeNode{
			Fingerprint:  r.fp,
			SubjectCN:    r.cn,
			SubjectOrg:   r.org,
			Country:      r.country,
			KeyAlgorithm: r.keyAlg,
			KeySizeBits:  r.keyBits,
			Grade:        r.grade,
			Score:        r.score,
			NotAfter:     r.notAfter.Format("2006-01-02"),
			NodeType:     nodeType,
			LeafCount:    r.leafCount,
		}
	}

	// Separate roots vs intermediates
	var roots []PKITreeNode
	intermediatesByIssuer := map[string][]PKITreeNode{}
	for _, ca := range cas {
		if ca.cn == ca.issuerCN || !isCASubject[ca.issuerCN] {
			roots = append(roots, toNode(ca, "root"))
		} else {
			node := toNode(ca, "intermediate")
			intermediatesByIssuer[ca.issuerCN] = append(intermediatesByIssuer[ca.issuerCN], node)
		}
	}

	// Attach intermediates to roots (recursive)
	var attachChildren func(node *PKITreeNode)
	attachChildren = func(node *PKITreeNode) {
		if children, ok := intermediatesByIssuer[node.SubjectCN]; ok {
			node.Children = children
			for i := range node.Children {
				attachChildren(&node.Children[i])
			}
		}
	}
	for i := range roots {
		attachChildren(&roots[i])
	}

	// Counts
	var totalLeaves int
	s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM certificates WHERE is_ca = false").Scan(&totalLeaves)

	// Orphans: leaves whose issuer_cn doesn't match any CA subject_cn
	var orphanCount int
	s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM certificates c
		WHERE c.is_ca = false
		AND NOT EXISTS (SELECT 1 FROM certificates ca WHERE ca.is_ca = true AND ca.subject_cn = c.issuer_cn)
	`).Scan(&orphanCount)

	return &PKITreeResponse{
		Roots:       roots,
		OrphanCount: orphanCount,
		TotalCAs:    len(cas),
		TotalLeaves: totalLeaves,
	}, nil
}

func (s *PostgresStore) GetIssuerStats(ctx context.Context) ([]IssuerStat, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT c.issuer_cn, c.issuer_org,
			COALESCE(ca.subject_country, '') as country,
			COUNT(*) as cert_count,
			COALESCE(AVG(h.score)::int, 0) as avg_score,
			COALESCE(MIN(h.grade), '?') as min_grade,
			COUNT(*) FILTER (WHERE c.not_after < NOW()) as expired_count
		FROM certificates c
		LEFT JOIN health_reports h ON c.fingerprint_sha256 = h.cert_fingerprint
		LEFT JOIN certificates ca ON ca.subject_cn = c.issuer_cn AND ca.is_ca = true
		WHERE c.is_ca = false
		GROUP BY c.issuer_cn, c.issuer_org, ca.subject_country
		ORDER BY cert_count DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []IssuerStat
	for rows.Next() {
		var s IssuerStat
		if err := rows.Scan(&s.IssuerCN, &s.IssuerOrg, &s.Country,
			&s.CertCount, &s.AvgScore, &s.MinGrade, &s.ExpiredCount); err != nil {
			return nil, err
		}
		stats = append(stats, s)
	}
	return stats, nil
}

func (s *PostgresStore) GetExpiryTimeline(ctx context.Context) (*ExpiryTimeline, error) {
	// Already expired
	var expired int
	s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM certificates WHERE not_after < NOW()").Scan(&expired)

	// Weekly buckets for next 52 weeks
	rows, err := s.pool.Query(ctx, `
		SELECT date_trunc('week', c.not_after)::date as week_start,
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE h.grade = 'F') as critical
		FROM certificates c
		LEFT JOIN health_reports h ON c.fingerprint_sha256 = h.cert_fingerprint
		WHERE c.not_after >= NOW()
			AND c.not_after < NOW() + INTERVAL '52 weeks'
		GROUP BY week_start
		ORDER BY week_start
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var buckets []ExpiryBucket
	for rows.Next() {
		var b ExpiryBucket
		var ws time.Time
		if err := rows.Scan(&ws, &b.Count, &b.Critical); err != nil {
			return nil, err
		}
		b.WeekStart = ws.Format("2006-01-02")
		buckets = append(buckets, b)
	}

	var totalCerts int
	s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM certificates").Scan(&totalCerts)

	return &ExpiryTimeline{
		Buckets:        buckets,
		TotalCerts:     totalCerts,
		AlreadyExpired: expired,
	}, nil
}

func (s *PostgresStore) GetChainFlow(ctx context.Context) (*model.ChainFlowResponse, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			ca.fingerprint_sha256,
			ca.subject_cn,
			ca.issuer_cn,
			ca.is_ca,
			CASE WHEN ca.subject_cn = ca.issuer_cn OR ca.issuer_cn = '' THEN 'root' ELSE 'intermediate' END as node_type,
			COALESCE(h.grade, '?') as grade,
			(SELECT COUNT(*) FROM certificates ch
			 WHERE ch.issuer_cn = ca.subject_cn AND ch.is_ca = false
			 AND ch.fingerprint_sha256 != ca.fingerprint_sha256) as leaf_count,
			(SELECT COUNT(*) FROM certificates ch
			 WHERE ch.issuer_cn = ca.subject_cn AND ch.is_ca = false
			 AND ch.not_after < NOW()
			 AND ch.fingerprint_sha256 != ca.fingerprint_sha256) as leaf_expired,
			(SELECT COALESCE(MAX(h2.grade), '?') FROM certificates ch2
			 JOIN health_reports h2 ON ch2.fingerprint_sha256 = h2.cert_fingerprint
			 WHERE ch2.issuer_cn = ca.subject_cn AND ch2.is_ca = false
			 AND ch2.fingerprint_sha256 != ca.fingerprint_sha256) as leaf_worst_grade
		FROM certificates ca
		LEFT JOIN health_reports h ON ca.fingerprint_sha256 = h.cert_fingerprint
		WHERE ca.is_ca = true
		ORDER BY node_type, ca.subject_cn
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	resp := &model.ChainFlowResponse{
		Nodes: []model.ChainFlowNode{},
		Links: []model.ChainFlowLink{},
	}

	type caInfo struct {
		fp, cn, issuerCN, nodeType, grade, leafWorstGrade string
		leafCount, leafExpired                             int
	}
	var cas []caInfo
	caSubjects := map[string]string{} // subject_cn → fingerprint

	for rows.Next() {
		var c caInfo
		var isCA bool
		if err := rows.Scan(&c.fp, &c.cn, &c.issuerCN, &isCA,
			&c.nodeType, &c.grade, &c.leafCount, &c.leafExpired, &c.leafWorstGrade); err != nil {
			return nil, err
		}
		cas = append(cas, c)
		caSubjects[c.cn] = c.fp
	}

	for _, ca := range cas {
		resp.Nodes = append(resp.Nodes, model.ChainFlowNode{
			ID:           "fp-" + ca.fp,
			Label:        ca.cn,
			NodeType:     ca.nodeType,
			CertCount:    ca.leafCount,
			Grade:        ca.grade,
			ExpiredCount: ca.leafExpired,
		})

		if ca.leafCount > 0 {
			leafGrade := ca.leafWorstGrade
			if leafGrade == "" {
				leafGrade = "?"
			}
			resp.Nodes = append(resp.Nodes, model.ChainFlowNode{
				ID:           "leaves-fp-" + ca.fp,
				Label:        fmt.Sprintf("%d leaf certificates", ca.leafCount),
				NodeType:     "leaf-aggregate",
				CertCount:    ca.leafCount,
				Grade:        leafGrade,
				ExpiredCount: ca.leafExpired,
			})

			resp.Links = append(resp.Links, model.ChainFlowLink{
				Source:       "fp-" + ca.fp,
				Target:       "leaves-fp-" + ca.fp,
				Value:        ca.leafCount,
				WorstGrade:   leafGrade,
				ExpiredCount: ca.leafExpired,
			})
		}
	}

	for _, ca := range cas {
		if ca.nodeType == "intermediate" {
			if issuerFP, ok := caSubjects[ca.issuerCN]; ok && ca.issuerCN != ca.cn {
				resp.Links = append(resp.Links, model.ChainFlowLink{
					Source:       "fp-" + issuerFP,
					Target:       "fp-" + ca.fp,
					Value:        max(ca.leafCount, 1),
					WorstGrade:   ca.grade,
					ExpiredCount: ca.leafExpired,
				})
			}
		}
	}

	return resp, nil
}

func (s *PostgresStore) GetOwnershipStats(ctx context.Context) (*model.OwnershipResponse, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			COALESCE(NULLIF(c.issuer_org, ''), 'Unknown Issuer') as issuer_org,
			COALESCE(NULLIF(c.subject_ou, ''), '') as subject_ou,
			COUNT(*) as cert_count,
			COUNT(*) FILTER (WHERE c.not_after < NOW()) as expired_count,
			COUNT(*) FILTER (WHERE c.not_after BETWEEN NOW() AND NOW() + INTERVAL '30 days') as expiring_30d_count,
			COALESCE(MAX(h.grade), '?') as worst_grade,
			COALESCE(AVG(h.score)::numeric(5,1), 0) as avg_score
		FROM certificates c
		LEFT JOIN health_reports h ON c.fingerprint_sha256 = h.cert_fingerprint
		GROUP BY COALESCE(NULLIF(c.issuer_org, ''), 'Unknown Issuer'),
		         COALESCE(NULLIF(c.subject_ou, ''), '')
		ORDER BY cert_count DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	resp := &model.OwnershipResponse{
		Groups: []model.OwnershipGroup{},
	}

	issuers := map[string]bool{}
	ous := map[string]bool{}

	for rows.Next() {
		var g model.OwnershipGroup
		if err := rows.Scan(&g.IssuerOrg, &g.SubjectOU, &g.CertCount,
			&g.ExpiredCount, &g.Expiring30dCount, &g.WorstGrade, &g.AvgScore); err != nil {
			return nil, err
		}
		resp.Groups = append(resp.Groups, g)
		resp.TotalCerts += g.CertCount
		issuers[g.IssuerOrg] = true
		if g.SubjectOU != "" {
			ous[g.SubjectOU] = true
		}
	}

	resp.TotalIssuers = len(issuers)
	resp.TotalOUs = len(ous)

	return resp, nil
}

func (s *PostgresStore) GetDeploymentStats(ctx context.Context) (*model.DeploymentResponse, error) {
	rows, err := s.pool.Query(ctx, `
		WITH cert_domains AS (
			SELECT DISTINCT
				o.cert_fingerprint,
				o.server_ip,
				CASE
					WHEN array_length(string_to_array(o.server_name, '.'), 1) >= 3
					THEN substring(o.server_name from position('.' in o.server_name) + 1)
					ELSE o.server_name
				END as domain
			FROM observations o
			WHERE o.server_name IS NOT NULL AND o.server_name != ''
		)
		SELECT
			cd.domain,
			COUNT(DISTINCT cd.cert_fingerprint) as cert_count,
			COUNT(DISTINCT cd.server_ip) as unique_ips,
			COUNT(DISTINCT cd.cert_fingerprint) FILTER (WHERE c.not_after < NOW()) as expired_count,
			COALESCE(MAX(h.grade), '?') as worst_grade,
			COALESCE(AVG(h.score)::numeric(5,1), 0) as avg_score
		FROM cert_domains cd
		JOIN certificates c ON c.fingerprint_sha256 = cd.cert_fingerprint
		LEFT JOIN health_reports h ON c.fingerprint_sha256 = h.cert_fingerprint
		GROUP BY cd.domain
		ORDER BY cert_count DESC
		LIMIT 50
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	resp := &model.DeploymentResponse{
		Groups: []model.DeploymentGroup{},
	}

	domains := map[string]bool{}
	for rows.Next() {
		var g model.DeploymentGroup
		if err := rows.Scan(&g.Domain, &g.CertCount, &g.UniqueIPs,
			&g.ExpiredCount, &g.WorstGrade, &g.AvgScore); err != nil {
			return nil, err
		}
		resp.Groups = append(resp.Groups, g)
		resp.TotalObservedCerts += g.CertCount
		domains[g.Domain] = true
	}

	resp.TotalDomains = len(domains)

	return resp, nil
}

func (s *PostgresStore) GetCryptoPosture(ctx context.Context) (*model.CryptoPostureResponse, error) {
	resp := &model.CryptoPostureResponse{
		KeyAlgorithms:       []model.KeyAlgoCount{},
		KeySizes:            []model.KeySizeCount{},
		SignatureAlgorithms: []model.SigAlgoCount{},
	}

	// Key algorithm distribution
	rows, err := s.pool.Query(ctx, `
		SELECT key_algorithm, COUNT(*) as count
		FROM certificates
		GROUP BY key_algorithm
		ORDER BY count DESC
	`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var a model.KeyAlgoCount
		if err := rows.Scan(&a.Algorithm, &a.Count); err != nil {
			rows.Close()
			return nil, err
		}
		resp.KeyAlgorithms = append(resp.KeyAlgorithms, a)
		resp.TotalCerts += a.Count
	}
	rows.Close()

	// Key size distribution (grouped by algorithm + size)
	rows, err = s.pool.Query(ctx, `
		SELECT key_algorithm, key_size_bits, COUNT(*) as count
		FROM certificates
		GROUP BY key_algorithm, key_size_bits
		ORDER BY key_algorithm, key_size_bits
	`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k model.KeySizeCount
		if err := rows.Scan(&k.Algorithm, &k.SizeBits, &k.Count); err != nil {
			rows.Close()
			return nil, err
		}
		resp.KeySizes = append(resp.KeySizes, k)
	}
	rows.Close()

	// Signature algorithm distribution
	rows, err = s.pool.Query(ctx, `
		SELECT signature_algorithm, COUNT(*) as count
		FROM certificates
		GROUP BY signature_algorithm
		ORDER BY count DESC
	`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sa model.SigAlgoCount
		if err := rows.Scan(&sa.Algorithm, &sa.Count); err != nil {
			rows.Close()
			return nil, err
		}
		resp.SignatureAlgorithms = append(resp.SignatureAlgorithms, sa)
	}
	rows.Close()

	return resp, nil
}

func (s *PostgresStore) GetExpiryForecast(ctx context.Context) (*model.ExpiryForecastResponse, error) {
	resp := &model.ExpiryForecastResponse{
		Buckets: []model.ExpiryForecastBucket{},
	}

	// Count already expired
	s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM certificates WHERE not_after < NOW()").Scan(&resp.AlreadyExpired)

	// Get top 8 issuers by expiring cert count (for stacked bar grouping)
	topRows, err := s.pool.Query(ctx, `
		SELECT COALESCE(NULLIF(issuer_org, ''), 'Unknown') as issuer_org, COUNT(*) as cnt
		FROM certificates
		WHERE not_after >= NOW() AND not_after <= NOW() + INTERVAL '52 weeks'
		GROUP BY issuer_org
		ORDER BY cnt DESC
		LIMIT 8
	`)
	if err != nil {
		return nil, err
	}
	for topRows.Next() {
		var org string
		var cnt int
		if err := topRows.Scan(&org, &cnt); err != nil {
			topRows.Close()
			return nil, err
		}
		resp.TopIssuers = append(resp.TopIssuers, org)
	}
	topRows.Close()

	// Build weekly buckets with per-issuer and per-grade breakdowns
	rows, err := s.pool.Query(ctx, `
		SELECT
			to_char(date_trunc('week', c.not_after), 'YYYY-MM-DD') as week_start,
			COALESCE(NULLIF(c.issuer_org, ''), 'Unknown') as issuer_org,
			COALESCE(h.grade, '?') as grade,
			COUNT(*) as cnt
		FROM certificates c
		LEFT JOIN health_reports h ON c.fingerprint_sha256 = h.cert_fingerprint
		WHERE c.not_after >= NOW() AND c.not_after <= NOW() + INTERVAL '52 weeks'
		GROUP BY week_start, issuer_org, grade
		ORDER BY week_start
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	bucketMap := map[string]*model.ExpiryForecastBucket{}
	for rows.Next() {
		var weekStart, issuerOrg, grade string
		var cnt int
		if err := rows.Scan(&weekStart, &issuerOrg, &grade, &cnt); err != nil {
			return nil, err
		}

		bucket, ok := bucketMap[weekStart]
		if !ok {
			bucket = &model.ExpiryForecastBucket{
				WeekStart: weekStart,
				ByGrade:   map[string]int{},
			}
			bucketMap[weekStart] = bucket
		}
		bucket.TotalCount += cnt
		bucket.ByGrade[grade] += cnt

		// Add to issuer breakdown
		found := false
		for i := range bucket.ByIssuer {
			if bucket.ByIssuer[i].IssuerOrg == issuerOrg {
				bucket.ByIssuer[i].Count += cnt
				found = true
				break
			}
		}
		if !found {
			bucket.ByIssuer = append(bucket.ByIssuer, model.ExpiryIssuerCount{
				IssuerOrg: issuerOrg,
				Count:     cnt,
			})
		}
	}

	// Sort buckets by week and calculate total
	weeks := make([]string, 0, len(bucketMap))
	for w := range bucketMap {
		weeks = append(weeks, w)
	}
	sort.Strings(weeks)

	for _, w := range weeks {
		resp.Buckets = append(resp.Buckets, *bucketMap[w])
		resp.TotalExpiring += bucketMap[w].TotalCount
	}

	return resp, nil
}

func (s *PostgresStore) GetSourceLineage(ctx context.Context) (*model.SourceLineageResponse, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			c.source_discovery,
			COUNT(*) as cert_count,
			COUNT(*) FILTER (WHERE c.not_after < NOW()) as expired_count,
			COUNT(*) FILTER (WHERE c.not_after BETWEEN NOW() AND NOW() + INTERVAL '30 days') as expiring_30d_count,
			COALESCE(AVG(h.score)::numeric(5,1), 0) as avg_score,
			to_char(MIN(c.first_seen), 'YYYY-MM-DD') as first_seen,
			to_char(MAX(c.last_seen), 'YYYY-MM-DD') as last_seen
		FROM certificates c
		LEFT JOIN health_reports h ON c.fingerprint_sha256 = h.cert_fingerprint
		GROUP BY c.source_discovery
		ORDER BY cert_count DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	resp := &model.SourceLineageResponse{
		Sources: []model.SourceLineageGroup{},
	}

	type sourceRow struct {
		source                                    string
		certCount, expiredCount, expiring30dCount int
		avgScore                                  float64
		firstSeen, lastSeen                       string
	}
	var sources []sourceRow

	for rows.Next() {
		var r sourceRow
		if err := rows.Scan(&r.source, &r.certCount, &r.expiredCount,
			&r.expiring30dCount, &r.avgScore, &r.firstSeen, &r.lastSeen); err != nil {
			return nil, err
		}
		sources = append(sources, r)
		resp.TotalCerts += r.certCount
	}

	// Get per-source grade distribution
	gradeRows, err := s.pool.Query(ctx, `
		SELECT c.source_discovery, COALESCE(h.grade, '?') as grade, COUNT(*) as cnt
		FROM certificates c
		LEFT JOIN health_reports h ON c.fingerprint_sha256 = h.cert_fingerprint
		GROUP BY c.source_discovery, grade
		ORDER BY c.source_discovery
	`)
	if err != nil {
		return nil, err
	}
	defer gradeRows.Close()

	gradeMap := map[string]map[string]int{}
	for gradeRows.Next() {
		var source, grade string
		var cnt int
		if err := gradeRows.Scan(&source, &grade, &cnt); err != nil {
			return nil, err
		}
		if gradeMap[source] == nil {
			gradeMap[source] = map[string]int{}
		}
		gradeMap[source][grade] = cnt
	}

	// Get per-source key algorithm distribution
	algoRows, err := s.pool.Query(ctx, `
		SELECT c.source_discovery, c.key_algorithm, COUNT(*) as cnt
		FROM certificates c
		GROUP BY c.source_discovery, c.key_algorithm
		ORDER BY c.source_discovery
	`)
	if err != nil {
		return nil, err
	}
	defer algoRows.Close()

	algoMap := map[string]map[string]int{}
	for algoRows.Next() {
		var source, algo string
		var cnt int
		if err := algoRows.Scan(&source, &algo, &cnt); err != nil {
			return nil, err
		}
		if algoMap[source] == nil {
			algoMap[source] = map[string]int{}
		}
		algoMap[source][algo] = cnt
	}

	// Assemble response
	for _, r := range sources {
		group := model.SourceLineageGroup{
			Source:            r.source,
			CertCount:         r.certCount,
			ExpiredCount:      r.expiredCount,
			Expiring30dCount:  r.expiring30dCount,
			GradeDistribution: gradeMap[r.source],
			KeyAlgorithms:     algoMap[r.source],
			AvgScore:          r.avgScore,
			FirstSeen:         r.firstSeen,
			LastSeen:          r.lastSeen,
		}
		if group.GradeDistribution == nil {
			group.GradeDistribution = map[string]int{}
		}
		if group.KeyAlgorithms == nil {
			group.KeyAlgorithms = map[string]int{}
		}
		resp.Sources = append(resp.Sources, group)
	}

	return resp, nil
}

// ── Ingestion State ─────────────────────────────────────────────────────────

func (s *PostgresStore) GetIngestionState(ctx context.Context, sourceName string) (*model.IngestionState, error) {
	row := s.pool.QueryRow(ctx, `SELECT source_name, cursor, updated_at FROM ingestion_state WHERE source_name = $1`, sourceName)
	var st model.IngestionState
	if err := row.Scan(&st.SourceName, &st.Cursor, &st.UpdatedAt); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &st, nil
}

func (s *PostgresStore) SetIngestionState(ctx context.Context, state *model.IngestionState) error {
	state.UpdatedAt = time.Now()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ingestion_state (source_name, cursor, updated_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (source_name) DO UPDATE SET cursor = EXCLUDED.cursor, updated_at = EXCLUDED.updated_at
	`, state.SourceName, state.Cursor, state.UpdatedAt)
	return err
}

// ── PCAP Jobs ───────────────────────────────────────────────────────────────

func (s *PostgresStore) CreatePCAPJob(ctx context.Context, job *model.PCAPJob) error {
	return s.pool.QueryRow(ctx, `
		INSERT INTO pcap_jobs (filename, file_size, status)
		VALUES ($1, $2, $3)
		RETURNING id, created_at
	`, job.Filename, job.FileSize, job.Status).Scan(&job.ID, &job.CreatedAt)
}

func (s *PostgresStore) GetPCAPJob(ctx context.Context, id string) (*model.PCAPJob, error) {
	var job model.PCAPJob
	err := s.pool.QueryRow(ctx, `
		SELECT id, filename, file_size, status, certs_found, certs_new,
			COALESCE(error, ''), created_at, completed_at
		FROM pcap_jobs WHERE id = $1
	`, id).Scan(&job.ID, &job.Filename, &job.FileSize, &job.Status,
		&job.CertsFound, &job.CertsNew, &job.Error,
		&job.CreatedAt, &job.CompletedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &job, nil
}

func (s *PostgresStore) UpdatePCAPJob(ctx context.Context, job *model.PCAPJob) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE pcap_jobs
		SET status = $1, certs_found = $2, certs_new = $3, error = $4, completed_at = $5
		WHERE id = $6
	`, job.Status, job.CertsFound, job.CertsNew, job.Error, job.CompletedAt, job.ID)
	return err
}

func (s *PostgresStore) ListPCAPJobs(ctx context.Context, limit int) ([]model.PCAPJob, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, filename, file_size, status, certs_found, certs_new,
			COALESCE(error, ''), created_at, completed_at
		FROM pcap_jobs
		ORDER BY created_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []model.PCAPJob
	for rows.Next() {
		var job model.PCAPJob
		if err := rows.Scan(&job.ID, &job.Filename, &job.FileSize, &job.Status,
			&job.CertsFound, &job.CertsNew, &job.Error,
			&job.CreatedAt, &job.CompletedAt); err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}

// ── Row scanners ────────────────────────────────────────────────────────────

func scanCertificate(row pgx.Row) (*model.Certificate, error) {
	var c model.Certificate
	var sansJSON, kuJSON, ekuJSON, ocspJSON, crlJSON, sctsJSON []byte
	err := row.Scan(
		&c.ID, &c.FingerprintSHA256,
		&c.Subject.CommonName, &c.Subject.Organization, &c.Subject.OrganizationalUnit,
		&c.Subject.Country, &c.Subject.State, &c.Subject.Locality, &c.Subject.Full,
		&c.Issuer.CommonName, &c.Issuer.Organization, &c.Issuer.OrganizationalUnit,
		&c.Issuer.Country, &c.Issuer.Full,
		&c.SerialNumber, &c.NotBefore, &c.NotAfter,
		&c.KeyAlgorithm, &c.KeySizeBits, &c.SignatureAlgorithm,
		&sansJSON, &c.IsCA, &c.BasicConstraintsPathLen,
		&kuJSON, &ekuJSON, &ocspJSON, &crlJSON, &sctsJSON,
		&c.SourceDiscovery, &c.FirstSeen, &c.LastSeen, &c.RawPEM,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	json.Unmarshal(sansJSON, &c.SubjectAltNames)
	json.Unmarshal(kuJSON, &c.KeyUsage)
	json.Unmarshal(ekuJSON, &c.ExtendedKeyUsage)
	json.Unmarshal(ocspJSON, &c.OCSPResponderURLs)
	json.Unmarshal(crlJSON, &c.CRLDistributionPoints)
	json.Unmarshal(sctsJSON, &c.SCTs)
	return &c, nil
}

func scanCertificateRows(rows pgx.Rows) (*model.Certificate, error) {
	var c model.Certificate
	var sansJSON, kuJSON, ekuJSON, ocspJSON, crlJSON, sctsJSON []byte
	err := rows.Scan(
		&c.ID, &c.FingerprintSHA256,
		&c.Subject.CommonName, &c.Subject.Organization, &c.Subject.OrganizationalUnit,
		&c.Subject.Country, &c.Subject.State, &c.Subject.Locality, &c.Subject.Full,
		&c.Issuer.CommonName, &c.Issuer.Organization, &c.Issuer.OrganizationalUnit,
		&c.Issuer.Country, &c.Issuer.Full,
		&c.SerialNumber, &c.NotBefore, &c.NotAfter,
		&c.KeyAlgorithm, &c.KeySizeBits, &c.SignatureAlgorithm,
		&sansJSON, &c.IsCA, &c.BasicConstraintsPathLen,
		&kuJSON, &ekuJSON, &ocspJSON, &crlJSON, &sctsJSON,
		&c.SourceDiscovery, &c.FirstSeen, &c.LastSeen, &c.RawPEM,
	)
	if err != nil {
		return nil, err
	}
	json.Unmarshal(sansJSON, &c.SubjectAltNames)
	json.Unmarshal(kuJSON, &c.KeyUsage)
	json.Unmarshal(ekuJSON, &c.ExtendedKeyUsage)
	json.Unmarshal(ocspJSON, &c.OCSPResponderURLs)
	json.Unmarshal(crlJSON, &c.CRLDistributionPoints)
	json.Unmarshal(sctsJSON, &c.SCTs)
	return &c, nil
}

func scanEndpointProfile(row pgx.Row) (*model.EndpointProfile, error) {
	var ep model.EndpointProfile
	var suitesJSON []byte
	err := row.Scan(
		&ep.ServerIP, &ep.ServerPort, &ep.ServerName, &ep.CertFingerprint,
		&ep.MinTLSVersion, &ep.MaxTLSVersion, &suitesJSON,
		&ep.SupportsForwardSecrecy, &ep.SupportsAEAD, &ep.HasWeakCiphers,
		&ep.ObservationCount, &ep.FirstSeen, &ep.LastSeen,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	json.Unmarshal(suitesJSON, &ep.CipherSuites)
	return &ep, nil
}

func scanEndpointProfileRows(rows pgx.Rows) (*model.EndpointProfile, error) {
	var ep model.EndpointProfile
	var suitesJSON []byte
	err := rows.Scan(
		&ep.ServerIP, &ep.ServerPort, &ep.ServerName, &ep.CertFingerprint,
		&ep.MinTLSVersion, &ep.MaxTLSVersion, &suitesJSON,
		&ep.SupportsForwardSecrecy, &ep.SupportsAEAD, &ep.HasWeakCiphers,
		&ep.ObservationCount, &ep.FirstSeen, &ep.LastSeen,
	)
	if err != nil {
		return nil, err
	}
	json.Unmarshal(suitesJSON, &ep.CipherSuites)
	return &ep, nil
}
