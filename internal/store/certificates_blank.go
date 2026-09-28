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

package store

import (
	"context"
	"time"
)

// BlankCertificate is a certificate row stored without its X.509 metadata
// but with the PEM it can be rebuilt from. CE before 2.3.0 stored a
// certificate posted to /api/v1/ingest with only RawPEM this way.
type BlankCertificate struct {
	FingerprintSHA256 string
	RawPEM            string
	SourceDiscovery   string
	FirstSeen         time.Time
	LastSeen          time.Time
}

// A zero not_after marks a blank row: every real certificate has one. The
// zero value is an index condition on idx_certs_not_after (v2.0 baseline),
// so the check serve runs at every startup visits only blank rows, not every
// certificate.
const listBlankCertificatesSQL = `
	SELECT fingerprint_sha256, raw_pem, source_discovery, first_seen, last_seen
	FROM certificates
	WHERE not_after = '0001-01-01 00:00:00+00' AND raw_pem <> ''
	  AND fingerprint_sha256 > $1
	ORDER BY fingerprint_sha256
	LIMIT $2`

// ListBlankCertificatesWithPEM returns up to limit blank certificates with a
// stored PEM, ordered by fingerprint and starting after the fingerprint
// after (keyset pagination: pass the last fingerprint of the previous page,
// or "" for the first). Paging by fingerprint rather than re-querying from
// the start means a row that cannot be repaired is passed over, not
// returned again forever.
func (s *PostgresStore) ListBlankCertificatesWithPEM(ctx context.Context, after string, limit int) ([]BlankCertificate, error) {
	rows, err := s.pool.Query(ctx, listBlankCertificatesSQL, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BlankCertificate
	for rows.Next() {
		var b BlankCertificate
		if err := rows.Scan(&b.FingerprintSHA256, &b.RawPEM, &b.SourceDiscovery, &b.FirstSeen, &b.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
