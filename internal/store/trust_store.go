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
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// UpsertTrustStoreObservations batches TrustStoreObservation rows into
// host_trust_store with last_seen=NOW() on re-observation.
func (s *PostgresStore) UpsertTrustStoreObservations(ctx context.Context, obs []model.TrustStoreObservation) error {
	if len(obs) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, o := range obs {
		batch.Queue(
			`INSERT INTO host_trust_store
                (host_id, ca_fingerprint_sha256, source, source_detail)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (host_id, ca_fingerprint_sha256, source, source_detail)
             DO UPDATE SET last_seen = NOW()`,
			o.HostID, o.CAFingerprint, o.Source, o.SourceDetail,
		)
	}
	br := s.pool.SendBatch(ctx, batch)
	defer br.Close()
	for i := range obs {
		if _, err := br.Exec(); err != nil {
			log.Warn().Err(err).
				Str("host", obs[i].HostID).Str("ca", obs[i].CAFingerprint).
				Msg("UpsertTrustStoreObservations: row failed")
		}
	}
	return nil
}

// PruneStaleTrustStoreRows deletes rows last-seen before watermark for
// the given (host, source) scope.
func (s *PostgresStore) PruneStaleTrustStoreRows(ctx context.Context, hostID, source string, watermark time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM host_trust_store
         WHERE host_id = $1 AND source = $2 AND last_seen < $3`,
		hostID, source, watermark,
	)
	if err != nil {
		return 0, fmt.Errorf("PruneStaleTrustStoreRows: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ListTrustStoreHoldingsForHost returns all rows for the given host,
// ordered by source then fingerprint for stable rendering.
func (s *PostgresStore) ListTrustStoreHoldingsForHost(ctx context.Context, hostID string) ([]model.TrustStoreHolding, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT host_id, ca_fingerprint_sha256, source, source_detail, first_seen, last_seen
         FROM host_trust_store WHERE host_id = $1
         ORDER BY source, ca_fingerprint_sha256`,
		hostID,
	)
	if err != nil {
		return nil, fmt.Errorf("ListTrustStoreHoldingsForHost: %w", err)
	}
	defer rows.Close()
	var out []model.TrustStoreHolding
	for rows.Next() {
		var h model.TrustStoreHolding
		if err := rows.Scan(&h.HostID, &h.CAFingerprint, &h.Source, &h.SourceDetail, &h.FirstSeen, &h.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// CertSubjectCN returns the subject_cn for the certificate with the given
// fingerprint, or an empty string if the cert is unknown or has no CN.
func (s *PostgresStore) CertSubjectCN(ctx context.Context, fp string) (string, error) {
	var cn string
	err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(subject_cn, '') FROM certificates WHERE fingerprint_sha256 = $1`,
		fp,
	).Scan(&cn)
	if err != nil {
		return "", err
	}
	return cn, nil
}

// CertFingerprintBySPKI satisfies certfiles.SPKILookup at runtime.
// Returns the fingerprint of any cert whose stored SPKI matches the
// given SPKI fingerprint, or false if no match.
func (s *PostgresStore) CertFingerprintBySPKI(ctx context.Context, spkiFP string) (string, bool) {
	var certFP string
	err := s.pool.QueryRow(ctx,
		`SELECT fingerprint_sha256 FROM certificates WHERE spki_fingerprint_sha256 = $1 LIMIT 1`,
		spkiFP,
	).Scan(&certFP)
	if err != nil {
		return "", false
	}
	return certFP, true
}
