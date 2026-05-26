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

// UpsertPrivateKeyHoldings batches PrivateKeyObservation rows into
// cert_private_key_holding with last_seen=NOW() on re-observation.
func (s *PostgresStore) UpsertPrivateKeyHoldings(ctx context.Context, obs []model.PrivateKeyObservation) error {
	if len(obs) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, o := range obs {
		batch.Queue(
			`INSERT INTO cert_private_key_holding
			    (host_id, cert_fingerprint, evidence, source, source_detail)
			 VALUES ($1, $2, $3, $4, $5)
			 ON CONFLICT (host_id, cert_fingerprint, evidence, source_detail)
			 DO UPDATE SET last_seen = NOW()`,
			o.HostID, o.CertFingerprint, o.Evidence, o.Source, o.SourceDetail,
		)
	}
	br := s.pool.SendBatch(ctx, batch)
	defer br.Close()
	for i := range obs {
		if _, err := br.Exec(); err != nil {
			log.Warn().Err(err).
				Str("host", obs[i].HostID).Str("cert", obs[i].CertFingerprint).
				Msg("UpsertPrivateKeyHoldings: row failed")
		}
	}
	return nil
}

// PruneStalePrivateKeyHoldings deletes rows last-seen before watermark for
// the given (host, source) scope. Called at the end of each scan cycle to
// reflect "private key file disappeared from this host since last scan".
func (s *PostgresStore) PruneStalePrivateKeyHoldings(ctx context.Context, hostID, source string, watermark time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM cert_private_key_holding
		 WHERE host_id = $1 AND source = $2 AND last_seen < $3`,
		hostID, source, watermark,
	)
	if err != nil {
		return 0, fmt.Errorf("PruneStalePrivateKeyHoldings: %w", err)
	}
	return tag.RowsAffected(), nil
}

// CAHolderRow is a hit from HostsHoldingCAKey. Evidence is one of
// "colocated_pem" | "pkcs12_entry" | "jks_private_key_entry" | "protected_path".
type CAHolderRow struct {
	HostID   string
	Evidence string
}

// HostsHoldingCAKey returns hosts holding the private key for caFP.
// When includeInferred is false (the scoring read path), rows with
// evidence='protected_path' are excluded. When true (the display read
// path), all evidence types are returned.
func (s *PostgresStore) HostsHoldingCAKey(ctx context.Context, caFP string, includeInferred bool) ([]CAHolderRow, error) {
	q := `SELECT DISTINCT host_id, evidence
	      FROM cert_private_key_holding
	      WHERE cert_fingerprint = $1`
	if !includeInferred {
		q += ` AND evidence != 'protected_path'`
	}
	rows, err := s.pool.Query(ctx, q, caFP)
	if err != nil {
		return nil, fmt.Errorf("HostsHoldingCAKey: %w", err)
	}
	defer rows.Close()
	var out []CAHolderRow
	for rows.Next() {
		var r CAHolderRow
		if err := rows.Scan(&r.HostID, &r.Evidence); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
