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
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// HostIPSighting is a time-windowed attestation that `IP` was held by
// `HostID` between `FirstSeen` and `LastSeen`, observed via `Source`
// with the given `Confidence` tier. `HostID` is nullable for
// observed-tier sightings that prove an IP was live without identifying
// whose it was (Zeek known_hosts.log).
//
// Spec: research/hip-sightings-spec-v1.5.0.md §3.2.
//
// Sources and confidences are constrained at the DB by CHECK clauses in
// migration 024 (`host_ip_sightings_source_check`,
// `host_ip_sightings_confidence_check`). Values outside the allowed set
// will error on INSERT.
type HostIPSighting struct {
	ID          string         `json:"id,omitempty"`
	HostID      string         `json:"host_id,omitempty"` // empty string means NULL in the DB
	IP          string         `json:"ip"`
	FirstSeen   time.Time      `json:"first_seen"`
	LastSeen    time.Time      `json:"last_seen"`
	Source      string         `json:"source"`
	Confidence  string         `json:"confidence"`
	Attribution map[string]any `json:"attribution,omitempty"`
	CreatedAt   time.Time      `json:"created_at,omitempty"`
}

// UpsertHostIPSighting inserts or merges a sighting on the functional
// unique index `idx_hip_unique = (source, ip, COALESCE(host_id, zero))`.
// On merge, the time window is expanded to the union of both
// observations: FirstSeen = LEAST(existing, new), LastSeen =
// GREATEST(existing, new). Attribution is overwritten with the new
// payload — newer observations carry more authoritative metadata than
// earlier ones in the DHCP case (e.g. lease renewals pick up a changed
// client_fqdn).
//
// Uses the SELECT-then-INSERT-or-UPDATE pattern established by
// RecordProvenance (provenance.go:82) because PostgreSQL does not
// support expressions in ON CONFLICT column lists.
func (s *PostgresStore) UpsertHostIPSighting(ctx context.Context, sighting *HostIPSighting) error {
	attrJSON, err := json.Marshal(sighting.Attribution)
	if err != nil {
		return fmt.Errorf("marshal sighting attribution: %w", err)
	}
	if len(attrJSON) == 0 || string(attrJSON) == "null" {
		attrJSON = []byte("{}")
	}

	var hostID any
	if sighting.HostID != "" {
		hostID = sighting.HostID
	}

	var existingID string
	err = s.pool.QueryRow(ctx, `
		SELECT id FROM host_ip_sightings
		WHERE source = $1
		  AND ip     = $2
		  AND COALESCE(host_id, '00000000-0000-0000-0000-000000000000'::uuid)
		    = COALESCE($3::uuid, '00000000-0000-0000-0000-000000000000'::uuid)
	`, sighting.Source, sighting.IP, hostID).Scan(&existingID)

	if err == pgx.ErrNoRows {
		// No existing row — insert. Populate ID so callers can chain.
		err = s.pool.QueryRow(ctx, `
			INSERT INTO host_ip_sightings
				(host_id, ip, first_seen, last_seen, source, confidence, attribution)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			RETURNING id, created_at
		`, hostID, sighting.IP, sighting.FirstSeen, sighting.LastSeen,
			sighting.Source, sighting.Confidence, attrJSON,
		).Scan(&sighting.ID, &sighting.CreatedAt)
		if err != nil {
			return fmt.Errorf("insert host_ip_sighting: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("host_ip_sighting lookup: %w", err)
	}

	// Existing row — expand the time window + refresh attribution.
	// LEAST/GREATEST ensure idempotence: replaying an earlier observation
	// doesn't shrink the window.
	_, err = s.pool.Exec(ctx, `
		UPDATE host_ip_sightings
		SET first_seen  = LEAST(first_seen, $2::timestamptz),
		    last_seen   = GREATEST(last_seen, $3::timestamptz),
		    confidence  = $4,
		    attribution = $5
		WHERE id = $1
	`, existingID, sighting.FirstSeen, sighting.LastSeen,
		sighting.Confidence, attrJSON,
	)
	if err != nil {
		return fmt.Errorf("update host_ip_sighting: %w", err)
	}
	sighting.ID = existingID
	return nil
}

// GetHostIPSightingsForIP returns every sighting whose time window
// contains `at` for the given `ip`. Only attributed rows (host_id NOT
// NULL) are returned — callers handling the "unattributed" case query
// separately via CountUnattributedObservations or the inline NOT EXISTS
// pattern in blast_radius.
//
// Rows returned in confidence-tier order (direct → attested → inferred
// → observed) so the first row is the strongest evidence for this IP.
func (s *PostgresStore) GetHostIPSightingsForIP(ctx context.Context, ip string, at time.Time) ([]HostIPSighting, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, host_id::text, ip, first_seen, last_seen, source, confidence, attribution, created_at
		FROM host_ip_sightings
		WHERE ip = $1
		  AND $2::timestamptz BETWEEN first_seen AND last_seen
		  AND host_id IS NOT NULL
		ORDER BY
		  CASE confidence
		    WHEN 'direct'   THEN 1
		    WHEN 'attested' THEN 2
		    WHEN 'inferred' THEN 3
		    WHEN 'observed' THEN 4
		    ELSE                 5
		  END ASC,
		  last_seen DESC
	`, ip, at)
	if err != nil {
		return nil, fmt.Errorf("query host_ip_sightings: %w", err)
	}
	defer rows.Close()

	out := []HostIPSighting{}
	for rows.Next() {
		var s HostIPSighting
		var attrJSON []byte
		if err := rows.Scan(&s.ID, &s.HostID, &s.IP, &s.FirstSeen, &s.LastSeen,
			&s.Source, &s.Confidence, &attrJSON, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan host_ip_sighting: %w", err)
		}
		if len(attrJSON) > 0 {
			_ = json.Unmarshal(attrJSON, &s.Attribution)
		}
		if s.Attribution == nil {
			s.Attribution = map[string]any{}
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate host_ip_sightings: %w", err)
	}
	return out, nil
}

// PruneHostIPSightings deletes every sighting whose `last_seen` is
// strictly before `cutoff`. Returns the number of rows removed.
//
// Called daily from the sightingsprune runner (P3) with cutoff =
// NOW() - 7 days. The idx_hip_last_seen index makes this an index scan
// rather than a full table walk.
func (s *PostgresStore) PruneHostIPSightings(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM host_ip_sightings WHERE last_seen < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune host_ip_sightings: %w", err)
	}
	return tag.RowsAffected(), nil
}

// CountHostIPSightings returns the row count for `source`, or the total
// if source == "". Test helper; not intended for production code paths.
func (s *PostgresStore) CountHostIPSightings(ctx context.Context, source string) (int, error) {
	var n int
	var err error
	if source == "" {
		err = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM host_ip_sightings`).Scan(&n)
	} else {
		err = s.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM host_ip_sightings WHERE source = $1`, source).Scan(&n)
	}
	if err != nil {
		return 0, fmt.Errorf("count host_ip_sightings: %w", err)
	}
	return n, nil
}
