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

import "context"

// GetLibraryDistribution returns a per-(library_name, version) breakdown with
// host count and whether any CVEs are known for that library+version.
func (s *PostgresStore) GetLibraryDistribution(ctx context.Context) ([]LibraryDistItem, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			l.library_name,
			l.version,
			COUNT(DISTINCT l.host_id) AS host_count,
			EXISTS (
				SELECT 1 FROM crypto_library_cves v
				WHERE v.library_name = l.library_name
			) AS has_cves
		FROM crypto_libraries l
		GROUP BY l.library_name, l.version
		ORDER BY host_count DESC, l.library_name, l.version
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []LibraryDistItem
	for rows.Next() {
		var item LibraryDistItem
		if err := rows.Scan(&item.Library, &item.Version, &item.HostCount, &item.HasCVEs); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if items == nil {
		items = []LibraryDistItem{}
	}
	return items, nil
}

// GetSSHKeyAnalytics returns aggregated SSH key analytics: key type distribution,
// age distribution, protection stats, root-authorized count, strength
// classification, shared-fingerprint risk, and discovery-source breakdown.
func (s *PostgresStore) GetSSHKeyAnalytics(ctx context.Context) (*SSHKeyAnalytics, error) {
	result := &SSHKeyAnalytics{
		KeyTypes:             make(map[string]int),
		AgeDistribution:      []AgeBucket{},
		StrengthDistribution: make(map[string]int),
		SourceBreakdown:      make(map[string]int),
	}

	// Key type distribution
	typeRows, err := s.pool.Query(ctx, `
		SELECT key_type, COUNT(*) FROM ssh_keys GROUP BY key_type ORDER BY COUNT(*) DESC
	`)
	if err != nil {
		return nil, err
	}
	defer typeRows.Close()
	for typeRows.Next() {
		var kt string
		var cnt int
		if err := typeRows.Scan(&kt, &cnt); err != nil {
			return nil, err
		}
		result.KeyTypes[kt] = cnt
		result.TotalKeys += cnt
	}
	if err := typeRows.Err(); err != nil {
		return nil, err
	}

	// Age distribution buckets based on first_seen
	ageRows, err := s.pool.Query(ctx, `
		SELECT
			CASE
				WHEN first_seen >= NOW() - INTERVAL '30 days'  THEN '0-30d'
				WHEN first_seen >= NOW() - INTERVAL '90 days'  THEN '31-90d'
				WHEN first_seen >= NOW() - INTERVAL '365 days' THEN '91-365d'
				ELSE '1y+'
			END AS bucket,
			COUNT(*) AS cnt
		FROM ssh_keys
		GROUP BY bucket
		ORDER BY MIN(first_seen) DESC
	`)
	if err != nil {
		return nil, err
	}
	defer ageRows.Close()
	for ageRows.Next() {
		var b AgeBucket
		if err := ageRows.Scan(&b.Bucket, &b.Count); err != nil {
			return nil, err
		}
		result.AgeDistribution = append(result.AgeDistribution, b)
	}
	if err := ageRows.Err(); err != nil {
		return nil, err
	}

	// Protection stats
	s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM ssh_keys WHERE is_protected = TRUE").Scan(&result.Protection.Protected)
	s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM ssh_keys WHERE is_protected = FALSE").Scan(&result.Protection.Unprotected)

	// Root-authorized count
	s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM ssh_keys WHERE grants_root = TRUE").Scan(&result.RootAuthorizedCount)

	// Strength distribution: classify each key by (key_type, key_size_bits).
	// "weak" → quantum is irrelevant; classical crypto already broken/deprecated.
	// "modern" → Ed25519 (best-in-class for classical; still QC-vulnerable long-term).
	strRows, err := s.pool.Query(ctx, `
		SELECT
			CASE
				WHEN LOWER(key_type) = 'dsa' THEN 'weak'
				WHEN LOWER(key_type) = 'rsa' AND key_size_bits < 2048 THEN 'weak'
				WHEN LOWER(key_type) = 'rsa' AND key_size_bits = 2048 THEN 'acceptable'
				WHEN LOWER(key_type) = 'rsa' AND key_size_bits >= 3072 THEN 'strong'
				WHEN LOWER(key_type) = 'ecdsa' THEN 'strong'
				WHEN LOWER(key_type) = 'ed25519' THEN 'modern'
				ELSE 'unknown'
			END AS bucket,
			COUNT(*) AS cnt
		FROM ssh_keys
		GROUP BY bucket
	`)
	if err != nil {
		return nil, err
	}
	defer strRows.Close()
	for strRows.Next() {
		var bucket string
		var cnt int
		if err := strRows.Scan(&bucket, &cnt); err != nil {
			return nil, err
		}
		result.StrengthDistribution[bucket] = cnt
	}
	if err := strRows.Err(); err != nil {
		return nil, err
	}

	// Shared-fingerprint risk: a fingerprint present on ≥2 hosts indicates
	// the same private key is trusted on multiple machines. `shared_keys_count`
	// is the number of distinct such fingerprints; `shared_keys_instances` is
	// the total number of ssh_keys rows those fingerprints account for.
	s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM (
			SELECT fingerprint_sha256
			FROM ssh_keys
			GROUP BY fingerprint_sha256
			HAVING COUNT(DISTINCT host_id) > 1
		) t
	`).Scan(&result.SharedKeysCount)

	s.pool.QueryRow(ctx, `
		SELECT COALESCE(SUM(instances), 0) FROM (
			SELECT COUNT(*) AS instances
			FROM ssh_keys
			GROUP BY fingerprint_sha256
			HAVING COUNT(DISTINCT host_id) > 1
		) t
	`).Scan(&result.SharedKeysInstances)

	// Source breakdown — maps the discovery-source field (same vocabulary as
	// certificates' source_discovery) to counts.
	srcRows, err := s.pool.Query(ctx, `
		SELECT COALESCE(NULLIF(source, ''), 'unknown') AS src, COUNT(*) AS cnt
		FROM ssh_keys
		GROUP BY src
		ORDER BY cnt DESC
	`)
	if err != nil {
		return nil, err
	}
	defer srcRows.Close()
	for srcRows.Next() {
		var src string
		var cnt int
		if err := srcRows.Scan(&src, &cnt); err != nil {
			return nil, err
		}
		result.SourceBreakdown[src] = cnt
	}
	if err := srcRows.Err(); err != nil {
		return nil, err
	}

	return result, nil
}
