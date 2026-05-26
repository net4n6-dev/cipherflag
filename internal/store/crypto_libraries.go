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

	"github.com/jackc/pgx/v5"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

func (s *PostgresStore) UpsertCryptoLibrary(ctx context.Context, lib *model.CryptoLibrary) error {
	err := s.pool.QueryRow(ctx, `
		INSERT INTO crypto_libraries (
			host_id, library_name, version, package_name, package_manager,
			install_path, pqc_capable, source, discovery_status
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (host_id, library_name, version) DO UPDATE SET
			last_seen = NOW(),
			discovery_status = 'active',
			pqc_capable = EXCLUDED.pqc_capable,
			package_name = EXCLUDED.package_name,
			package_manager = EXCLUDED.package_manager,
			install_path = EXCLUDED.install_path
		RETURNING id, first_seen, last_seen
	`, lib.HostID, lib.LibraryName, lib.Version, lib.PackageName,
		lib.PackageManager, lib.InstallPath, lib.PQCCapable,
		lib.Source, lib.DiscoveryStatus,
	).Scan(&lib.ID, &lib.FirstSeen, &lib.LastSeen)
	if err != nil {
		return fmt.Errorf("upsert crypto library: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetCryptoLibrary(ctx context.Context, id string) (*model.CryptoLibrary, error) {
	lib := &model.CryptoLibrary{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, host_id, library_name, version,
		       package_name, package_manager, install_path,
		       pqc_capable, source, discovery_status, first_seen, last_seen
		FROM crypto_libraries
		WHERE id = $1
	`, id).Scan(
		&lib.ID, &lib.HostID, &lib.LibraryName, &lib.Version,
		&lib.PackageName, &lib.PackageManager, &lib.InstallPath,
		&lib.PQCCapable, &lib.Source, &lib.DiscoveryStatus, &lib.FirstSeen, &lib.LastSeen,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get crypto library: %w", err)
	}
	return lib, nil
}

func (s *PostgresStore) ListCryptoLibraries(ctx context.Context, query LibrarySearchQuery) (*LibrarySearchResult, error) {
	where := "WHERE 1=1"
	args := []any{}
	argN := 1

	if query.HostID != "" {
		where += fmt.Sprintf(" AND host_id = $%d", argN)
		args = append(args, query.HostID)
		argN++
	}
	if query.LibraryName != "" {
		where += fmt.Sprintf(" AND library_name = $%d", argN)
		args = append(args, query.LibraryName)
		argN++
	}
	if query.Status != "" {
		where += fmt.Sprintf(" AND discovery_status = $%d", argN)
		args = append(args, query.Status)
		argN++
	}
	if query.PQCCapable != nil {
		where += fmt.Sprintf(" AND pqc_capable = $%d", argN)
		args = append(args, *query.PQCCapable)
		argN++
	}
	if query.Search != "" {
		like := "%" + query.Search + "%"
		where += fmt.Sprintf(
			" AND (library_name ILIKE $%d OR version ILIKE $%d OR package_name ILIKE $%d OR install_path ILIKE $%d)",
			argN, argN, argN, argN,
		)
		args = append(args, like)
		argN++
	}

	var total int
	if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM crypto_libraries "+where, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count crypto libraries: %w", err)
	}

	limit := query.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := query.Offset
	if offset < 0 {
		offset = 0
	}

	querySQL := fmt.Sprintf(`
		SELECT id, host_id, library_name, version, package_name, package_manager,
		       install_path, pqc_capable, source, discovery_status, first_seen, last_seen
		FROM crypto_libraries %s
		ORDER BY last_seen DESC
		LIMIT $%d OFFSET $%d
	`, where, argN, argN+1)
	args = append(args, limit, offset)

	rows, err := s.pool.Query(ctx, querySQL, args...)
	if err != nil {
		return nil, fmt.Errorf("list crypto libraries: %w", err)
	}
	defer rows.Close()

	libs := []model.CryptoLibrary{}
	for rows.Next() {
		var lib model.CryptoLibrary
		if err := rows.Scan(
			&lib.ID, &lib.HostID, &lib.LibraryName, &lib.Version,
			&lib.PackageName, &lib.PackageManager, &lib.InstallPath,
			&lib.PQCCapable, &lib.Source, &lib.DiscoveryStatus,
			&lib.FirstSeen, &lib.LastSeen,
		); err != nil {
			return nil, fmt.Errorf("scan crypto library row: %w", err)
		}
		libs = append(libs, lib)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list crypto libraries rows: %w", err)
	}

	return &LibrarySearchResult{Libraries: libs, Total: total}, nil
}

func (s *PostgresStore) GetCryptoLibraryCVEs(ctx context.Context, libraryName, version string) ([]model.CryptoLibraryCVE, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT library_name, version_range, cve_id, severity, description
		FROM crypto_library_cves
		WHERE library_name = $1
		ORDER BY severity DESC, cve_id
	`, libraryName)
	if err != nil {
		return nil, fmt.Errorf("get crypto library cves: %w", err)
	}
	defer rows.Close()

	var cves []model.CryptoLibraryCVE
	for rows.Next() {
		var cve model.CryptoLibraryCVE
		if err := rows.Scan(
			&cve.LibraryName, &cve.VersionRange, &cve.CVEID,
			&cve.Severity, &cve.Description,
		); err != nil {
			return nil, fmt.Errorf("scan cve row: %w", err)
		}
		cves = append(cves, cve)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("get crypto library cves rows: %w", err)
	}
	if cves == nil {
		cves = []model.CryptoLibraryCVE{}
	}
	_ = version // reserved for future semver range filtering
	return cves, nil
}
