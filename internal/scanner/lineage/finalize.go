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

// Package lineage finalises scan findings by creating lineage_links rows
// for every B1 finding whose fingerprint matches an existing runtime-observed
// certificate or SSH key.
package lineage

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

type Store interface {
	CreateLineageLink(ctx context.Context, l *model.LineageLink) error
}

// PoolQuerier is the minimal pgx surface we need for the fingerprint-exists
// checks. PostgresStore.Pool() satisfies it.
type PoolQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type Finalizer struct {
	Store Store
	Pool  PoolQuerier
}

// Finalize inspects findings. For each finding with a non-empty Fingerprint,
// it checks certificates.fingerprint_sha256 and ssh_keys.fingerprint_sha256;
// on match it emits a lineage_links row.
func (f *Finalizer) Finalize(ctx context.Context, repoID, scanID string, findings []finding.FindingRecord) (int, error) {
	var created int
	for _, fr := range findings {
		if ctx.Err() != nil {
			return created, ctx.Err()
		}
		if fr.Fingerprint == "" {
			continue
		}
		fp := stripSHAPrefix(fr.Fingerprint)

		var has bool
		if err := f.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM certificates WHERE fingerprint_sha256 = $1)`, fp).Scan(&has); err != nil {
			return created, fmt.Errorf("cert fp check: %w", err)
		}
		if has {
			if err := f.Store.CreateLineageLink(ctx, &model.LineageLink{
				FromAssetType: "repository", FromAssetID: repoID,
				ToAssetType: "certificate", ToAssetID: fp,
				LinkType: "cert_fingerprint_match", Confidence: 1.0,
				Evidence: map[string]any{"commit_sha": fr.CommitSHA, "path": fr.Path, "scan_id": scanID},
			}); err != nil {
				return created, err
			}
			created++
			continue
		}

		if err := f.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ssh_keys WHERE fingerprint_sha256 = $1)`, fp).Scan(&has); err != nil {
			return created, fmt.Errorf("ssh fp check: %w", err)
		}
		if has {
			if err := f.Store.CreateLineageLink(ctx, &model.LineageLink{
				FromAssetType: "repository", FromAssetID: repoID,
				ToAssetType: "ssh_key", ToAssetID: fp,
				LinkType: "ssh_key_fingerprint_match", Confidence: 1.0,
				Evidence: map[string]any{"commit_sha": fr.CommitSHA, "path": fr.Path, "scan_id": scanID},
			}); err != nil {
				return created, err
			}
			created++
		}
	}
	return created, nil
}

func stripSHAPrefix(fp string) string {
	if len(fp) > 7 && fp[:7] == "sha256:" {
		return fp[7:]
	}
	return fp
}
