//go:build integration

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

package ingest

import (
	"context"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
	"github.com/net4n6-dev/cipherflag/internal/store"
	"github.com/net4n6-dev/cipherflag/internal/testdb"
)

// TestIngest_SSHComment_EmitsSighting verifies the ssh_comment
// producer migrated from DedupSSHKey to the ingester layer: after a
// full Ingest call with an SSH key whose comment resolves to a team
// slug, an asset_ownership_sightings row exists with source=ssh_comment
// and confidence=observed.
func TestIngest_SSHComment_EmitsSighting(t *testing.T) {
	dsn := testdb.Require(t)
	ctx := context.Background()

	st, err := store.NewPostgresStore(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Clean slate.
	_, _ = st.Pool().Exec(ctx,
		"TRUNCATE asset_ownership_sightings, ssh_keys, asset_provenance, hosts RESTART IDENTITY CASCADE")

	ingester := NewUnifiedIngester(st)

	result := &DiscoveryResult{
		Source:       "osquery",
		SourceHostID: "test-host-001",
		Hostname:     "test-host.payments.acme.com",
		OSFamily:     "linux",
		Timestamp:    time.Now().UTC(),
		SSHKeys: []dedup.SSHKeyDiscovery{
			{
				KeyType:           "ssh-ed25519",
				KeySizeBits:       256,
				FingerprintSHA256: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
				FilePath:          "/home/alice/.ssh/authorized_keys",
				OwnerUser:         "alice",
				IsAuthorized:      true,
				Comment:           "alice@ops-01.payments.com",
				Source:            "osquery",
			},
		},
	}

	summary, err := ingester.Ingest(ctx, result)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(summary.IngestedAssets) != 1 {
		t.Fatalf("IngestedAssets = %d, want 1", len(summary.IngestedAssets))
	}

	var sightingCount int
	if err := st.Pool().QueryRow(ctx, `
		SELECT count(*) FROM asset_ownership_sightings
		WHERE source = 'ssh_comment'
		  AND confidence = 'observed'
		  AND team = 'payments'
	`).Scan(&sightingCount); err != nil {
		t.Fatalf("count sightings: %v", err)
	}
	if sightingCount != 1 {
		t.Errorf("ssh_comment sighting count = %d, want 1", sightingCount)
	}
}
