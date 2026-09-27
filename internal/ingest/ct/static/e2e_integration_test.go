//go:build integration

// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file is a CE-architecture rewrite of EE's e2e_integration_test.go.
// EE's version wired static.Poller (an externalsource.Poller) against a
// *store.PostgresStore via externalsource.Source / store.ExternalSource
// rows — infrastructure that does not exist in CE (CE has no
// internal/externalsource package; sources are configured via TOML,
// internal/config.CtStaticSourceConfig, per Task 6). This port keeps EE's
// valuable part — a hermetic fake Sunlight log exercising real Merkle
// verification end-to-end against a real Postgres store and the real
// ingest pipeline — but drives it through CE's static.Poller
// (NewPoller/runCycle/pollDomain) instead. It reuses the package-local
// spec-faithful fake log (fakelog_test.go) rather than redefining
// e2e_-prefixed duplicates, since this file lives in the same package.
package static

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
	"github.com/net4n6-dev/cipherflag/internal/testdb"
)

// newIntegrationStore opens a PostgresStore against the per-package test
// schema and truncates the tables this file's tests touch. Mirrors
// internal/ingest/ingester_cache_integration_test.go's newIntegrationStore.
func newIntegrationStore(t *testing.T) *store.PostgresStore {
	t.Helper()
	ctx := context.Background()
	st, err := store.NewPostgresStore(ctx, testdb.Require(t))
	if err != nil {
		t.Skipf("integration DB unavailable: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate test db: %v", err)
	}
	for _, tbl := range []string{"ingestion_state", "certificates"} {
		if _, err := st.Pool().Exec(ctx, "TRUNCATE TABLE "+tbl+" CASCADE"); err != nil {
			t.Fatalf("TRUNCATE %s: %v", tbl, err)
		}
	}
	return st
}

// seedCursor persists a ct_static cursor so the poll walks from a real,
// non-zero position (a zero/absent cursor bootstraps to the head without
// walking — see Provider.QueryDomain).
func seedCursor(t *testing.T, st *store.PostgresStore, domain, cursor string) {
	t.Helper()
	if err := st.SetIngestionState(context.Background(), &model.IngestionState{
		SourceName: "ct_static:" + domain, Cursor: cursor, UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}
}

// End-to-end: wires static.Poller against a REAL *store.PostgresStore +
// real ingest pipeline, fed by a hermetic fake Sunlight log whose leaf 0
// was already seen (cursor seeded at 1) and leaf 1 is net-new.
// Asserts:
//  1. runCycle returns no error.
//  2. A certificates row is inserted with source_discovery = "ct_static".
//  3. ingestion_state["ct_static:e2e.example"].cursor advances to "2".
func TestPollerE2E_RealStoreAndIngester(t *testing.T) {
	ctx := context.Background()
	st := newIntegrationStore(t)

	const domain = "e2e.example"
	fl := newFakeLogFromCerts(t, []*x509.Certificate{
		mustGenerateLeafCert(t, "e2e-already-seen", []string{"other.test"}),
		mustGenerateLeafCert(t, "e2e", []string{domain}),
	})
	seedCursor(t, st, domain, "1")

	cfg := config.CtStaticSourceConfig{
		Domains: []config.CtStaticDomainConfig{
			{Enabled: true, Domain: domain, LogURL: fl.logURL(), PublicKeyPEM: fl.pubPEM()},
		},
	}

	ingester := ingest.NewUnifiedIngester(st)
	poller := NewPoller(ingester, st, fl.client(), cfg)

	if err := poller.runCycle(ctx); err != nil {
		t.Fatalf("runCycle: %v", err)
	}

	// Assertion 2: cert ingested with ct_static source.
	var sourceDiscovery string
	if err := st.Pool().QueryRow(ctx,
		`SELECT source_discovery FROM certificates WHERE subject_cn = 'e2e' LIMIT 1`).
		Scan(&sourceDiscovery); err != nil {
		t.Fatalf("certs lookup: %v", err)
	}
	if !strings.Contains(sourceDiscovery, "ct_static") {
		t.Errorf("source_discovery = %q, want contains ct_static", sourceDiscovery)
	}

	// Assertion 3: ingestion_state cursor advanced to 2.
	state, err := st.GetIngestionState(ctx, "ct_static:"+domain)
	if err != nil {
		t.Fatalf("GetIngestionState: %v", err)
	}
	if state == nil || state.Cursor != "2" {
		t.Errorf("ingestion_state = %+v, want Cursor=\"2\"", state)
	}
}

// E2E: serve a tampered hash tile (3-leaf tree, one leaf hash corrupted
// in the served level-0 tile while the checkpoint signs the true root).
// tlog.TileHashReader's tile authentication rejects it — a cryptographic
// mismatch, so pollDomain must return an error, insert no certs row, and
// leave the seeded cursor untouched.
func TestPollerE2E_AbortsOnTamperedPathTile(t *testing.T) {
	ctx := context.Background()
	st := newIntegrationStore(t)

	const domain = "e2e-tampered.example"
	fl := newFakeLogFromCerts(t, []*x509.Certificate{
		mustGenerateLeafCert(t, "tampered-e2e-seen", []string{"other.test"}),
		mustGenerateLeafCert(t, "tampered-e2e", []string{domain}),
		mustGenerateLeafCert(t, "tampered-e2e-other", []string{"other-" + domain}),
	})
	var bad tlog.Hash
	bad[0] = 0xFF
	fl.configure(func(f *fakeLog) { f.tamper = map[int64]tlog.Hash{tlog.StoredHashIndex(0, 0): bad} })
	seedCursor(t, st, domain, "1")

	domainCfg := config.CtStaticDomainConfig{
		Enabled: true, Domain: domain, LogURL: fl.logURL(), PublicKeyPEM: fl.pubPEM(),
	}

	ingester := ingest.NewUnifiedIngester(st)
	poller := NewPoller(ingester, st, fl.client(), config.CtStaticSourceConfig{Domains: []config.CtStaticDomainConfig{domainCfg}})

	if err := poller.pollDomain(ctx, domainCfg); err == nil {
		t.Fatalf("pollDomain: expected an error on tampered inclusion proof, got nil")
	}

	var certCount int
	if err := st.Pool().QueryRow(ctx,
		`SELECT count(*) FROM certificates WHERE subject_cn = 'tampered-e2e'`).Scan(&certCount); err != nil {
		t.Fatalf("count certs: %v", err)
	}
	if certCount != 0 {
		t.Errorf("certificates inserted: %d, want 0", certCount)
	}

	state, err := st.GetIngestionState(ctx, "ct_static:"+domain)
	if err != nil {
		t.Fatalf("GetIngestionState: %v", err)
	}
	if state == nil || state.Cursor != "1" {
		t.Errorf("ingestion_state = %+v, want the seeded Cursor=\"1\" unchanged (must not advance on crypto abort)", state)
	}
}
