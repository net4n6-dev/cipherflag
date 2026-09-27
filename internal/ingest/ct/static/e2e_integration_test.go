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
// fake-log fixture helpers already defined in provider_test.go
// (mustGenerateLeafCert, buildTestLeafData, fakeTreeLeafHash,
// buildStoredHashes, staticTestHashReader, buildTestTile,
// buildTestCheckpointWithRoot, servePathTile, mustEncodeEd25519PubPEM)
// rather than redefining e2e_-prefixed duplicates, since this file lives
// in the same (internal, non-_test-suffixed) package static.
package static

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
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

// End-to-end: wires static.Poller against a REAL *store.PostgresStore +
// real ingest pipeline, fed by a hermetic httptest fake Sunlight log.
// Asserts:
//  1. runCycle returns no error.
//  2. A certificates row is inserted with source_discovery = "ct_static".
//  3. ingestion_state["ct_static:e2e.example"].cursor advances to "1".
func TestPollerE2E_RealStoreAndIngester(t *testing.T) {
	ctx := context.Background()
	st := newIntegrationStore(t)

	const domain = "e2e.example"
	logPub, logPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cert := mustGenerateLeafCert(t, "e2e", []string{domain})
	leaves := buildTestLeafData([]*x509.Certificate{cert})
	leafHash := fakeTreeLeafHash(t, leaves[0], 0)
	storedHashes := buildStoredHashes(t, []tlog.Hash{leafHash})
	rootHash, err := tlog.TreeHash(1, staticTestHashReader(storedHashes))
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}
	tileBytes := buildTestTile(t, leaves)

	var checkpoint string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/2024h2/checkpoint":
			_, _ = w.Write([]byte(checkpoint))
		case r.URL.Path == "/2024h2/tile/data/000":
			_, _ = w.Write(tileBytes)
		case strings.HasPrefix(r.URL.Path, "/2024h2/tile/"):
			servePathTile(t, w, r, storedHashes, 1)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse srv.URL: %v", err)
	}
	checkpoint = buildTestCheckpointWithRoot(t, logPub, logPriv, u.Host, "/2024h2/", 1, rootHash[:])

	cfg := config.CtStaticSourceConfig{
		Domains: []config.CtStaticDomainConfig{
			{Enabled: true, Domain: domain, LogURL: srv.URL + "/2024h2/", PublicKeyPEM: mustEncodeEd25519PubPEM(t, logPub)},
		},
	}

	ingester := ingest.NewUnifiedIngester(st)
	poller := NewPoller(ingester, st, srv.Client(), cfg)

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

	// Assertion 3: ingestion_state cursor advanced to 1.
	state, err := st.GetIngestionState(ctx, "ct_static:"+domain)
	if err != nil {
		t.Fatalf("GetIngestionState: %v", err)
	}
	if state == nil || state.Cursor != "1" {
		t.Errorf("ingestion_state = %+v, want Cursor=\"1\"", state)
	}
}

// E2E: serve a tampered path tile (2-leaf tree, sibling hash corrupted).
// pollDomain must return an error, no certs row inserted, no
// ingestion_state cursor written.
//
// Design note: a 1-leaf tree cannot exercise tampered-tile abort because
// the audit proof for leaf 0 in a size-1 tree is empty (the leaf hash IS
// the root; no siblings fetched). We use a 2-leaf tree instead: for leaf
// 0 the proof has one element — StoredHashIndex(0,1) (the sibling).
// Tampering that sibling causes CheckRecord to recompute a different
// root, which mismatches the signed root → abort. runCycle itself
// swallows per-domain errors (multi-domain isolation, by design), so
// this test calls pollDomain directly to observe the abort.
func TestPollerE2E_AbortsOnTamperedPathTile(t *testing.T) {
	ctx := context.Background()
	st := newIntegrationStore(t)

	const domain = "e2e-tampered.example"
	logPub, logPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cert0 := mustGenerateLeafCert(t, "tampered-e2e", []string{domain})
	cert1 := mustGenerateLeafCert(t, "tampered-e2e-other", []string{"other-" + domain})
	leaves := buildTestLeafData([]*x509.Certificate{cert0, cert1})

	leafHashes := []tlog.Hash{
		fakeTreeLeafHash(t, leaves[0], 0),
		fakeTreeLeafHash(t, leaves[1], 1),
	}
	storedHashes := buildStoredHashes(t, leafHashes)
	rootHash, err := tlog.TreeHash(2, staticTestHashReader(storedHashes))
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}

	// Sign the REAL root, but tamper the sibling (StoredHashIndex(0,1)) in
	// the served path tiles so the proof recomputes a different root.
	tampered := make(map[int64]tlog.Hash, len(storedHashes))
	for k, v := range storedHashes {
		tampered[k] = v
	}
	var bad tlog.Hash
	bad[0] = 0xFF
	tampered[tlog.StoredHashIndex(0, 1)] = bad

	tileBytes := buildTestTile(t, leaves)

	var checkpoint string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/2024h2/checkpoint":
			_, _ = w.Write([]byte(checkpoint))
		case r.URL.Path == "/2024h2/tile/data/000":
			_, _ = w.Write(tileBytes)
		case strings.HasPrefix(r.URL.Path, "/2024h2/tile/"):
			servePathTile(t, w, r, tampered, 2)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse srv.URL: %v", err)
	}
	checkpoint = buildTestCheckpointWithRoot(t, logPub, logPriv, u.Host, "/2024h2/", 2, rootHash[:])

	domainCfg := config.CtStaticDomainConfig{
		Enabled: true, Domain: domain, LogURL: srv.URL + "/2024h2/", PublicKeyPEM: mustEncodeEd25519PubPEM(t, logPub),
	}

	ingester := ingest.NewUnifiedIngester(st)
	poller := NewPoller(ingester, st, srv.Client(), config.CtStaticSourceConfig{Domains: []config.CtStaticDomainConfig{domainCfg}})

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
	if state != nil {
		t.Errorf("ingestion_state = %+v, want nil (must not persist a cursor on crypto abort)", state)
	}
}
