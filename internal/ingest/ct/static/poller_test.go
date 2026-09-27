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
	"github.com/net4n6-dev/cipherflag/internal/model"
)

type fakeIngester struct{ calls []*ingest.DiscoveryResult }

func (f *fakeIngester) Ingest(ctx context.Context, r *ingest.DiscoveryResult) (*ingest.IngestionSummary, error) {
	f.calls = append(f.calls, r)
	return &ingest.IngestionSummary{}, nil
}
func (f *fakeIngester) AttributeAssets(ctx context.Context, claims []ingest.OwnershipClaim) (int, int, error) {
	return 0, 0, nil
}

type fakeStore struct {
	states map[string]*model.IngestionState
}

func newFakeStore() *fakeStore { return &fakeStore{states: map[string]*model.IngestionState{}} }
func (f *fakeStore) GetIngestionState(ctx context.Context, sourceName string) (*model.IngestionState, error) {
	return f.states[sourceName], nil
}
func (f *fakeStore) SetIngestionState(ctx context.Context, state *model.IngestionState) error {
	f.states[state.SourceName] = state
	return nil
}

func TestRunCycle_NoDomains_NoOp(t *testing.T) {
	ing := &fakeIngester{}
	st := newFakeStore()
	p := NewPoller(ing, st, nil, config.CtStaticSourceConfig{})
	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}
	if len(ing.calls) != 0 {
		t.Fatalf("expected no Ingest calls, got %d", len(ing.calls))
	}
}

// newFakeSunlightServer builds a hermetic one-leaf Static CT log (checkpoint
// + data tile + path tiles) serving a single cert whose SAN is domain.
// Mirrors the fake-log construction in TestProvider_QueryDomain_FiltersBySAN
// (provider_test.go), reusing its package-local helpers. Returns the
// *httptest.Server and the log's PEM-encoded Ed25519 public key.
func newFakeSunlightServer(t *testing.T, domain string) (*httptest.Server, string) {
	t.Helper()
	logPub, logPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cert := mustGenerateLeafCert(t, domain, []string{domain})
	leaves := buildTestLeafData([]*x509.Certificate{cert})
	leafHash := fakeTreeLeafHash(t, leaves[0], 0)
	storedHashes := buildStoredHashes(t, []tlog.Hash{leafHash})
	rootHash, err := tlog.TreeHash(1, staticTestHashReader(storedHashes))
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}
	tileBytes := buildTestTile(t, leaves)

	// checkpoint is filled in below, once the server's own host is known —
	// the poller (poller.go's pollDomain) never sets Provider.KeyName, so
	// Provider.QueryDomain derives it from the LogURL host (deriveKeyName),
	// which for a httptest.Server is only known after it starts listening.
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
	return srv, mustEncodeEd25519PubPEM(t, logPub)
}

// TestRunCycle_OneDomainFails_DoesNotBlockOthers proves the isolation
// property runCycle is named for (mirrors crtsh's poller_test.go test of
// the same name — Review Focus: multi-domain isolation): domain 1's log
// always fails its checkpoint fetch with a 404, while domain 2 is a real
// hermetic fake Sunlight log with one net-new leaf matching its own SAN.
// Asserting domain 2 was actually reached and ingested (not just "no
// panic") is what proves isolation held.
func TestRunCycle_OneDomainFails_DoesNotBlockOthers(t *testing.T) {
	const failDomain = "fail.example.com"
	const okDomain = "ok.example.com"

	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(failSrv.Close)

	okSrv, okPubPEM := newFakeSunlightServer(t, okDomain)

	ing := &fakeIngester{}
	st := newFakeStore()
	cfg := config.CtStaticSourceConfig{
		Domains: []config.CtStaticDomainConfig{
			{Enabled: true, Domain: failDomain, LogURL: failSrv.URL + "/2024h2/", PublicKeyPEM: okPubPEM},
			{Enabled: true, Domain: okDomain, LogURL: okSrv.URL + "/2024h2/", PublicKeyPEM: okPubPEM},
		},
	}
	p := NewPoller(ing, st, okSrv.Client(), cfg)

	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}

	if len(ing.calls) != 1 {
		t.Fatalf("expected exactly 1 Ingest call (from the surviving domain) despite the first domain's failure, got %d", len(ing.calls))
	}
	if got := len(ing.calls[0].Certificates); got != 1 {
		t.Fatalf("expected 1 certificate ingested from %s, got %d", okDomain, got)
	}
	if st.states["ct_static:"+okDomain] == nil {
		t.Fatalf("expected an ingestion_state checkpoint for the surviving domain %s", okDomain)
	}
	if st.states["ct_static:"+failDomain] != nil {
		t.Fatalf("did not expect a checkpoint for the failed domain %s (query never succeeded)", failDomain)
	}
}

// TestRunCycle_EmptyResult_NotAnError proves that a domain already at the
// log's current tree size (zero net-new leaves) is a normal ok cycle, not
// an error, and does not produce a spurious Ingest call.
func TestRunCycle_EmptyResult_NotAnError(t *testing.T) {
	const domain = "example.com"
	srv, pubPEM := newFakeSunlightServer(t, domain)

	ing := &fakeIngester{}
	st := newFakeStore()
	// Pre-seed the cursor at the log's current tree size (1) so
	// QueryDomain's "already up to date" branch fires and returns zero
	// entries without needing to walk any tiles.
	st.states["ct_static:"+domain] = &model.IngestionState{
		SourceName: "ct_static:" + domain,
		Cursor:     "1",
	}
	cfg := config.CtStaticSourceConfig{
		Domains: []config.CtStaticDomainConfig{
			{Enabled: true, Domain: domain, LogURL: srv.URL + "/2024h2/", PublicKeyPEM: pubPEM},
		},
	}
	p := NewPoller(ing, st, srv.Client(), cfg)

	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}
	if len(ing.calls) != 0 {
		t.Fatalf("expected no Ingest calls for an already-up-to-date domain, got %d", len(ing.calls))
	}
}

// TestPollDomain_MalformedCursor_ResetsRatherThanPanics proves a corrupted
// persisted ingestion_state.Cursor (Review Focus, shared with Task 2's
// ct/crtsh — e.g. hand-edited, or written by a different kind by mistake)
// logs a warning and resets lastTreeSize to 0 instead of panicking the
// poller goroutine. Mirrors crtsh's own
// TestPollDomain_MalformedCursor_ResetsRatherThanPanics
// (internal/ingest/ct/crtsh/poller_test.go). Hermetic — a fake Sunlight
// log backs the domain so this never touches the live network.
func TestPollDomain_MalformedCursor_ResetsRatherThanPanics(t *testing.T) {
	const domain = "example.com"
	srv, pubPEM := newFakeSunlightServer(t, domain)

	ing := &fakeIngester{}
	st := newFakeStore()
	st.states["ct_static:"+domain] = &model.IngestionState{
		SourceName: "ct_static:" + domain,
		Cursor:     "not-a-uint64",
	}
	cfg := config.CtStaticSourceConfig{
		Domains: []config.CtStaticDomainConfig{
			{Enabled: true, Domain: domain, LogURL: srv.URL + "/2024h2/", PublicKeyPEM: pubPEM},
		},
	}
	p := NewPoller(ing, st, srv.Client(), cfg)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("pollDomain panicked on malformed cursor: %v", r)
		}
	}()
	if err := p.pollDomain(context.Background(), cfg.Domains[0]); err != nil {
		t.Fatalf("pollDomain: %v", err)
	}

	// A malformed cursor must reset lastTreeSize to 0 rather than aborting
	// the poll — proven by the cycle completing as if starting fresh: the
	// fake log's single leaf (tree size 1) is ingested, and the malformed
	// cursor is overwritten with a well-formed one afterward.
	if len(ing.calls) != 1 {
		t.Fatalf("expected 1 Ingest call (poll proceeded as if starting fresh from tree size 0), got %d", len(ing.calls))
	}
	state := st.states["ct_static:"+domain]
	if state == nil || state.Cursor != "1" {
		t.Fatalf("expected the malformed cursor to be overwritten with a well-formed one after a successful poll, got %+v", state)
	}
}
