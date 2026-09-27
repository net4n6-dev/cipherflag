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
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

func (f *fakeStore) seed(domain, cursor string) {
	f.states["ct_static:"+domain] = &model.IngestionState{SourceName: "ct_static:" + domain, Cursor: cursor}
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

// newFakeSunlightLog builds a hermetic two-leaf Static CT log: leaf 0 is
// a non-matching leaf the poller has already seen (the tests seed cursor
// "1"), leaf 1 is a net-new cert whose SAN is domain.
func newFakeSunlightLog(t *testing.T, domain string) *fakeLog {
	t.Helper()
	return newFakeLogFromCerts(t, []*x509.Certificate{
		mustGenerateLeafCert(t, "already-seen", []string{"other.test"}),
		mustGenerateLeafCert(t, domain, []string{domain}),
	})
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

	okLog := newFakeSunlightLog(t, okDomain)

	ing := &fakeIngester{}
	st := newFakeStore()
	st.seed(okDomain, "1")
	cfg := config.CtStaticSourceConfig{
		Domains: []config.CtStaticDomainConfig{
			{Enabled: true, Domain: failDomain, LogURL: failSrv.URL + "/2024h2/", PublicKeyPEM: okLog.pubPEM()},
			{Enabled: true, Domain: okDomain, LogURL: okLog.logURL(), PublicKeyPEM: okLog.pubPEM()},
		},
	}
	p := NewPoller(ing, st, okLog.client(), cfg)

	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}

	if len(ing.calls) != 1 {
		t.Fatalf("expected exactly 1 Ingest call (from the surviving domain) despite the first domain's failure, got %d", len(ing.calls))
	}
	if got := len(ing.calls[0].Certificates); got != 1 {
		t.Fatalf("expected 1 certificate ingested from %s, got %d", okDomain, got)
	}
	if state := st.states["ct_static:"+okDomain]; state == nil || state.Cursor != "2" {
		t.Fatalf("expected the surviving domain's cursor to advance to 2, got %+v", state)
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
	fl := newFakeSunlightLog(t, domain)

	ing := &fakeIngester{}
	st := newFakeStore()
	// Pre-seed the cursor at the log's current tree size (2) so
	// QueryDomain's "already up to date" branch fires.
	st.seed(domain, "2")
	cfg := config.CtStaticSourceConfig{
		Domains: []config.CtStaticDomainConfig{
			{Enabled: true, Domain: domain, LogURL: fl.logURL(), PublicKeyPEM: fl.pubPEM()},
		},
	}
	p := NewPoller(ing, st, fl.client(), cfg)

	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}
	if len(ing.calls) != 0 {
		t.Fatalf("expected no Ingest calls for an already-up-to-date domain, got %d", len(ing.calls))
	}
	if tiles := tileRequests(fl.requestLog()); len(tiles) != 0 {
		t.Errorf("fetched tiles %v for an up-to-date domain", tiles)
	}
}

// TestPollDomain_MalformedCursor_ResetsRatherThanPanics proves a corrupted
// persisted ingestion_state.Cursor (Review Focus, shared with Task 2's
// ct/crtsh — e.g. hand-edited, or written by a different kind by mistake)
// logs a warning and is treated as "no persisted state" instead of
// panicking the poller goroutine. "No persisted state" bootstraps to the
// log's current head (forward-watching; see Provider.QueryDomain), so the
// cycle ingests nothing and overwrites the bad cursor with a well-formed
// one.
func TestPollDomain_MalformedCursor_ResetsRatherThanPanics(t *testing.T) {
	const domain = "example.com"
	fl := newFakeSunlightLog(t, domain)

	ing := &fakeIngester{}
	st := newFakeStore()
	st.seed(domain, "not-a-uint64")
	cfg := config.CtStaticSourceConfig{
		Domains: []config.CtStaticDomainConfig{
			{Enabled: true, Domain: domain, LogURL: fl.logURL(), PublicKeyPEM: fl.pubPEM()},
		},
	}
	p := NewPoller(ing, st, fl.client(), cfg)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("pollDomain panicked on malformed cursor: %v", r)
		}
	}()
	if err := p.pollDomain(context.Background(), cfg.Domains[0]); err != nil {
		t.Fatalf("pollDomain: %v", err)
	}
	if len(ing.calls) != 0 {
		t.Fatalf("expected 0 Ingest calls (malformed cursor = no state = bootstrap to head), got %d", len(ing.calls))
	}
	if state := st.states["ct_static:"+domain]; state == nil || state.Cursor != "2" {
		t.Fatalf("expected the malformed cursor to be overwritten with the current head (2), got %+v", state)
	}
}

// Final-review Fix 2(b), through the real standalone poller: the first
// cycle for a domain with no ingestion_state row, against a 600-leaf log
// that already holds a matching cert, fetches no tiles, ingests nothing
// and persists cursor "600". After the log grows by one matching leaf,
// the second cycle walks only that new leaf's tile and ingests it.
func TestPollDomain_NoCursor_BootstrapsToHeadThenWatchesForward(t *testing.T) {
	const domain = "example.com"
	leaves := fillerLeaves(t, 601)
	leaves[5] = buildTestLeafData([]*x509.Certificate{mustGenerateLeafCert(t, "historical", []string{domain})})[0]
	leaves[600] = buildTestLeafData([]*x509.Certificate{mustGenerateLeafCert(t, "brand-new", []string{domain})})[0]
	fl := newFakeLog(t, leaves)
	fl.setSize(600)

	ing := &fakeIngester{}
	st := newFakeStore()
	dcfg := config.CtStaticDomainConfig{Enabled: true, Domain: domain, LogURL: fl.logURL(), PublicKeyPEM: fl.pubPEM()}
	p := NewPoller(ing, st, fl.client(), config.CtStaticSourceConfig{Domains: []config.CtStaticDomainConfig{dcfg}})
	ctx := context.Background()

	// Cycle 1: bootstrap.
	if err := p.pollDomain(ctx, dcfg); err != nil {
		t.Fatalf("cycle 1: %v", err)
	}
	if tiles := tileRequests(fl.requestLog()); len(tiles) != 0 {
		t.Fatalf("cycle 1 fetched %d tiles (%v); a cold start must not walk the log", len(tiles), tiles)
	}
	if len(ing.calls) != 0 {
		t.Fatalf("cycle 1 ingested %d batches, want 0 (historical certs are not backfilled)", len(ing.calls))
	}
	if state := st.states["ct_static:"+domain]; state == nil || state.Cursor != "600" {
		t.Fatalf("cycle 1 cursor = %+v, want 600 (bootstrapped to head)", state)
	}

	// Cycle 2: the log grows by one matching leaf.
	fl.setSize(601)
	if err := p.pollDomain(ctx, dcfg); err != nil {
		t.Fatalf("cycle 2: %v", err)
	}
	if len(ing.calls) != 1 || len(ing.calls[0].Certificates) != 1 || ing.calls[0].Certificates[0].SubjectCN != "brand-new" {
		t.Fatalf("cycle 2 should ingest exactly the brand-new cert; got %+v", ing.calls)
	}
	// Final-review Fix 7: full parse populates the scoring fields
	// (mustGenerateLeafCert: self-signed Ed25519).
	disc := ing.calls[0].Certificates[0]
	if disc.KeyAlgorithm != "Ed25519" || disc.KeySizeBits != 256 || disc.SignatureAlgorithm != "Ed25519" || disc.SerialNumber == "" {
		t.Errorf("scoring fields not populated: KeyAlgorithm=%q KeySizeBits=%d SignatureAlgorithm=%q SerialNumber=%q",
			disc.KeyAlgorithm, disc.KeySizeBits, disc.SignatureAlgorithm, disc.SerialNumber)
	}
	if disc.Source != "ct_static" || disc.StoreType != "ct_log" || disc.FilePath != "ct_static:"+disc.FingerprintSHA256 {
		t.Errorf("Source=%q StoreType=%q FilePath=%q", disc.Source, disc.StoreType, disc.FilePath)
	}
	for _, r := range tileRequests(fl.requestLog()) {
		if strings.HasPrefix(r, "/2024h2/tile/data/000") || strings.HasPrefix(r, "/2024h2/tile/data/001") {
			t.Errorf("cycle 2 fetched historical data tile %s", r)
		}
	}
	if state := st.states["ct_static:"+domain]; state == nil || state.Cursor != "601" {
		t.Fatalf("cycle 2 cursor = %+v, want 601", state)
	}
}
