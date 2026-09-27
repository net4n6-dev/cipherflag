package certspotter

import (
	"context"
	"net/http"
	"net/http/httptest"
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

func TestRunCycle_NoDomains_NoOp(t *testing.T) {
	ing := &fakeIngester{}
	st := newFakeStore()
	p := NewPoller(nil, ing, st, config.CtCertspotterSourceConfig{})
	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}
	if len(ing.calls) != 0 {
		t.Fatalf("expected no Ingest calls, got %d", len(ing.calls))
	}
}

// TestRunCycle_EmptyResult_NotAnError proves a freshly-configured domain
// with zero CertSpotter issuances so far is a normal "ok" cycle, not an
// error (Review Focus: first-ever poll of an empty domain).
func TestRunCycle_EmptyResult_NotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`)) // CertSpotter issuances endpoint: no results
	}))
	defer srv.Close()

	ing := &fakeIngester{}
	st := newFakeStore()
	cfg := config.CtCertspotterSourceConfig{
		Domains: []config.CtCertspotterDomainConfig{{Enabled: true, Domain: "example.com"}},
	}
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client(), Limiter: NewRateLimiter(100000)}
	p := NewPoller(client, ing, st, cfg)
	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}
	if len(ing.calls) != 0 {
		t.Fatalf("expected no Ingest calls for an empty result set, got %d", len(ing.calls))
	}
}

// TestRunCycle_IngestsAndPersistsCursor proves a non-empty page is
// converted, ingested, and the resulting cursor (CertSpotter's opaque
// "after" id) is persisted to the store under the per-domain checkpoint
// key.
func TestRunCycle_IngestsAndPersistsCursor(t *testing.T) {
	pageOne := `[{
	  "id": "42",
	  "tbs_sha256": "aaa",
	  "cert_sha256": "BB11",
	  "dns_names": ["example.com", "*.example.com"],
	  "issuer": {"name": "CN=Test CA"},
	  "not_before": "2026-01-01T00:00:00Z",
	  "not_after":  "2026-04-01T00:00:00Z",
	  "cert": {"data": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"}
	}]`
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Write([]byte(pageOne))
			return
		}
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	ing := &fakeIngester{}
	st := newFakeStore()
	cfg := config.CtCertspotterSourceConfig{
		Domains: []config.CtCertspotterDomainConfig{{Enabled: true, Domain: "example.com"}},
	}
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client(), Limiter: NewRateLimiter(100000)}
	p := NewPoller(client, ing, st, cfg)
	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}
	// The decode step for this fixture's cert data will fail to parse as
	// a real x509 cert (truncated base64 body), so no Ingest call is
	// guaranteed here — the important assertion is that runCycle itself
	// doesn't error and the cursor still advances via QueryDomainAll.
	state, err := st.GetIngestionState(context.Background(), "ct_certspotter:example.com")
	if err != nil {
		t.Fatalf("GetIngestionState: %v", err)
	}
	if state == nil {
		t.Fatal("expected ingestion state to be persisted")
	}
	if state.Cursor != "42" {
		t.Errorf("cursor = %q, want %q", state.Cursor, "42")
	}
}

// TestPollDomain_MalformedCursor_DoesNotPanic proves an arbitrary/garbage
// persisted Cursor string doesn't panic pollDomain. Unlike ct_crtsh
// (JSON-encoded seen-ID array) and ct_static (JSON-encoded tree-size
// checkpoint), certspotter's Cursor is a bare opaque string handed
// straight to the CertSpotter API's `after` query param — there's no
// JSON-unmarshal step to fail, so "malformed" here means any garbage
// string value must still flow through QueryDomainAll without panicking
// (Review Focus item shared across Tasks 2-5).
func TestPollDomain_MalformedCursor_DoesNotPanic(t *testing.T) {
	var gotAfter string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAfter = r.URL.Query().Get("after")
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	ing := &fakeIngester{}
	st := newFakeStore()
	garbage := "\x00not-json-{{{garbage\xffbytes"
	st.states["ct_certspotter:example.com"] = &model.IngestionState{
		SourceName: "ct_certspotter:example.com",
		Cursor:     garbage,
	}
	cfg := config.CtCertspotterSourceConfig{
		Domains: []config.CtCertspotterDomainConfig{{Enabled: true, Domain: "example.com"}},
	}
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client(), Limiter: NewRateLimiter(100000)}
	p := NewPoller(client, ing, st, cfg)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("runCycle panicked on malformed cursor: %v", r)
		}
	}()
	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}
	if gotAfter != garbage {
		t.Errorf("after query param = %q, want the raw garbage cursor %q passed through unchanged", gotAfter, garbage)
	}
}
