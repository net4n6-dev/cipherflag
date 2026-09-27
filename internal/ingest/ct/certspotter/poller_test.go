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

package certspotter

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

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

// generateTestCertDER returns a minimal, self-signed, valid DER
// certificate for cn — used wherever a test needs an issuance whose
// cert.data actually decodes via issuanceToCTEntry's x509.ParseCertificate
// step (unlike the truncated placeholder base64 used by client_test.go's
// pageOne fixture, whose tests never reach that parse step).
func generateTestCertDER(t *testing.T, cn string) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

// issuanceJSON builds a single-entry CertSpotter /v1/issuances JSON page
// wrapping der as the (valid, decodable) cert.data payload.
func issuanceJSON(id, domain string, der []byte) string {
	sum := sha256.Sum256(der)
	certB64 := base64.StdEncoding.EncodeToString(der)
	return fmt.Sprintf(`[{
		"id": %q,
		"tbs_sha256": "aaa",
		"cert_sha256": %q,
		"dns_names": [%q],
		"issuer": {"name": "CN=Test CA"},
		"not_before": "2026-01-01T00:00:00Z",
		"not_after": "2026-04-01T00:00:00Z",
		"cert": {"data": %q}
	}]`, id, hex.EncodeToString(sum[:]), domain, certB64)
}

// captureLogs swaps the global zerolog logger for one writing into a
// buffer for the duration of the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	orig := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = orig })
	return &buf
}

// TestClient_NilHTTP_UsesDefaultClient is the unit-level regression for
// the final-review Critical finding: a Client with no HTTP field used to
// call (*http.Client)(nil).Do and panic.
func TestClient_NilHTTP_UsesDefaultClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, Limiter: NewRateLimiter(3600000)} // HTTP deliberately nil
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("QueryDomain panicked with nil HTTP client: %v", r)
		}
	}()
	if _, _, err := c.QueryDomain(context.Background(), "example.com", true, ""); err != nil {
		t.Fatalf("QueryDomain: %v", err)
	}
}

// TestRunOneCycleSafely_ProductionNilClientPath_IngestsWithoutPanic
// drives the exact production construction path from
// cmd/cipherflag/main.go — certspotter.NewPoller(nil, ...) — so
// pollDomain lazily builds its own Client (no HTTP field). Before the
// fix this panicked on every cycle, runOneCycleSafely swallowed the
// panic, and nothing was ever ingested. Only the base URL is redirected
// (defaultBaseURL) — everything else is the real production code path.
func TestRunOneCycleSafely_ProductionNilClientPath_IngestsWithoutPanic(t *testing.T) {
	der := generateTestCertDER(t, "example.com")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after") == "" {
			w.Write([]byte(issuanceJSON("42", "example.com", der)))
			return
		}
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	origBase := defaultBaseURL
	defaultBaseURL = srv.URL
	t.Cleanup(func() { defaultBaseURL = origBase })
	logs := captureLogs(t)

	ing := &fakeIngester{}
	st := newFakeStore()
	cfg := config.CtCertspotterSourceConfig{
		Domains: []config.CtCertspotterDomainConfig{{Enabled: true, Domain: "example.com", RequestsPerHour: 3600000}},
	}
	p := NewPoller(nil, ing, st, cfg) // client == nil: the production path

	p.runOneCycleSafely(context.Background())

	if strings.Contains(logs.String(), "panic recovered") {
		t.Fatalf("runOneCycleSafely recovered a panic; logs:\n%s", logs.String())
	}
	if len(ing.calls) != 1 || len(ing.calls[0].Certificates) != 1 {
		t.Fatalf("expected 1 Ingest call with 1 cert via the nil-client production path, got %d calls; logs:\n%s", len(ing.calls), logs.String())
	}
	if st.states["ct_certspotter:example.com"] == nil || st.states["ct_certspotter:example.com"].Cursor != "42" {
		t.Errorf("expected cursor 42 persisted, got %+v", st.states["ct_certspotter:example.com"])
	}
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

// TestRunCycle_CursorPersists_EvenWhenIssuanceDecodeFails proves the
// cursor still advances to the page's last id when the page's only
// issuance fails to decode (this fixture's cert.data is the same
// truncated placeholder base64 used by client_test.go's pageOne, which
// deliberately does not parse as a real x509 cert). This test does NOT
// prove a cert is ever ingested — see
// TestRunCycle_ValidIssuance_IngestsAndPersistsCursor below for the real
// "parse a valid cert -> build DiscoveryResult -> call Ingest" path.
func TestRunCycle_CursorPersists_EvenWhenIssuanceDecodeFails(t *testing.T) {
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
	// The decode step for this fixture's cert data fails to parse as a
	// real x509 cert (truncated base64 body), so no Ingest call happens
	// — assert that explicitly, since the poller's len(certs) > 0 guard
	// skips Ingest entirely when every issuance in the page fails to
	// decode.
	if len(ing.calls) != 0 {
		t.Fatalf("expected no Ingest calls when the only issuance fails to decode, got %d", len(ing.calls))
	}
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

// TestRunCycle_ValidIssuance_IngestsAndPersistsCursor proves the real
// happy path: a page with one valid, decodable cert is converted to a
// dedup.CertDiscovery, Ingest is actually called with it, and the
// resulting cursor is persisted to the per-domain checkpoint key.
func TestRunCycle_ValidIssuance_IngestsAndPersistsCursor(t *testing.T) {
	der := generateTestCertDER(t, "example.com")
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Write([]byte(issuanceJSON("42", "example.com", der)))
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

	if len(ing.calls) != 1 {
		t.Fatalf("expected exactly 1 Ingest call for the valid issuance, got %d", len(ing.calls))
	}
	if got := len(ing.calls[0].Certificates); got != 1 {
		t.Fatalf("expected 1 certificate ingested, got %d", got)
	}
	cert := ing.calls[0].Certificates[0]
	if cert.SubjectCN != "example.com" {
		t.Errorf("SubjectCN = %q, want %q", cert.SubjectCN, "example.com")
	}
	if cert.RawPEM == "" {
		t.Error("RawPEM unexpectedly empty")
	}

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

// TestRunCycle_OneDomainFails_DoesNotBlockOthers proves the isolation
// property runCycle is named for (Review Focus item shared with Tasks
// 2/3: multi-domain isolation): the first configured domain's query
// always fails with a non-retryable 400, while the second domain
// succeeds and has one net-new (valid, decodable) cert. The only way to
// prove runCycle doesn't abort after the first domain's failure is to
// assert the second domain was actually reached and ingested. Hermetic
// (httptest.Server) — no live network, runs in milliseconds.
func TestRunCycle_OneDomainFails_DoesNotBlockOthers(t *testing.T) {
	const failDomain = "fail.example.com"
	const okDomain = "ok.example.com"
	der := generateTestCertDER(t, okDomain)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("domain") == failDomain {
			w.WriteHeader(http.StatusBadRequest) // non-retryable: no retry loop
			return
		}
		if q.Get("after") == "" {
			w.Write([]byte(issuanceJSON("7", okDomain, der)))
			return
		}
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	ing := &fakeIngester{}
	st := newFakeStore()
	cfg := config.CtCertspotterSourceConfig{
		Domains: []config.CtCertspotterDomainConfig{
			{Enabled: true, Domain: failDomain},
			{Enabled: true, Domain: okDomain},
		},
	}
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client(), Limiter: NewRateLimiter(100000)}
	p := NewPoller(client, ing, st, cfg)

	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}

	if len(ing.calls) != 1 {
		t.Fatalf("expected exactly 1 Ingest call (from the surviving domain) despite the first domain's failure, got %d", len(ing.calls))
	}
	if got := len(ing.calls[0].Certificates); got != 1 {
		t.Fatalf("expected 1 certificate ingested from %s, got %d", okDomain, got)
	}
	if st.states["ct_certspotter:"+okDomain] == nil {
		t.Fatalf("expected an ingestion_state checkpoint for the surviving domain %s", okDomain)
	}
	if state := st.states["ct_certspotter:"+okDomain]; state.Cursor != "7" {
		t.Errorf("surviving domain cursor = %q, want %q", state.Cursor, "7")
	}
	if st.states["ct_certspotter:"+failDomain] != nil {
		t.Fatalf("did not expect a checkpoint for the failed domain %s (query never succeeded)", failDomain)
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
