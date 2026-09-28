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

package crtsh

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

type fakeIngester struct {
	calls []*ingest.DiscoveryResult
}

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

// generateTestCertPEM returns a minimal, self-signed, valid PEM
// certificate for cn — used wherever a test needs a cert that
// certparse.ParseDER can actually parse (unlike the placeholder
// "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
// strings used by client_test.go, whose tests never reach parsePEM).
func generateTestCertPEM(t *testing.T, cn string) string {
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
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestRunCycle_NoDomains_NoOp(t *testing.T) {
	ing := &fakeIngester{}
	st := newFakeStore()
	p := NewPoller(nil, ing, st, config.CtCrtshSourceConfig{})
	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}
	if len(ing.calls) != 0 {
		t.Fatalf("expected no Ingest calls for zero configured domains, got %d", len(ing.calls))
	}
}

// TestRunCycle_OneDomainFails_DoesNotBlockOthers proves the isolation
// property runCycle is named for (Review Focus: multi-domain isolation):
// domain 1's crt.sh query always fails with a non-retryable 500, while
// domain 2 succeeds and has one net-new cert. The only way to prove
// runCycle doesn't abort after domain 1's failure is to assert domain
// 2 was actually reached and ingested — a prior version of this test
// only asserted "no panic", which passes identically even if isolation
// were broken. Hermetic (httptest.Server, pollerOverrides) — no live
// network, runs in milliseconds.
func TestRunCycle_OneDomainFails_DoesNotBlockOthers(t *testing.T) {
	const failDomain = "fail.example.com"
	const okDomain = "ok.example.com"
	certPEM := generateTestCertPEM(t, okDomain)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if d := q.Get("d"); d != "" {
			// FetchPEM call — only ever made for the surviving domain's
			// single entry (id=1).
			_, _ = w.Write([]byte(certPEM))
			return
		}
		domain := q.Get("q")
		if strings.Contains(domain, "fail") {
			w.WriteHeader(http.StatusInternalServerError) // non-transient: no retry loop
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id": 1, "common_name": "` + okDomain + `", "name_value": "` + okDomain + `", "issuer_name": "Test CA", "not_before": "2026-01-01T00:00:00", "not_after": "2026-04-01T00:00:00", "entry_timestamp": "2026-01-01T00:00:00"}]`))
	}))
	defer srv.Close()

	ing := &fakeIngester{}
	st := newFakeStore()
	cfg := config.CtCrtshSourceConfig{
		Domains: []config.CtDomainConfig{
			{Enabled: true, Domain: failDomain},
			{Enabled: true, Domain: okDomain},
		},
	}
	p := NewPoller(nil, ing, st, cfg)
	p.overrides = &pollerOverrides{
		client: &Client{BaseURL: srv.URL, HTTPClient: srv.Client()},
		pemGap: time.Millisecond,
	}

	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}

	if len(ing.calls) != 1 {
		t.Fatalf("expected exactly 1 Ingest call (from the surviving domain) despite the first domain's failure, got %d", len(ing.calls))
	}
	if got := len(ing.calls[0].Certificates); got != 1 {
		t.Fatalf("expected 1 certificate ingested from %s, got %d", okDomain, got)
	}
	if st.states["ct_crtsh:"+okDomain] == nil {
		t.Fatalf("expected an ingestion_state checkpoint for the surviving domain %s", okDomain)
	}
	if st.states["ct_crtsh:"+failDomain] != nil {
		t.Fatalf("did not expect a checkpoint for the failed domain %s (query never succeeded)", failDomain)
	}
}

// Final-review Fix 6: a transient PEM-fetch failure must NOT permanently
// blacklist the cert. Cycle 1: id=2's PEM fetch returns 502 on every
// attempt (retries exhausted), id=3's PEM fetches fine but is garbage.
// Cycle 2: crt.sh has recovered. id=2 must be fetched again and ingested;
// id=1 (ingested) and id=3 (fetched-but-unparseable) must not be refetched.
func TestPollDomain_TransientPEMFetchFailure_RetriedNextCycle(t *testing.T) {
	const domain = "example.com"
	pem1 := generateTestCertPEM(t, "one."+domain)
	pem2 := generateTestCertPEM(t, "two."+domain)

	var (
		mu         sync.Mutex
		recovered  bool
		pemFetches = map[string]int{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if id := q.Get("d"); id != "" {
			mu.Lock()
			pemFetches[id]++
			ok := recovered
			mu.Unlock()
			switch id {
			case "1":
				_, _ = w.Write([]byte(pem1))
			case "2":
				if !ok {
					w.WriteHeader(http.StatusBadGateway) // transient
					return
				}
				_, _ = w.Write([]byte(pem2))
			case "3":
				_, _ = w.Write([]byte("<html>not a certificate</html>"))
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id": 1, "common_name": "one.example.com"}, {"id": 2, "common_name": "two.example.com"}, {"id": 3, "common_name": "three.example.com"}]`))
	}))
	defer srv.Close()

	ing := &fakeIngester{}
	st := newFakeStore()
	dcfg := config.CtDomainConfig{Enabled: true, Domain: domain}
	p := NewPoller(nil, ing, st, config.CtCrtshSourceConfig{Domains: []config.CtDomainConfig{dcfg}})
	p.overrides = &pollerOverrides{
		client: &Client{BaseURL: srv.URL, HTTPClient: srv.Client(), BackoffBase: time.Millisecond},
		pemGap: time.Millisecond,
	}
	ctx := context.Background()

	// Cycle 1: id=2 fails transiently.
	if err := p.pollDomain(ctx, dcfg); err != nil {
		t.Fatalf("cycle 1: %v", err)
	}
	if len(ing.calls) != 1 || len(ing.calls[0].Certificates) != 1 || ing.calls[0].Certificates[0].SubjectCN != "one."+domain {
		t.Fatalf("cycle 1 should ingest only id=1, got %+v", ing.calls)
	}
	var ids []int64
	if err := json.Unmarshal([]byte(st.states["ct_crtsh:"+domain].Cursor), &ids); err != nil {
		t.Fatalf("cursor: %v", err)
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []int64{1, 3}) {
		t.Fatalf("cycle 1 seen-set = %v, want [1 3] (id=2's failed fetch must not be recorded)", ids)
	}

	// Cycle 2: crt.sh recovered.
	mu.Lock()
	recovered = true
	mu.Unlock()
	if err := p.pollDomain(ctx, dcfg); err != nil {
		t.Fatalf("cycle 2: %v", err)
	}
	if len(ing.calls) != 2 || len(ing.calls[1].Certificates) != 1 || ing.calls[1].Certificates[0].SubjectCN != "two."+domain {
		t.Fatalf("cycle 2 should ingest id=2 (retried after the transient failure), got %+v", ing.calls)
	}
	ids = nil
	if err := json.Unmarshal([]byte(st.states["ct_crtsh:"+domain].Cursor), &ids); err != nil {
		t.Fatalf("cursor: %v", err)
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []int64{1, 2, 3}) {
		t.Errorf("cycle 2 seen-set = %v, want [1 2 3]", ids)
	}
	mu.Lock()
	defer mu.Unlock()
	if pemFetches["1"] != 1 || pemFetches["3"] != 1 {
		t.Errorf("already-handled IDs refetched: fetches = %v (want id 1 and 3 fetched exactly once)", pemFetches)
	}
	if pemFetches["2"] < 2 {
		t.Errorf("id=2 fetched %d times, want retries in cycle 1 plus a fetch in cycle 2", pemFetches["2"])
	}
}

func TestRunCycle_EmptyResult_NotAnError(t *testing.T) {
	ing := &fakeIngester{}
	st := newFakeStore()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	cfg := config.CtCrtshSourceConfig{
		Domains: []config.CtDomainConfig{
			{Enabled: true, Domain: "example.com"},
		},
	}
	p := NewPoller(nil, ing, st, cfg)
	p.overrides = &pollerOverrides{
		client: &Client{BaseURL: srv.URL, HTTPClient: srv.Client()},
		pemGap: time.Millisecond,
	}

	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}
	if len(ing.calls) != 0 {
		t.Fatalf("expected no Ingest calls for an empty crt.sh result, got %d", len(ing.calls))
	}
	state := st.states["ct_crtsh:example.com"]
	if state == nil {
		t.Fatalf("expected an ingestion_state checkpoint to be written even for an empty result")
	}
	if state.Cursor != "[]" {
		t.Fatalf("expected an empty-array cursor, got %q", state.Cursor)
	}
}

// TestPollDomain_MalformedCursor_ResetsRatherThanPanics proves a corrupted
// persisted ingestion_state.cursor (Review Focus: malformed checkpoint —
// e.g. hand-edited, or written by a different kind by mistake) logs and
// resets the seen-ID set instead of panicking the poller goroutine.
// Hermetic — a fake crt.sh server backs the client override so this
// never touches the live network.
func TestPollDomain_MalformedCursor_ResetsRatherThanPanics(t *testing.T) {
	ing := &fakeIngester{}
	st := newFakeStore()
	st.states["ct_crtsh:example.com"] = &model.IngestionState{
		SourceName: "ct_crtsh:example.com",
		Cursor:     "{not valid json array",
	}
	cfg := config.CtCrtshSourceConfig{
		Domains: []config.CtDomainConfig{{Enabled: true, Domain: "example.com"}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	p := NewPoller(nil, ing, st, cfg)
	p.overrides = &pollerOverrides{
		client: &Client{BaseURL: srv.URL, HTTPClient: srv.Client()},
		pemGap: time.Millisecond,
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("pollDomain panicked on malformed cursor: %v", r)
		}
	}()
	if err := p.pollDomain(context.Background(), cfg.Domains[0]); err != nil {
		t.Fatalf("pollDomain: %v", err)
	}
}

// TestPoller_QueryDomain_SatisfiesProvider proves crtsh.Poller implements
// ct.Provider (Task 5's ct_multi puts *crtsh.Poller directly into a
// []ct.Provider slice) — QueryDomain converts crt.sh entries into the
// normalised ct.CTEntry shape, and Name() reports the stable "crtsh"
// provider id. See also the package-level `var _ ct.Provider =
// (*Poller)(nil)` compile-time assertion in poller.go.
func TestPoller_QueryDomain_SatisfiesProvider(t *testing.T) {
	certPEM := generateTestCertPEM(t, "a.example.com")

	cases := []struct {
		name      string
		queryBody string
		queryFail bool
		wantCount int
		wantErr   bool
	}{
		{
			name:      "happy path returns normalised CTEntry",
			queryBody: `[{"id": 1, "common_name": "a.example.com", "name_value": "a.example.com", "issuer_name": "Test CA", "not_before": "2026-01-01T00:00:00", "not_after": "2026-04-01T00:00:00", "entry_timestamp": "2026-01-01T00:00:00"}]`,
			wantCount: 1,
		},
		{
			name:      "empty result is not an error",
			queryBody: `[]`,
			wantCount: 0,
		},
		{
			name:      "query failure propagates as an error",
			queryFail: true,
			wantErr:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("d") != "" {
					_, _ = w.Write([]byte(certPEM))
					return
				}
				if tc.queryFail {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.queryBody))
			}))
			defer srv.Close()

			p := NewPoller(nil, &fakeIngester{}, newFakeStore(), config.CtCrtshSourceConfig{})
			p.overrides = &pollerOverrides{
				client: &Client{BaseURL: srv.URL, HTTPClient: srv.Client()},
				pemGap: time.Millisecond,
			}

			entries, err := p.QueryDomain(context.Background(), "a.example.com")
			if (err != nil) != tc.wantErr {
				t.Fatalf("QueryDomain error = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if len(entries) != tc.wantCount {
				t.Fatalf("entries len = %d, want %d", len(entries), tc.wantCount)
			}
			if tc.wantCount > 0 {
				// CTEntry.Source must match pollDomain's
				// DiscoveryResult.Source ("ct_crtsh") — ct_multi's
				// composer groups by CTEntry.Source and stamps it
				// directly as DiscoveryResult.Source, so this must not
				// drift from the standalone path's provenance string.
				if entries[0].Source != "ct_crtsh" {
					t.Errorf("entries[0].Source = %q, want %q", entries[0].Source, "ct_crtsh")
				}
				if entries[0].Fingerprint == "" {
					t.Errorf("entries[0].Fingerprint is empty")
				}
				if len(entries[0].PEM) == 0 {
					t.Errorf("entries[0].PEM is empty")
				}
			}
		})
	}
}

func TestPoller_Name(t *testing.T) {
	p := &Poller{}
	if got := p.Name(); got != "crtsh" {
		t.Errorf("Name() = %q, want %q", got, "crtsh")
	}
}
