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

package multi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/ingest/ct"
)

type fakeIngester struct {
	calls   []*ingest.DiscoveryResult
	failFor string // if non-empty, Ingest returns an error when called with this Source
}

func (f *fakeIngester) Ingest(ctx context.Context, r *ingest.DiscoveryResult) (*ingest.IngestionSummary, error) {
	f.calls = append(f.calls, r)
	if f.failFor != "" && r.Source == f.failFor {
		return nil, errors.New("simulated ingest failure")
	}
	return &ingest.IngestionSummary{}, nil
}
func (f *fakeIngester) AttributeAssets(ctx context.Context, claims []ingest.OwnershipClaim) (int, int, error) {
	return 0, 0, nil
}

type fakeChildProvider struct {
	name    string
	entries []ct.CTEntry
}

func (f *fakeChildProvider) Name() string { return f.name }
func (f *fakeChildProvider) QueryDomain(ctx context.Context, domain string) ([]ct.CTEntry, error) {
	return f.entries, nil
}

// testEntry returns a CTEntry carrying a real, parseable ECDSA P-256 cert
// (ct.BuildCertDiscovery rejects entries whose PEM doesn't parse).
func testEntry(t *testing.T, cn, source string) ct.CTEntry {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}}, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	fp := sha256.Sum256(der)
	return ct.CTEntry{
		Fingerprint: hex.EncodeToString(fp[:]),
		PEM:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		CommonName:  cn,
		Source:      source,
	}
}

// TestPoll_GroupsByChildSource proves the LOAD-BEARING per-child grouping:
// entries from two different children must produce two separate Ingest
// calls, each with DiscoveryResult.Source matching the entry's originating
// provider, not a single merged "ct_multi"-sourced batch.
func TestPoll_GroupsByChildSource(t *testing.T) {
	composer := &Composer{
		Domain: "example.com",
		Children: []ct.Provider{
			&fakeChildProvider{name: "crtsh", entries: []ct.CTEntry{testEntry(t, "a.example.com", "ct_crtsh")}},
			&fakeChildProvider{name: "static", entries: []ct.CTEntry{testEntry(t, "b.example.com", "ct_static")}},
		},
	}
	ing := &fakeIngester{}
	p := &Poller{Composer: map[string]*Composer{"example.com": composer}, Ingester: ing}

	if err := p.runCycle(context.Background(), "example.com"); err != nil {
		t.Fatalf("runCycle: %v", err)
	}
	if len(ing.calls) != 2 {
		t.Fatalf("expected 2 Ingest calls (one per child source), got %d", len(ing.calls))
	}
	sources := map[string]bool{}
	for _, c := range ing.calls {
		sources[c.Source] = true
		if len(c.Certificates) != 1 {
			t.Errorf("expected 1 cert per per-child batch, got %d for source %q", len(c.Certificates), c.Source)
			continue
		}
		// Final-review Fix 7: the full parse must populate the fields the
		// risk scorer grades, not just CN/dates/SANs.
		d := c.Certificates[0]
		if d.Source != c.Source || d.StoreType != "ct_log" {
			t.Errorf("Source/StoreType = %q/%q, want %q/ct_log", d.Source, d.StoreType, c.Source)
		}
		if d.KeyAlgorithm != "ECDSA" || d.KeySizeBits != 256 || d.SignatureAlgorithm != "ECDSAWithSHA256" || d.SerialNumber != "2a" {
			t.Errorf("scoring fields not populated for %s: KeyAlgorithm=%q KeySizeBits=%d SignatureAlgorithm=%q SerialNumber=%q",
				c.Source, d.KeyAlgorithm, d.KeySizeBits, d.SignatureAlgorithm, d.SerialNumber)
		}
		if d.IssuerCN != "Test CA" || d.FilePath != c.Source+":"+d.FingerprintSHA256 {
			t.Errorf("IssuerCN=%q FilePath=%q", d.IssuerCN, d.FilePath)
		}
	}
	if !sources["ct_crtsh"] || !sources["ct_static"] {
		t.Fatalf("expected Ingest calls stamped ct_crtsh and ct_static, got %v", sources)
	}
}

// An entry whose PEM doesn't parse is skipped (logged) without dropping
// the same child's parseable entries.
func TestPoll_UnparseableEntry_SkippedOthersIngested(t *testing.T) {
	composer := &Composer{
		Domain: "example.com",
		Children: []ct.Provider{
			&fakeChildProvider{name: "certspotter", entries: []ct.CTEntry{
				{Fingerprint: "bad", PEM: []byte("not a pem"), Source: "ct_certspotter"},
				testEntry(t, "ok.example.com", "ct_certspotter"),
			}},
		},
	}
	ing := &fakeIngester{}
	p := &Poller{Composer: map[string]*Composer{"example.com": composer}, Ingester: ing}
	if err := p.runCycle(context.Background(), "example.com"); err != nil {
		t.Fatalf("runCycle: %v", err)
	}
	if len(ing.calls) != 1 || len(ing.calls[0].Certificates) != 1 || ing.calls[0].Certificates[0].SubjectCN != "ok.example.com" {
		t.Fatalf("want exactly the parseable cert ingested, got %+v", ing.calls)
	}
}

// TestPoll_OneChildIngestFailure_DoesNotBlockOtherChild proves the other
// half of the Review Focus isolation requirement: within one group, one
// child's Ingest failing must not prevent the group's other children from
// being ingested. runCycle must still attempt (and here, succeed at) the
// second child's Ingest call even though the first child's call errored.
func TestPoll_OneChildIngestFailure_DoesNotBlockOtherChild(t *testing.T) {
	composer := &Composer{
		Domain: "example.com",
		Children: []ct.Provider{
			&fakeChildProvider{name: "crtsh", entries: []ct.CTEntry{testEntry(t, "a.example.com", "ct_crtsh")}},
			&fakeChildProvider{name: "static", entries: []ct.CTEntry{testEntry(t, "b.example.com", "ct_static")}},
		},
	}
	ing := &fakeIngester{failFor: "ct_crtsh"}
	p := &Poller{Composer: map[string]*Composer{"example.com": composer}, Ingester: ing}

	if err := p.runCycle(context.Background(), "example.com"); err != nil {
		t.Fatalf("runCycle should not propagate a per-child ingest failure: %v", err)
	}
	if len(ing.calls) != 2 {
		t.Fatalf("expected both children's Ingest to be attempted despite one failing, got %d calls", len(ing.calls))
	}
	sources := map[string]bool{}
	for _, c := range ing.calls {
		sources[c.Source] = true
	}
	if !sources["ct_crtsh"] || !sources["ct_static"] {
		t.Fatalf("expected Ingest attempted for both ct_crtsh and ct_static, got %v", sources)
	}
}

// TestRunOneCycleSafely_OneGroupFailure_DoesNotBlockOtherGroup proves the
// multi-domain isolation half of the Review Focus item: one configured
// group's cycle failing must not prevent runOneCycleSafely from still
// running the other configured group. "bad.com"'s children are
// deliberately empty tagged-union entries (no Crtsh/Static/Certspotter
// set), which makes buildChildren fail immediately in-process — this
// keeps the test hermetic (no real crtsh/static network client is ever
// constructed) while still exercising the runCycle error path that
// runOneCycleSafely must log-and-continue past.
func TestRunOneCycleSafely_OneGroupFailure_DoesNotBlockOtherGroup(t *testing.T) {
	okComposer := &Composer{
		Domain: "good.com",
		Children: []ct.Provider{
			&fakeChildProvider{name: "crtsh", entries: []ct.CTEntry{testEntry(t, "a.good.com", "ct_crtsh")}},
			&fakeChildProvider{name: "static", entries: []ct.CTEntry{testEntry(t, "b.good.com", "ct_static")}},
		},
	}
	ing := &fakeIngester{}
	p := &Poller{
		Composer: map[string]*Composer{"good.com": okComposer}, // "bad.com" deliberately has no cached Composer, forcing buildChildren
		Ingester: ing,
		cfg: config.CtMultiSourceConfig{
			Groups: []config.CtMultiGroupConfig{
				{Enabled: true, Domain: "bad.com", Children: []config.CtMultiChildConfig{{}, {}}},
				{Enabled: true, Domain: "good.com", Children: []config.CtMultiChildConfig{
					{Crtsh: &config.CtMultiChildCrtshConfig{}},
					{Static: &config.CtMultiChildStaticConfig{}},
				}},
			},
		},
	}

	p.runOneCycleSafely(context.Background())

	if len(ing.calls) != 2 {
		t.Fatalf("expected good.com's 2 per-child Ingest calls despite bad.com failing to build a Composer, got %d", len(ing.calls))
	}
	sources := map[string]bool{}
	for _, c := range ing.calls {
		sources[c.Source] = true
	}
	if !sources["ct_crtsh"] || !sources["ct_static"] {
		t.Fatalf("expected good.com's children ingested, got %v", sources)
	}
}
