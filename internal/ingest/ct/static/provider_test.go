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
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/tlog"
)

// Most walk tests below start from Cache{LastTreeSize: 1} with a
// non-matching leaf at index 0: a zero cursor means "no persisted
// state" and bootstraps to the head without walking (see
// TestProvider_QueryDomain_NoPriorCursor_BootstrapsToHead), so a walk
// test needs a real, non-zero starting position — exactly as the poller
// has after its first cycle.

// End-to-end provider test against a spec-faithful fake Sunlight log:
// one non-matching leaf before the cursor, then a cert with example.com
// in SAN and one without. QueryDomain returns exactly the matching cert.
// The 3-leaf log's only data tile is partial, so it must be fetched at
// tile/data/000.p/3 (the full URL 404s, as on a real log).
func TestProvider_QueryDomain_FiltersBySAN(t *testing.T) {
	certs := []*x509.Certificate{
		mustGenerateLeafCert(t, "before-cursor", []string{"example.com"}), // index 0: already seen
		mustGenerateLeafCert(t, "match", []string{"example.com", "api.example.com"}),
		mustGenerateLeafCert(t, "miss", []string{"other.test"}),
	}
	fl := newFakeLogFromCerts(t, certs)
	prov := fl.newProvider("example.com", &Cache{LastTreeSize: 1})

	got, err := prov.QueryDomain(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("QueryDomain: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("entries = %d, want 1 (only the matching cert after the cursor)", len(got))
	}
	if got[0].Source != "ct_static" {
		t.Errorf("Source = %q, want ct_static", got[0].Source)
	}
	if got[0].CommonName != "match" {
		t.Errorf("CommonName = %q, want match", got[0].CommonName)
	}
	if got[0].Fingerprint == "" || len(got[0].PEM) == 0 {
		t.Errorf("missing Fingerprint or PEM: %+v", got[0])
	}
	if prov.LastSeenTreeSize != 3 || prov.LastVerifiedCount != 1 {
		t.Errorf("LastSeenTreeSize=%d LastVerifiedCount=%d, want 3 and 1", prov.LastSeenTreeSize, prov.LastVerifiedCount)
	}
	if reqs := fl.requestLog(); !slices.Contains(reqs, "/2024h2/tile/data/000.p/3") {
		t.Errorf("partial data tile URL not requested; requests: %v", reqs)
	}
}

func TestProvider_Name_ReturnsStatic(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "static" {
		t.Errorf("Name() = %q, want static", got)
	}
}

// Final-review Fix 2(b)/(c): with no prior cursor — Cache nil (always
// the case under ct_multi) or LastTreeSize 0 (the standalone poller's
// "no ingestion_state row yet") — QueryDomain must NOT walk the log from
// leaf 0. A real Sunlight shard has hundreds of millions of leaves. It
// bootstraps LastSeenTreeSize to the current head and fetches zero tiles,
// even though matching certs exist in the historical range.
func TestProvider_QueryDomain_NoPriorCursor_BootstrapsToHead(t *testing.T) {
	const treeSize = 600
	leaves := fillerLeaves(t, treeSize)
	// Put matching certs in the historical range: they must NOT be returned.
	hist := buildTestLeafData([]*x509.Certificate{
		mustGenerateLeafCert(t, "historical-a", []string{"example.com"}),
		mustGenerateLeafCert(t, "historical-b", []string{"example.com"}),
	})
	leaves[10], leaves[400] = hist[0], hist[1]
	fl := newFakeLog(t, leaves)

	for _, tc := range []struct {
		name  string
		cache *Cache
	}{
		{"nil cache (ct_multi child)", nil},
		{"zero cursor (standalone first cycle)", &Cache{LastTreeSize: 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fl.requestLog() // reset
			prov := fl.newProvider("example.com", tc.cache)
			got, err := prov.QueryDomain(context.Background(), "example.com")
			if err != nil {
				t.Fatalf("QueryDomain: %v", err)
			}
			if got != nil {
				t.Errorf("got %d entries, want nil (bootstrap walks nothing)", len(got))
			}
			if tiles := tileRequests(fl.requestLog()); len(tiles) != 0 {
				t.Errorf("bootstrap fetched %d tiles, want 0: %v", len(tiles), tiles)
			}
			if prov.LastSeenTreeSize != treeSize {
				t.Errorf("LastSeenTreeSize = %d, want %d (bootstrapped to head)", prov.LastSeenTreeSize, treeSize)
			}
			if prov.LastVerifiedCount != 0 {
				t.Errorf("LastVerifiedCount = %d, want 0", prov.LastVerifiedCount)
			}
		})
	}
}

// The ct_multi path: a long-lived Provider with Cfg.Cache == nil. Call 1
// bootstraps at the head (600); the log grows to 603; call 2 walks ONLY
// the new leaves (data tile 2, requested as the partial 002.p/91) and
// returns the two new matches with verified inclusion proofs; call 3
// with no growth fetches nothing.
//
// Leaf 600's proof in a 603-leaf tree needs Merkle hashes above level 7,
// which a real log serves only in the level-1 hash tile (tile/1/000.p/2,
// holding Merkle level-8 hashes). So this also pins the tile geometry fix
// in hashreader.go.
func TestProvider_QueryDomain_InstanceCursor_WatchesForwardAcrossCalls(t *testing.T) {
	leaves := fillerLeaves(t, 603)
	news := buildTestLeafData([]*x509.Certificate{
		mustGenerateLeafCert(t, "new-600", []string{"example.com"}),
		mustGenerateLeafCert(t, "new-602", []string{"www.example.com"}),
	})
	leaves[600], leaves[602] = news[0], news[1]
	fl := newFakeLog(t, leaves)
	fl.setSize(600)

	prov := fl.newProvider("example.com", nil)
	ctx := context.Background()

	if got, err := prov.QueryDomain(ctx, "example.com"); err != nil || got != nil {
		t.Fatalf("call 1 (bootstrap): got %v, %v; want nil, nil", got, err)
	}
	if tiles := tileRequests(fl.requestLog()); len(tiles) != 0 {
		t.Fatalf("call 1 fetched tiles %v, want none", tiles)
	}

	fl.setSize(603)
	got, err := prov.QueryDomain(ctx, "example.com")
	if err != nil {
		t.Fatalf("call 2: %v", err)
	}
	var cns []string
	for _, e := range got {
		cns = append(cns, e.CommonName)
	}
	slices.Sort(cns)
	if !slices.Equal(cns, []string{"new-600", "new-602"}) {
		t.Fatalf("call 2 entries = %v, want [new-600 new-602]", cns)
	}
	if prov.LastVerifiedCount != 2 || prov.LastProofFetchFailures != 0 {
		t.Errorf("LastVerifiedCount=%d LastProofFetchFailures=%d, want 2 and 0", prov.LastVerifiedCount, prov.LastProofFetchFailures)
	}
	if prov.LastSeenTreeSize != 603 {
		t.Errorf("LastSeenTreeSize = %d, want 603", prov.LastSeenTreeSize)
	}
	reqs := tileRequests(fl.requestLog())
	for _, old := range []string{"/2024h2/tile/data/000", "/2024h2/tile/data/001"} {
		for _, r := range reqs {
			if strings.HasPrefix(r, old) {
				t.Errorf("call 2 re-fetched historical data tile %s", r)
			}
		}
	}
	for _, want := range []string{"/2024h2/tile/data/002.p/91", "/2024h2/tile/1/000.p/2"} {
		if !slices.Contains(reqs, want) {
			t.Errorf("call 2 did not request %s; requests: %v", want, reqs)
		}
	}

	if got, err := prov.QueryDomain(ctx, "example.com"); err != nil || got != nil {
		t.Fatalf("call 3 (no growth): got %v, %v; want nil, nil", got, err)
	}
	if tiles := tileRequests(fl.requestLog()); len(tiles) != 0 {
		t.Errorf("call 3 fetched tiles %v, want none", tiles)
	}
}

// A log that has grown past our checkpoint may prune a partial tile once
// its full tile exists. FetchLeafTile (and the hash-tile reader) must then
// fall back to the full URL. Published size 300 (tile 1 partial, W=44),
// but the log holds 520 entries and has pruned partial tile 1.
func TestProvider_QueryDomain_PrunedPartialTile_FallsBackToFullTile(t *testing.T) {
	leaves := fillerLeaves(t, 520)
	leaves[270] = buildTestLeafData([]*x509.Certificate{mustGenerateLeafCert(t, "match-270", []string{"example.com"})})[0]
	fl := newFakeLog(t, leaves)
	fl.setSize(300)
	fl.configure(func(f *fakeLog) { f.prunePartials = true })

	prov := fl.newProvider("example.com", &Cache{LastTreeSize: 256})
	got, err := prov.QueryDomain(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("QueryDomain: %v", err)
	}
	if len(got) != 1 || got[0].CommonName != "match-270" {
		t.Fatalf("got %+v, want exactly match-270", got)
	}
	if prov.LastSeenTreeSize != 300 {
		t.Errorf("LastSeenTreeSize = %d, want 300 (leaves beyond the checkpoint in the full tile are ignored)", prov.LastSeenTreeSize)
	}
	reqs := fl.requestLog()
	for _, want := range []string{"/2024h2/tile/data/001.p/44", "/2024h2/tile/data/001", "/2024h2/tile/0/001.p/44", "/2024h2/tile/0/001"} {
		if !slices.Contains(reqs, want) {
			t.Errorf("expected request %s; requests: %v", want, reqs)
		}
	}
}

// --- helpers (file-local; mirror test patterns used in sth_test.go) ---

func mustGenerateLeafCert(t *testing.T, cn string, sans []string) *x509.Certificate {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		Issuer:                pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              sans,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	cert.Raw = der
	return cert
}

// buildTestLeafData materialises the LeafData records that both the
// data-tile builder (buildTestTile) and the fake-tree leaf-hash builder
// (fakeTreeLeafHash) consume. Capturing them once — with the same
// per-cert Timestamp — guarantees the bytes the fake server emits in
// the data tile and the bytes hashed into the fake-tree leaves agree
// exactly, so verifyLeafInclusion's EncodeTileLeaf computation in
// production matches the seeded leaf hashes.
//
// All test corpus entries are x509_entry leaves (EntryType=0); extensions
// and chain fingerprints are empty (v1.25.x test corpus exercises tree
// math + parser, not the §1.1.5 leaf_index ext or chain attribution).
func buildTestLeafData(certs []*x509.Certificate) []LeafData {
	now := uint64(time.Now().UnixMilli())
	out := make([]LeafData, len(certs))
	for i, c := range certs {
		out[i] = LeafData{
			Timestamp:   now,
			EntryType:   0, // x509_entry
			Certificate: c.Raw,
		}
	}
	return out
}

// fakeTreeLeafHash returns the hash to seed into the fake-log tree
// builder for the given leaf at the given position. Mirrors what the
// production verifier computes in verifyLeafInclusion (EncodeTileLeaf
// with archival=false → native Sunlight, leaf_index extension present).
func fakeTreeLeafHash(t *testing.T, leaf LeafData, leafIndex uint64) tlog.Hash {
	t.Helper()
	return tlog.RecordHash(EncodeTileLeaf(leaf, leafIndex, false))
}

// buildTestTile serialises the given LeafData records as a Static-CT
// data tile per c2sp.org/static-ct-api §1.1.3 (canonical wire format).
//
// Mirrors the canonical wire format that ParseLeafTile reads:
//
//	uint64 timestamp
//	uint16 entry_type (0=x509_entry in this corpus)
//	uint24-prefixed signed_entry (the cert DER)
//	uint16-prefixed extensions (empty here)
//	uint16-prefixed chain_fingerprints (empty here)
//
// Takes []LeafData (not []*x509.Certificate) so the caller can share
// the same Timestamp + Certificate fields with fakeTreeLeafHash; the
// tree-hash builder and the data-tile builder must agree byte-for-byte
// for verifyLeafInclusion to succeed against the fake log.
func buildTestTile(t *testing.T, leaves []LeafData) []byte {
	t.Helper()
	b := cryptobyte.NewBuilder(nil)
	for _, ld := range leaves {
		if ld.EntryType != 0 {
			t.Fatalf("buildTestTile: this builder only supports x509 entries (EntryType=0); got EntryType=%d", ld.EntryType)
		}
		b.AddUint64(ld.Timestamp)
		b.AddUint16(ld.EntryType) // 0 = x509_entry; precert support not implemented in this test corpus
		b.AddUint24LengthPrefixed(func(d *cryptobyte.Builder) { d.AddBytes(ld.Certificate) })
		b.AddUint16(0) // extensions: empty
		b.AddUint16(0) // chain_fingerprints: empty
	}
	bs, err := b.Bytes()
	if err != nil {
		t.Fatalf("buildTestTile: %v", err)
	}
	return bs
}

func uintToStr(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func mustEncodeEd25519PubPEM(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// LastSeenTreeSize must only advance after the walk completes
// successfully. A tile-fetch failure must leave it at its prior value
// so the poller's cache cursor doesn't skip the failed tiles on retry.
func TestProvider_QueryDomain_DoesNotAdvanceLastSeenTreeSizeOnError(t *testing.T) {
	fl := newFakeLogFromCerts(t, []*x509.Certificate{
		mustGenerateLeafCert(t, "before-cursor", []string{"example.com"}),
		mustGenerateLeafCert(t, "ok", []string{"example.com"}),
	})
	fl.configure(func(f *fakeLog) { f.dataTileStatus = http.StatusInternalServerError })
	prov := fl.newProvider("example.com", &Cache{LastTreeSize: 1})

	got, err := prov.QueryDomain(context.Background(), "example.com")
	if err == nil {
		t.Fatalf("QueryDomain: want tile-fetch error, got nil")
	}
	if got != nil {
		t.Errorf("got %d entries, want nil (contract: complete-or-nil)", len(got))
	}
	if prov.LastSeenTreeSize != 0 {
		t.Errorf("LastSeenTreeSize = %d, want 0 (must not advance on walk error)", prov.LastSeenTreeSize)
	}
}

// "Already up to date" — Cache.LastTreeSize >= sth.TreeSize returns
// (nil, nil) without any tile fetch.
func TestProvider_QueryDomain_AlreadyUpToDate(t *testing.T) {
	fl := newFakeLogFromCerts(t, []*x509.Certificate{mustGenerateLeafCert(t, "ok", []string{"example.com"})})
	prov := fl.newProvider("example.com", &Cache{LastTreeSize: 1}) // already at the STH's tree size

	got, err := prov.QueryDomain(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("QueryDomain: %v", err)
	}
	if got != nil {
		t.Errorf("got %d entries, want nil", len(got))
	}
	if tiles := tileRequests(fl.requestLog()); len(tiles) != 0 {
		t.Errorf("tiles fetched %v, want none", tiles)
	}
}

// Uppercase SAN must match a lowercase domain query (RFC 5280 case-
// insensitivity).
func TestProvider_QueryDomain_CaseInsensitiveSAN(t *testing.T) {
	fl := newFakeLogFromCerts(t, []*x509.Certificate{
		mustGenerateLeafCert(t, "before-cursor", []string{"other.test"}),
		mustGenerateLeafCert(t, "ok", []string{"EXAMPLE.COM"}),
	})
	prov := fl.newProvider("example.com", &Cache{LastTreeSize: 1})

	got, err := prov.QueryDomain(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("QueryDomain: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("got %d entries, want 1 (uppercase SAN must match)", len(got))
	}
}

// fourLeafLog is the 4-leaf corpus shared by the proof tests: the
// example.com match sits at leaf index 1, the others never match.
func fourLeafLog(t *testing.T) *fakeLog {
	t.Helper()
	return newFakeLogFromCerts(t, []*x509.Certificate{
		mustGenerateLeafCert(t, "other-0", []string{"unmatched.test"}),
		mustGenerateLeafCert(t, "match", []string{"example.com"}),
		mustGenerateLeafCert(t, "other-2", []string{"unmatched.test"}),
		mustGenerateLeafCert(t, "other-3", []string{"unmatched.test"}),
	})
}

// Real 4-leaf tlog tree, real (spec-geometry) hash-tile server. The
// matched leaf at index 1 passes inclusion-proof verification.
func TestProvider_QueryDomain_VerifiesInclusionProof_Success(t *testing.T) {
	fl := fourLeafLog(t)
	prov := fl.newProvider("example.com", &Cache{LastTreeSize: 1})

	got, err := prov.QueryDomain(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("QueryDomain: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1 (only the matched leaf)", len(got))
	}
	if prov.LastVerifiedCount != 1 {
		t.Errorf("LastVerifiedCount = %d, want 1", prov.LastVerifiedCount)
	}
}

// --- shared helpers ---

// buildStoredHashes computes every tlog stored hash for a tree built
// from the given leaf hashes, using tlog's own reference builder
// (StoredHashesForRecordHash), keyed by stored-hash index.
func buildStoredHashes(t *testing.T, leafHashes []tlog.Hash) map[int64]tlog.Hash {
	t.Helper()
	out := make(map[int64]tlog.Hash, 2*len(leafHashes))
	for i, h := range leafHashes {
		hashes, err := tlog.StoredHashesForRecordHash(int64(i), h, staticTestHashReader(out))
		if err != nil {
			t.Fatalf("StoredHashesForRecordHash(%d): %v", i, err)
		}
		base := tlog.StoredHashIndex(0, int64(i))
		for j, x := range hashes {
			out[base+int64(j)] = x
		}
	}
	return out
}

// staticTestHashReader is a tlog.HashReader over a precomputed map.
type staticTestHashReader map[int64]tlog.Hash

func (m staticTestHashReader) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, idx := range indexes {
		h, ok := m[idx]
		if !ok {
			return nil, fmt.Errorf("staticTestHashReader: missing index %d", idx)
		}
		out[i] = h
	}
	return out, nil
}

// buildTestCheckpointWithRoot builds a signed checkpoint for the given
// tree size and root hash.
func buildTestCheckpointWithRoot(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey, keyName, origin string, treeSize uint64, rootHash []byte) string {
	t.Helper()
	body := origin + "\n" + uintToStr(treeSize) + "\n" + base64.StdEncoding.EncodeToString(rootHash) + "\n"
	sig := ed25519.Sign(priv, []byte(body))
	kh := KeyHashEd25519(keyName, pub)
	return body + "\n— " + keyName + " " + base64.StdEncoding.EncodeToString(append(kh, sig...)) + "\n"
}

// One matched leaf, but every hash-tile request returns 500. Provider
// logs + skips the leaf; the poll continues to completion with
// LastSeenTreeSize advanced and LastProofFetchFailures incremented.
func TestProvider_QueryDomain_SkipsLeafOnPathTileFetchFailure(t *testing.T) {
	fl := fourLeafLog(t)
	fl.configure(func(f *fakeLog) { f.hashTileStatus = http.StatusInternalServerError })
	prov := fl.newProvider("example.com", &Cache{LastTreeSize: 1})

	got, err := prov.QueryDomain(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("QueryDomain: %v (want nil; fetch failures should log+skip)", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d entries, want 0 (matched leaf was skipped due to fetch failure)", len(got))
	}
	if prov.LastProofFetchFailures != 1 {
		t.Errorf("LastProofFetchFailures = %d, want 1", prov.LastProofFetchFailures)
	}
	if prov.LastVerifiedCount != 0 {
		t.Errorf("LastVerifiedCount = %d, want 0", prov.LastVerifiedCount)
	}
	if prov.LastSeenTreeSize != 4 {
		t.Errorf("LastSeenTreeSize = %d, want 4 (poll completed; cursor should advance)", prov.LastSeenTreeSize)
	}
}

// Real tree, real tile bytes — but one leaf hash in the served level-0
// hash tile is tampered while the checkpoint signs the true root.
// tlog.TileHashReader's tile authentication fails ("downloaded
// inconsistent tile") — a cryptographic mismatch, NOT a fetch error.
// Provider must return (nil, err) and NOT advance LastSeenTreeSize.
func TestProvider_QueryDomain_AbortsOnProofMismatch(t *testing.T) {
	fl := fourLeafLog(t)
	var bad tlog.Hash
	bad[0] = 0xFF
	fl.configure(func(f *fakeLog) { f.tamper = map[int64]tlog.Hash{tlog.StoredHashIndex(0, 2): bad} })
	prov := fl.newProvider("example.com", &Cache{LastTreeSize: 1})

	got, err := prov.QueryDomain(context.Background(), "example.com")
	if err == nil {
		t.Fatalf("got err = nil, want crypto-mismatch error")
	}
	if errors.Is(err, errProofFetch) {
		t.Errorf("err = %v, want NON-fetch (crypto) error", err)
	}
	if got != nil {
		t.Errorf("got %d entries, want nil (complete-or-nil contract)", len(got))
	}
	if prov.LastSeenTreeSize != 0 {
		t.Errorf("LastSeenTreeSize = %d, want 0 (must not advance on crypto failure)", prov.LastSeenTreeSize)
	}
}
