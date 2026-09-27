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
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/tlog"
)

// End-to-end provider test against a httptest-served fake Sunlight log
// containing two leaves: one cert with example.com in SAN, one without.
// QueryDomain("example.com") returns exactly the matching cert as a
// CTEntry with Source="ct_static".
func TestProvider_QueryDomain_FiltersBySAN(t *testing.T) {
	// 1. Generate the test log's signing key + two leaf certs.
	logPub, logPriv, _ := ed25519.GenerateKey(rand.Reader)

	matchCert := mustGenerateLeafCert(t, "match", []string{"example.com", "api.example.com"})
	missCert := mustGenerateLeafCert(t, "miss", []string{"other.test"})
	certs := []*x509.Certificate{matchCert, missCert}
	leaves := buildTestLeafData(certs)

	// 2. Build a real 2-leaf tlog tree so inclusion-proof verification passes.
	leafHashes := make([]tlog.Hash, len(leaves))
	for i, ld := range leaves {
		leafHashes[i] = fakeTreeLeafHash(t, ld, uint64(i))
	}
	storedHashes := buildStoredHashes(t, leafHashes)
	rootHash, err := tlog.TreeHash(int64(len(certs)), staticTestHashReader(storedHashes))
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}

	// 3. Build a one-tile leaf-data payload containing both leaves.
	tileBytes := buildTestTile(t, leaves)

	// 4. Build a signed checkpoint with the real root.
	checkpoint := buildTestCheckpointWithRoot(t, logPub, logPriv, "sunlight.test", "/2024h2/", uint64(len(certs)), rootHash[:])

	// 5. Serve checkpoint + data tile + path tiles.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/2024h2/checkpoint":
			_, _ = w.Write([]byte(checkpoint))
		case r.URL.Path == "/2024h2/tile/data/000":
			_, _ = w.Write(tileBytes)
		case strings.HasPrefix(r.URL.Path, "/2024h2/tile/"):
			servePathTile(t, w, r, storedHashes, int64(len(certs)))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	pemPub := mustEncodeEd25519PubPEM(t, logPub)
	cfg := Config{
		Domain:       "example.com",
		LogURL:       srv.URL + "/2024h2/",
		PublicKeyPEM: pemPub,
	}
	prov := &Provider{Cfg: cfg, HTTPClient: srv.Client(), KeyName: "sunlight.test"}

	got, err := prov.QueryDomain(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("QueryDomain: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("entries = %d, want 1 (only the matching cert)", len(got))
	}
	if got[0].Source != "ct_static" {
		t.Errorf("Source = %q, want ct_static", got[0].Source)
	}
	if got[0].Fingerprint == "" || len(got[0].PEM) == 0 {
		t.Errorf("missing Fingerprint or PEM: %+v", got[0])
	}
}

func TestProvider_Name_ReturnsStatic(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "static" {
		t.Errorf("Name() = %q, want static", got)
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

// buildTestCheckpoint builds a signed checkpoint pointing at the given
// tree size. The root hash is intentionally NOT a real Merkle root —
// the provider test does not verify inclusion proofs (T11's tree walk
// trusts the STH for tree size; inclusion-proof verification is the
// crypto layer's job tested separately in merkle_test.go).
func buildTestCheckpoint(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey, keyName, origin string, _ []byte, treeSize uint64) string {
	t.Helper()
	rootHash := make([]byte, 32) // placeholder — see comment above
	body := origin + "\n" + uintToStr(treeSize) + "\n" + base64.StdEncoding.EncodeToString(rootHash) + "\n"
	sig := ed25519.Sign(priv, []byte(body))
	keyHash := KeyHashEd25519(keyName, pub) // already exists in sth.go
	return body + "\n— " + keyName + " " + base64.StdEncoding.EncodeToString(append(keyHash, sig...)) + "\n"
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
	logPub, logPriv, _ := ed25519.GenerateKey(rand.Reader)
	cert := mustGenerateLeafCert(t, "ok", []string{"example.com"})
	tileBytes := buildTestTile(t, buildTestLeafData([]*x509.Certificate{cert}))
	checkpoint := buildTestCheckpoint(t, logPub, logPriv, "sunlight.test", "/2024h2/", tileBytes, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/2024h2/checkpoint":
			_, _ = w.Write([]byte(checkpoint))
		case "/2024h2/tile/data/000":
			http.Error(w, "intentional 500", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	prov := &Provider{
		Cfg: Config{
			Domain:       "example.com",
			LogURL:       srv.URL + "/2024h2/",
			PublicKeyPEM: mustEncodeEd25519PubPEM(t, logPub),
		},
		HTTPClient: srv.Client(),
		KeyName:    "sunlight.test",
	}

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
	logPub, logPriv, _ := ed25519.GenerateKey(rand.Reader)
	cert := mustGenerateLeafCert(t, "ok", []string{"example.com"})
	tileBytes := buildTestTile(t, buildTestLeafData([]*x509.Certificate{cert}))
	checkpoint := buildTestCheckpoint(t, logPub, logPriv, "sunlight.test", "/2024h2/", tileBytes, 1)

	tileCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/2024h2/checkpoint":
			_, _ = w.Write([]byte(checkpoint))
		case "/2024h2/tile/data/000":
			tileCalls++
			_, _ = w.Write(tileBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	prov := &Provider{
		Cfg: Config{
			Domain:       "example.com",
			LogURL:       srv.URL + "/2024h2/",
			PublicKeyPEM: mustEncodeEd25519PubPEM(t, logPub),
			Cache:        &Cache{LastTreeSize: 1}, // already at the STH's tree size
		},
		HTTPClient: srv.Client(),
		KeyName:    "sunlight.test",
	}

	got, err := prov.QueryDomain(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("QueryDomain: %v", err)
	}
	if got != nil {
		t.Errorf("got %d entries, want nil", len(got))
	}
	if tileCalls != 0 {
		t.Errorf("tile fetched %d times, want 0", tileCalls)
	}
}

// Uppercase SAN must match a lowercase domain query (RFC 5280 case-
// insensitivity).
func TestProvider_QueryDomain_CaseInsensitiveSAN(t *testing.T) {
	logPub, logPriv, _ := ed25519.GenerateKey(rand.Reader)
	cert := mustGenerateLeafCert(t, "ok", []string{"EXAMPLE.COM"})
	certs := []*x509.Certificate{cert}
	leaves := buildTestLeafData(certs)

	// Build a real 1-leaf tlog tree so inclusion-proof verification passes.
	leafHashes := []tlog.Hash{fakeTreeLeafHash(t, leaves[0], 0)}
	storedHashes := buildStoredHashes(t, leafHashes)
	rootHash, err := tlog.TreeHash(int64(len(certs)), staticTestHashReader(storedHashes))
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}

	tileBytes := buildTestTile(t, leaves)
	checkpoint := buildTestCheckpointWithRoot(t, logPub, logPriv, "sunlight.test", "/2024h2/", uint64(len(certs)), rootHash[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/2024h2/checkpoint":
			_, _ = w.Write([]byte(checkpoint))
		case r.URL.Path == "/2024h2/tile/data/000":
			_, _ = w.Write(tileBytes)
		case strings.HasPrefix(r.URL.Path, "/2024h2/tile/"):
			servePathTile(t, w, r, storedHashes, int64(len(certs)))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	prov := &Provider{
		Cfg: Config{
			Domain:       "example.com",
			LogURL:       srv.URL + "/2024h2/",
			PublicKeyPEM: mustEncodeEd25519PubPEM(t, logPub),
		},
		HTTPClient: srv.Client(),
		KeyName:    "sunlight.test",
	}

	got, err := prov.QueryDomain(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("QueryDomain: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("got %d entries, want 1 (uppercase SAN must match)", len(got))
	}
}

// Real 4-leaf tlog tree, real path-tile server. The matched leaf at
// index 1 passes inclusion-proof verification; the other tile entries
// don't need to pass (only matched leaves get verified).
func TestProvider_QueryDomain_VerifiesInclusionProof_Success(t *testing.T) {
	logPub, logPriv, _ := ed25519.GenerateKey(rand.Reader)
	matchCert := mustGenerateLeafCert(t, "match", []string{"example.com"})
	otherCerts := []*x509.Certificate{
		mustGenerateLeafCert(t, "other-0", []string{"unmatched.test"}),
		matchCert,
		mustGenerateLeafCert(t, "other-2", []string{"unmatched.test"}),
		mustGenerateLeafCert(t, "other-3", []string{"unmatched.test"}),
	}
	// Leaf index 1 is the one with example.com.
	matchedLeafIndex := int64(1)
	leaves := buildTestLeafData(otherCerts)

	// Build a real 4-leaf tlog tree from the RFC 6962 MerkleTreeLeaf bytes
	// produced by EncodeTileLeaf — matches what verifyLeafInclusion computes.
	leafHashes := make([]tlog.Hash, len(leaves))
	for i, ld := range leaves {
		leafHashes[i] = fakeTreeLeafHash(t, ld, uint64(i))
	}
	storedHashes := buildStoredHashes(t, leafHashes)
	rootHash, err := tlog.TreeHash(int64(len(otherCerts)), staticTestHashReader(storedHashes))
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}

	tileBytes := buildTestTile(t, leaves)
	checkpoint := buildTestCheckpointWithRoot(t, logPub, logPriv, "sunlight.test", "/2024h2/", uint64(len(otherCerts)), rootHash[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.URL.Path == "/2024h2/checkpoint":
			_, _ = w.Write([]byte(checkpoint))
		case req.URL.Path == "/2024h2/tile/data/000":
			_, _ = w.Write(tileBytes)
		case strings.HasPrefix(req.URL.Path, "/2024h2/tile/"):
			servePathTile(t, w, req, storedHashes, int64(len(otherCerts)))
		default:
			http.NotFound(w, req)
		}
	}))
	defer srv.Close()

	prov := &Provider{
		Cfg: Config{
			Domain:       "example.com",
			LogURL:       srv.URL + "/2024h2/",
			PublicKeyPEM: mustEncodeEd25519PubPEM(t, logPub),
		},
		HTTPClient: srv.Client(),
		KeyName:    "sunlight.test",
	}

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
	_ = matchedLeafIndex // referenced for clarity; verification happens by the leaf-index math inside QueryDomain
}

// --- shared helpers used by T4 and T5/T6 below ---

// buildStoredHashes computes every tlog-stored hash for a tree built
// from the given leaf hashes. Returns a map keyed by stored-hash
// index so the test server and the Provider's tileHashReader can
// agree on every fetchable entry.
func buildStoredHashes(t *testing.T, leafHashes []tlog.Hash) map[int64]tlog.Hash {
	t.Helper()
	out := make(map[int64]tlog.Hash)
	for i, h := range leafHashes {
		out[tlog.StoredHashIndex(0, int64(i))] = h
	}
	// Higher levels: compute internal nodes.
	level := 0
	for {
		level++
		entriesAtLevel := (int64(len(leafHashes)) + (1 << level) - 1) >> level
		if entriesAtLevel == 0 {
			break
		}
		for n := int64(0); n < entriesAtLevel; n++ {
			leftIdx := tlog.StoredHashIndex(level-1, n*2)
			rightIdx := tlog.StoredHashIndex(level-1, n*2+1)
			left := out[leftIdx]
			var right tlog.Hash
			if r, ok := out[rightIdx]; ok {
				right = r
			} else {
				right = left // odd node: duplicate left at incomplete subtree boundary
			}
			out[tlog.StoredHashIndex(level, n)] = tlog.NodeHash(left, right)
		}
		if entriesAtLevel == 1 {
			break
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

// buildTestCheckpointWithRoot is like buildTestCheckpoint but takes an
// explicit root hash (so the test can sign a checkpoint that matches
// the real tlog-built tree, not a zero placeholder).
func buildTestCheckpointWithRoot(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey, keyName, origin string, treeSize uint64, rootHash []byte) string {
	t.Helper()
	body := origin + "\n" + uintToStr(treeSize) + "\n" + base64.StdEncoding.EncodeToString(rootHash) + "\n"
	sig := ed25519.Sign(priv, []byte(body))
	kh := KeyHashEd25519(keyName, pub)
	return body + "\n— " + keyName + " " + base64.StdEncoding.EncodeToString(append(kh, sig...)) + "\n"
}

// servePathTile serves a Static CT path tile assembled from a
// precomputed stored-hash map. Used by the success/abort/skip tests
// in T4/T5/T6. Treats partial-tile URLs (.p/<N>) the same way real
// Sunlight logs do.
func servePathTile(t *testing.T, w http.ResponseWriter, req *http.Request, stored map[int64]tlog.Hash, treeSize int64) {
	t.Helper()
	// Path: /2024h2/tile/<level>/<W>[/<partial-suffix>]
	parts := strings.Split(strings.TrimPrefix(req.URL.Path, "/2024h2/tile/"), "/")
	if len(parts) < 2 {
		http.NotFound(w, req)
		return
	}
	level, err := strconv.Atoi(parts[0])
	if err != nil {
		http.NotFound(w, req)
		return
	}
	tileSpec := parts[1] // "000" or "000.p"
	var partialN int64
	if strings.HasSuffix(tileSpec, ".p") && len(parts) >= 3 {
		tileSpec = strings.TrimSuffix(tileSpec, ".p")
		partialN, _ = strconv.ParseInt(parts[2], 10, 64)
	}
	tileN, _ := strconv.ParseInt(strings.TrimLeft(tileSpec, "0"), 10, 64)
	if tileSpec == "000" {
		tileN = 0
	}

	entriesAtLevel := (treeSize + (1 << level) - 1) >> level
	count := int64(256)
	if remaining := entriesAtLevel - tileN*256; remaining < 256 {
		count = remaining
	}
	// If the request specified a partial-suffix size but it doesn't match
	// our level's actual remaining, 404. Otherwise serve count entries.
	if partialN > 0 && partialN != count {
		http.NotFound(w, req)
		return
	}
	// Full-tile URL only valid when count == 256.
	if partialN == 0 && count < 256 {
		http.NotFound(w, req)
		return
	}

	body := make([]byte, count*int64(tlog.HashSize))
	baseIndex := tileN * 256
	for i := int64(0); i < count; i++ {
		h, ok := stored[tlog.StoredHashIndex(level, baseIndex+i)]
		if !ok {
			http.NotFound(w, req)
			return
		}
		copy(body[i*int64(tlog.HashSize):], h[:])
	}
	_, _ = w.Write(body)
}

// One matched leaf, but the path-tile endpoint returns 500. Provider
// logs + skips the leaf; the poll continues to completion with
// LastSeenTreeSize advanced and LastProofFetchFailures incremented.
func TestProvider_QueryDomain_SkipsLeafOnPathTileFetchFailure(t *testing.T) {
	logPub, logPriv, _ := ed25519.GenerateKey(rand.Reader)
	matchCert := mustGenerateLeafCert(t, "match", []string{"example.com"})
	otherCerts := []*x509.Certificate{
		mustGenerateLeafCert(t, "other-0", []string{"unmatched.test"}),
		matchCert,
		mustGenerateLeafCert(t, "other-2", []string{"unmatched.test"}),
		mustGenerateLeafCert(t, "other-3", []string{"unmatched.test"}),
	}
	leaves := buildTestLeafData(otherCerts)
	leafHashes := make([]tlog.Hash, len(leaves))
	for i, ld := range leaves {
		leafHashes[i] = fakeTreeLeafHash(t, ld, uint64(i))
	}
	storedHashes := buildStoredHashes(t, leafHashes)
	rootHash, _ := tlog.TreeHash(int64(len(otherCerts)), staticTestHashReader(storedHashes))

	tileBytes := buildTestTile(t, leaves)
	checkpoint := buildTestCheckpointWithRoot(t, logPub, logPriv, "sunlight.test", "/2024h2/", uint64(len(otherCerts)), rootHash[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.URL.Path == "/2024h2/checkpoint":
			_, _ = w.Write([]byte(checkpoint))
		case req.URL.Path == "/2024h2/tile/data/000":
			_, _ = w.Write(tileBytes)
		case strings.HasPrefix(req.URL.Path, "/2024h2/tile/"):
			http.Error(w, "intentional 500", http.StatusInternalServerError)
		default:
			http.NotFound(w, req)
		}
	}))
	defer srv.Close()

	prov := &Provider{
		Cfg: Config{
			Domain:       "example.com",
			LogURL:       srv.URL + "/2024h2/",
			PublicKeyPEM: mustEncodeEd25519PubPEM(t, logPub),
		},
		HTTPClient: srv.Client(),
		KeyName:    "sunlight.test",
	}

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

// Real tree, real tile bytes, real path-tile server — but one path-tile
// hash is tampered. The proof check fails with a cryptographic
// mismatch (NOT a fetch error). Provider must return (nil, err) and
// NOT advance LastSeenTreeSize.
func TestProvider_QueryDomain_AbortsOnProofMismatch(t *testing.T) {
	logPub, logPriv, _ := ed25519.GenerateKey(rand.Reader)
	matchCert := mustGenerateLeafCert(t, "match", []string{"example.com"})
	otherCerts := []*x509.Certificate{
		mustGenerateLeafCert(t, "other-0", []string{"unmatched.test"}),
		matchCert,
		mustGenerateLeafCert(t, "other-2", []string{"unmatched.test"}),
		mustGenerateLeafCert(t, "other-3", []string{"unmatched.test"}),
	}
	leaves := buildTestLeafData(otherCerts)
	leafHashes := make([]tlog.Hash, len(leaves))
	for i, ld := range leaves {
		leafHashes[i] = fakeTreeLeafHash(t, ld, uint64(i))
	}
	storedHashes := buildStoredHashes(t, leafHashes)

	// Tamper one stored level-1 hash before computing the root the log
	// signs (the log signs the REAL root; the served tiles return the
	// tampered hash → mismatch when the Provider tries to verify).
	rootHash, _ := tlog.TreeHash(int64(len(otherCerts)), staticTestHashReader(storedHashes))
	tampered := make(map[int64]tlog.Hash, len(storedHashes))
	for k, v := range storedHashes {
		tampered[k] = v
	}
	// For leaf index 1 in a 4-leaf tree the proof path is:
	//   StoredHashIndex(0, 0) — sibling leaf 0
	//   StoredHashIndex(1, 1) — hash of leaves 2+3
	// Tamper StoredHashIndex(1, 1) so it IS in the proof path.
	level1Idx := tlog.StoredHashIndex(1, 1)
	var bad tlog.Hash
	bad[0] = 0xFF
	tampered[level1Idx] = bad

	tileBytes := buildTestTile(t, leaves)
	checkpoint := buildTestCheckpointWithRoot(t, logPub, logPriv, "sunlight.test", "/2024h2/", uint64(len(otherCerts)), rootHash[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.URL.Path == "/2024h2/checkpoint":
			_, _ = w.Write([]byte(checkpoint))
		case req.URL.Path == "/2024h2/tile/data/000":
			_, _ = w.Write(tileBytes)
		case strings.HasPrefix(req.URL.Path, "/2024h2/tile/"):
			servePathTile(t, w, req, tampered, int64(len(otherCerts)))
		default:
			http.NotFound(w, req)
		}
	}))
	defer srv.Close()

	prov := &Provider{
		Cfg: Config{
			Domain:       "example.com",
			LogURL:       srv.URL + "/2024h2/",
			PublicKeyPEM: mustEncodeEd25519PubPEM(t, logPub),
		},
		HTTPClient: srv.Client(),
		KeyName:    "sunlight.test",
	}

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
