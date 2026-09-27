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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

// fakeLog is a hermetic Static CT log that follows the real
// c2sp.org/static-ct-api + tlog-tiles serving rules, so tests cannot
// pass against client behaviour a real Sunlight log would reject:
//
//   - Tile paths are parsed with golang.org/x/mod/sumdb/tlog's
//     ParseTilePath (independent of the production tileIndexFormat
//     encoder), so a wrong N encoding 404s here as it would in production.
//   - A tile holding fewer than 256 entries at the published tree size is
//     served ONLY at <N>.p/<W> with the exact W; the full URL 404s (and
//     vice versa). Set prunePartials to model a log that has grown past
//     the published checkpoint and deleted partial tiles whose full tile
//     now exists (allowed by the spec); the full tile is then served.
//   - Hash tiles use the real geometry: tile level L holds Merkle level
//     8*L hashes (tlog.ReadTileData), not Merkle level L.
//
// The published tree size can be changed between calls (setSize) to model
// a growing log. The checkpoint always signs the true root; tamper
// overrides only the hashes served in hash tiles.
type fakeLog struct {
	t       *testing.T
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
	keyName string
	leaves  []LeafData
	stored  map[int64]tlog.Hash

	mu             sync.Mutex
	size           int64
	tamper         map[int64]tlog.Hash
	dataTileStatus int // non-zero: every data-tile request fails with this status
	hashTileStatus int // non-zero: every hash-tile request fails with this status
	prunePartials  bool
	requests       []string

	srv *httptest.Server
}

// newFakeLog serves leaves (all published) from a fresh httptest server.
// keyName is the server's host, matching Provider's deriveKeyName
// default, so tests need not set Provider.KeyName.
func newFakeLog(t *testing.T, leaves []LeafData) *fakeLog {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	f := &fakeLog{t: t, pub: pub, priv: priv, leaves: leaves, size: int64(len(leaves))}
	f.stored = buildStoredHashes(t, leafHashesFor(t, leaves))
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	u, err := url.Parse(f.srv.URL)
	if err != nil {
		t.Fatalf("parse srv.URL: %v", err)
	}
	f.keyName = u.Host
	return f
}

// newFakeLogFromCerts is newFakeLog over x509 leaves for certs, in order.
func newFakeLogFromCerts(t *testing.T, certs []*x509.Certificate) *fakeLog {
	t.Helper()
	return newFakeLog(t, buildTestLeafData(certs))
}

func (f *fakeLog) logURL() string { return f.srv.URL + "/2024h2/" }

func (f *fakeLog) pubPEM() string { return mustEncodeEd25519PubPEM(f.t, f.pub) }

func (f *fakeLog) client() *http.Client { return f.srv.Client() }

// configure mutates serving options under the lock (the handler runs on
// server goroutines).
func (f *fakeLog) configure(fn func(f *fakeLog)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeLog) setSize(n int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n > int64(len(f.leaves)) {
		f.t.Fatalf("fakeLog.setSize(%d) > %d leaves", n, len(f.leaves))
	}
	f.size = n
}

// requestLog returns (and clears) the request paths served so far.
func (f *fakeLog) requestLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.requests
	f.requests = nil
	return out
}

// tileRequests returns the subset of requestLog that were tile fetches.
func tileRequests(paths []string) []string {
	var out []string
	for _, p := range paths {
		if strings.Contains(p, "/tile/") {
			out = append(out, p)
		}
	}
	return out
}

// newProvider builds a Provider for this log with the given cache.
func (f *fakeLog) newProvider(domain string, cache *Cache) *Provider {
	return &Provider{
		Cfg:        Config{Domain: domain, LogURL: f.logURL(), PublicKeyPEM: f.pubPEM(), Cache: cache},
		HTTPClient: f.client(),
	}
}

func (f *fakeLog) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.URL.Path)
	size := f.size
	tamper := f.tamper
	dataStatus, hashStatus, prune := f.dataTileStatus, f.hashTileStatus, f.prunePartials
	f.mu.Unlock()

	const prefix = "/2024h2/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	if rest == "checkpoint" {
		_, _ = w.Write([]byte(f.checkpoint(size)))
		return
	}
	if !strings.HasPrefix(rest, "tile/") {
		http.NotFound(w, r)
		return
	}
	// Static CT drops tlog's height element: tile/<L>/<N>[.p/<W>].
	// Re-insert it so tlog.ParseTilePath (the reference decoder) parses it.
	tile, err := tlog.ParseTilePath("tile/8/" + strings.TrimPrefix(rest, "tile/"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	isData := tile.L == -1
	if isData && dataStatus != 0 {
		http.Error(w, "injected data-tile failure", dataStatus)
		return
	}
	if !isData && hashStatus != 0 {
		http.Error(w, "injected hash-tile failure", hashStatus)
		return
	}

	entriesAtLevel := size
	if !isData {
		entriesAtLevel = size >> uint(8*tile.L)
	}
	avail := entriesAtLevel - tile.N*256
	if avail <= 0 {
		http.NotFound(w, r)
		return
	}
	if avail > 256 {
		avail = 256
	}
	if tile.W < 256 {
		// Partial URL: valid only with the exact width for the published
		// size. With prunePartials, a partial whose full tile already
		// exists (the log grew past our checkpoint) has been deleted — the
		// only pruning the spec allows.
		if int64(tile.W) != avail || (prune && f.hasFullTile(tile, isData)) {
			http.NotFound(w, r)
			return
		}
	} else if avail < 256 {
		// Full URL for a tile that is still partial at the published
		// size: a real log 404s — unless we are modelling a log that has
		// since grown past our checkpoint and pruned the partial, in
		// which case the full tile (a superset) exists.
		if !prune || !f.hasFullTile(tile, isData) {
			http.NotFound(w, r)
			return
		}
	}

	if isData {
		start := tile.N * 256
		_, _ = w.Write(buildTestTile(f.t, f.leaves[start:start+int64(tile.W)]))
		return
	}
	src := staticTestHashReader(f.stored)
	if len(tamper) > 0 {
		merged := make(staticTestHashReader, len(f.stored))
		for k, v := range f.stored {
			merged[k] = v
		}
		for k, v := range tamper {
			merged[k] = v
		}
		src = merged
	}
	data, err := tlog.ReadTileData(tile, src)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write(data)
}

// hasFullTile reports whether the fixture holds enough entries (beyond
// the published size) to serve the full 256-wide version of tile.
func (f *fakeLog) hasFullTile(tile tlog.Tile, isData bool) bool {
	total := int64(len(f.leaves))
	if !isData {
		total >>= uint(8 * tile.L)
	}
	return total-tile.N*256 >= 256
}

// checkpoint signs the true root of the first size leaves.
func (f *fakeLog) checkpoint(size int64) string {
	root, err := tlog.TreeHash(size, staticTestHashReader(f.stored))
	if err != nil {
		f.t.Errorf("fakeLog: TreeHash(%d): %v", size, err)
	}
	return buildTestCheckpointWithRoot(f.t, f.pub, f.priv, f.keyName, "/2024h2/", uint64(size), root[:])
}

// leafHashesFor returns the RFC 6962 leaf hash of each leaf at its index,
// matching what verifyLeafInclusion recomputes.
func leafHashesFor(t *testing.T, leaves []LeafData) []tlog.Hash {
	t.Helper()
	out := make([]tlog.Hash, len(leaves))
	for i, ld := range leaves {
		out[i] = fakeTreeLeafHash(t, ld, uint64(i))
	}
	return out
}

// fillerLeaves returns n x509 leaves (one shared filler cert whose SAN
// never matches test domains) — cheap padding for large-tree tests.
func fillerLeaves(t *testing.T, n int) []LeafData {
	t.Helper()
	filler := mustGenerateLeafCert(t, "filler", []string{"filler.invalid"})
	return buildTestLeafData(repeatCert(filler, n))
}

func repeatCert(c *x509.Certificate, n int) []*x509.Certificate {
	out := make([]*x509.Certificate, n)
	for i := range out {
		out[i] = c
	}
	return out
}
