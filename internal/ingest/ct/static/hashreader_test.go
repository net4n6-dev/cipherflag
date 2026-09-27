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
	"crypto/sha256"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

// Pre-populating the cache and calling ReadHashes returns the cached
// hashes without any HTTP call (the test uses a nil http.Client to
// prove no I/O happens on cache hits).
func TestTileHashReader_CacheHit_NoFetch(t *testing.T) {
	r := newTileHashReader(context.Background(), nil, "https://example/2024h2/", 100)

	// Pre-populate the cache for two stored-hash indexes.
	idxA := tlog.StoredHashIndex(0, 0)
	idxB := tlog.StoredHashIndex(1, 0)
	var hA, hB tlog.Hash
	hA[0], hA[31] = 0xAA, 0xAA
	hB[0], hB[31] = 0xBB, 0xBB
	r.cache[idxA] = hA
	r.cache[idxB] = hB

	got, err := r.ReadHashes([]int64{idxA, idxB})
	if err != nil {
		t.Fatalf("ReadHashes: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d hashes, want 2", len(got))
	}
	if got[0] != hA || got[1] != hB {
		t.Errorf("hashes don't match cache: got %x, %x", got[0], got[1])
	}
}

// First call triggers an HTTP fetch of the path tile and populates the
// cache for all 256 stored-hash indexes the tile covers. Second call
// for any of the same indexes is a cache hit (asserted by counting
// HTTP calls).
func TestTileHashReader_FetchAndCache_PopulatesWholeTile(t *testing.T) {
	// Build a synthetic level-0 path tile with 256 distinct hashes.
	const numHashes = 256
	tileBytes := make([]byte, numHashes*tlog.HashSize)
	wantHashes := make([]tlog.Hash, numHashes)
	for i := 0; i < numHashes; i++ {
		// Deterministic-but-distinct hash per entry: SHA-256(uint32(i)).
		var ib [4]byte
		binary.BigEndian.PutUint32(ib[:], uint32(i))
		h := sha256.Sum256(ib[:])
		copy(wantHashes[i][:], h[:])
		copy(tileBytes[i*tlog.HashSize:(i+1)*tlog.HashSize], h[:])
	}

	tileCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/2024h2/tile/0/000" {
			http.NotFound(w, req)
			return
		}
		tileCalls++
		_, _ = w.Write(tileBytes)
	}))
	defer srv.Close()

	r := newTileHashReader(context.Background(), srv.Client(), srv.URL+"/2024h2/", int64(numHashes))

	// First call fetches the tile; cache is populated for all 256 indexes.
	idx0 := tlog.StoredHashIndex(0, 0)
	got, err := r.ReadHashes([]int64{idx0})
	if err != nil {
		t.Fatalf("first ReadHashes: %v", err)
	}
	if got[0] != wantHashes[0] {
		t.Errorf("got[0] = %x, want %x", got[0], wantHashes[0])
	}
	if tileCalls != 1 {
		t.Errorf("tileCalls after first fetch = %d, want 1", tileCalls)
	}

	// Second call for any index in the same tile is a cache hit — no
	// new HTTP request.
	idx5 := tlog.StoredHashIndex(0, 5)
	got, err = r.ReadHashes([]int64{idx5})
	if err != nil {
		t.Fatalf("second ReadHashes: %v", err)
	}
	if got[0] != wantHashes[5] {
		t.Errorf("got[0] = %x, want %x", got[0], wantHashes[5])
	}
	if tileCalls != 1 {
		t.Errorf("tileCalls after cache-hit call = %d, want 1 (cache miss should not trigger fetch)", tileCalls)
	}
}

// Server returns 404 for the full-tile URL but 200 for the partial-tile
// URL with the right size suffix. Reader should fall back transparently.
func TestTileHashReader_PartialTileFallback(t *testing.T) {
	const numHashes = 100 // partial tile of 100 < 256 entries
	tileBytes := make([]byte, numHashes*tlog.HashSize)
	wantHash := tlog.Hash{}
	for i := 0; i < numHashes; i++ {
		var ib [4]byte
		binary.BigEndian.PutUint32(ib[:], uint32(i))
		h := sha256.Sum256(ib[:])
		copy(tileBytes[i*tlog.HashSize:(i+1)*tlog.HashSize], h[:])
		if i == 7 {
			copy(wantHash[:], h[:])
		}
	}

	fullCalls, partialCalls := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/2024h2/tile/0/000":
			fullCalls++
			http.NotFound(w, req) // Sunlight: tree isn't full → 404 on the full URL
		case "/2024h2/tile/0/000.p/100":
			partialCalls++
			_, _ = w.Write(tileBytes)
		default:
			http.NotFound(w, req)
		}
	}))
	defer srv.Close()

	r := newTileHashReader(context.Background(), srv.Client(), srv.URL+"/2024h2/", numHashes)

	got, err := r.ReadHashes([]int64{tlog.StoredHashIndex(0, 7)})
	if err != nil {
		t.Fatalf("ReadHashes: %v", err)
	}
	if got[0] != wantHash {
		t.Errorf("got hash mismatch")
	}
	if fullCalls != 1 {
		t.Errorf("fullCalls = %d, want 1 (full URL tried first)", fullCalls)
	}
	if partialCalls != 1 {
		t.Errorf("partialCalls = %d, want 1 (fallback on 404)", partialCalls)
	}
}
