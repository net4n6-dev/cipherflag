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
	"errors"
	"net/http"
	"slices"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

// A partial hash tile is requested at its .p/<W> URL; a full one at the
// bare URL. Once SaveTiles has recorded authenticated tiles, ReadTiles
// serves them from cache without another HTTP request.
func TestTileReader_PartialURL_And_CacheAfterSave(t *testing.T) {
	fl := newFakeLog(t, fillerLeaves(t, 300))
	r := newTileReader(context.Background(), fl.client(), fl.logURL())

	tiles := []tlog.Tile{
		{H: 8, L: 0, N: 0, W: 256}, // full
		{H: 8, L: 0, N: 1, W: 44},  // partial
	}
	data, err := r.ReadTiles(tiles)
	if err != nil {
		t.Fatalf("ReadTiles: %v", err)
	}
	if len(data[0]) != 256*tlog.HashSize || len(data[1]) != 44*tlog.HashSize {
		t.Fatalf("tile sizes = %d, %d; want %d, %d", len(data[0]), len(data[1]), 256*tlog.HashSize, 44*tlog.HashSize)
	}
	reqs := fl.requestLog()
	if !slices.Equal(reqs, []string{"/2024h2/tile/0/000", "/2024h2/tile/0/001.p/44"}) {
		t.Errorf("requests = %v", reqs)
	}

	r.SaveTiles(tiles, data)
	if _, err := r.ReadTiles(tiles); err != nil {
		t.Fatalf("second ReadTiles: %v", err)
	}
	if reqs := fl.requestLog(); len(reqs) != 0 {
		t.Errorf("cached tiles re-fetched: %v", reqs)
	}
}

// An HTTP failure surfaces wrapped in errProofFetch (the "skip the leaf"
// half of the split failure policy).
func TestTileReader_FetchFailure_WrapsErrProofFetch(t *testing.T) {
	fl := newFakeLog(t, fillerLeaves(t, 4))
	fl.configure(func(f *fakeLog) { f.hashTileStatus = http.StatusBadGateway })
	r := newTileReader(context.Background(), fl.client(), fl.logURL())

	_, err := r.ReadTiles([]tlog.Tile{{H: 8, L: 0, N: 0, W: 4}})
	if !errors.Is(err, errProofFetch) {
		t.Fatalf("err = %v, want errors.Is(err, errProofFetch)", err)
	}
}

// End-to-end geometry check: prove leaf 590 of a 600-leaf tree through
// newTileHashReader and verify it against the tree root. The proof needs
// Merkle hashes above level 7, available only via the level-1 tile
// (tile/1/000.p/2 — Merkle level-8 hashes). The previous reader fetched
// tile/<merkle level>/..., which cannot produce a valid proof here.
func TestNewTileHashReader_ProvesAcrossTileLevels(t *testing.T) {
	const size = 600
	leaves := fillerLeaves(t, size)
	fl := newFakeLog(t, leaves)
	root, err := tlog.TreeHash(size, staticTestHashReader(fl.stored))
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}

	hr := newTileHashReader(context.Background(), fl.client(), fl.logURL(), size, root[:])
	for _, n := range []int64{0, 255, 256, 511, 590, 599} {
		proof, err := tlog.ProveRecord(size, n, hr)
		if err != nil {
			t.Fatalf("ProveRecord(%d): %v", n, err)
		}
		leafHash := fakeTreeLeafHash(t, leaves[n], uint64(n))
		if err := tlog.CheckRecord(proof, size, root, n, leafHash); err != nil {
			t.Errorf("CheckRecord(%d): %v", n, err)
		}
	}
	if reqs := fl.requestLog(); !slices.Contains(reqs, "/2024h2/tile/1/000.p/2") {
		t.Errorf("level-1 tile never requested; requests: %v", reqs)
	}
}
