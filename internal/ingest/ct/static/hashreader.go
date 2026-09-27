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

// Package static (hashreader.go): the Merkle hash source for inclusion
// proofs. A tileReader fetches Static CT hash tiles from
// <logURL>tile/<L>/<N>[.p/<W>] and is wrapped in tlog.TileHashReader,
// which (a) maps each requested stored-hash index onto the correct tile
// and (b) authenticates every fetched tile against the verified
// checkpoint's root hash before any hash is used. One reader per
// QueryDomain invocation; its cache lives for a single poll cycle.
//
// Tile geometry (c2sp.org/tlog-tiles): tiles are 8 Merkle levels tall.
// The tile at tile-level L lists hashes at MERKLE level 8*L; the Merkle
// levels in between are not served and are recomputed from the tile
// below. tlog.TileHashReader does that recomputation.
//
// History: this file previously implemented tlog.HashReader directly,
// fetching tile/<m>/... for a Merkle level m. That conflated Merkle
// level with tile level, so any proof needing a hash above Merkle level
// 0 requested the wrong tile (tile/1/... holds Merkle level-8 hashes,
// not level-1) — every inclusion proof against a real Sunlight log would
// have failed. The test fixture served the same wrong geometry, which is
// why it went unnoticed.
package static

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"

	"golang.org/x/mod/sumdb/tlog"
)

// staticCTTileHeight is the fixed tile height used by Static CT API logs.
const staticCTTileHeight = 8

// errProofFetch is the sentinel returned when hash-tile HTTP fetch
// fails. Callers distinguish this from cryptographic mismatches via
// errors.Is — fetch failures log + skip the matched leaf; crypto
// mismatches (including tlog.TileHashReader's "downloaded inconsistent
// tile" authentication failure) abort the entire poll (split failure
// policy). tlog.ProveRecord returns ReadHashes errors unwrapped, so the
// sentinel survives to verifyLeafInclusion's caller.
var errProofFetch = errors.New("static: path-tile fetch failed")

// tileReader implements tlog.TileReader over HTTP for one log. Tiles are
// cached only after tlog.TileHashReader has authenticated them
// (SaveTiles), so a later proof in the same cycle never re-downloads a
// tile and never trusts an unauthenticated one.
type tileReader struct {
	ctx    context.Context
	hc     *http.Client
	logURL string

	mu    sync.Mutex
	cache map[tlog.Tile][]byte
}

// newTileHashReader returns a tlog.HashReader for the tree described by
// a verified checkpoint (treeSize, rootHash). rootHash must be 32 bytes
// (ParseAndVerifyCheckpoint guarantees this).
func newTileHashReader(ctx context.Context, hc *http.Client, logURL string, treeSize int64, rootHash []byte) tlog.HashReader {
	var root tlog.Hash
	copy(root[:], rootHash)
	return tlog.TileHashReader(tlog.Tree{N: treeSize, Hash: root}, newTileReader(ctx, hc, logURL))
}

func newTileReader(ctx context.Context, hc *http.Client, logURL string) *tileReader {
	return &tileReader{ctx: ctx, hc: hc, logURL: logURL, cache: make(map[tlog.Tile][]byte)}
}

// Height implements tlog.TileReader.
func (r *tileReader) Height() int { return staticCTTileHeight }

// ReadTiles implements tlog.TileReader. Any fetch failure is wrapped in
// errProofFetch.
func (r *tileReader) ReadTiles(tiles []tlog.Tile) ([][]byte, error) {
	out := make([][]byte, len(tiles))
	for i, t := range tiles {
		r.mu.Lock()
		data, ok := r.cache[t]
		r.mu.Unlock()
		if !ok {
			var err error
			data, err = r.fetchTile(t)
			if err != nil {
				return nil, fmt.Errorf("%w: level=%d tile=%d width=%d: %v", errProofFetch, t.L, t.N, t.W, err)
			}
		}
		out[i] = data
	}
	return out, nil
}

// SaveTiles implements tlog.TileReader: called only after the tiles were
// authenticated against the checkpoint root.
func (r *tileReader) SaveTiles(tiles []tlog.Tile, data [][]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, t := range tiles {
		r.cache[t] = data[i]
	}
}

// fetchTile GETs the hash tile t. A partial tile (t.W < 256) is requested
// at its .p/<W> URL; on 404 we fall back to the full tile and truncate
// it to W hashes (a log MAY prune partial tiles once the full tile
// exists). tlog.TileHashReader requires exactly t.W*HashSize bytes.
func (r *tileReader) fetchTile(t tlog.Tile) ([]byte, error) {
	const maxBytes = tileWidth * tlog.HashSize // 8192 bytes for a full hash tile
	level := strconv.Itoa(t.L)
	body, err := fetchTileURL(r.ctx, r.hc, tileURL(r.logURL, level, t.N, t.W), maxBytes)
	if err != nil && t.W < tileWidth && errors.Is(err, errTileNotFound) {
		body, err = fetchTileURL(r.ctx, r.hc, tileURL(r.logURL, level, t.N, tileWidth), maxBytes)
		if err == nil && len(body) >= t.W*tlog.HashSize {
			body = body[:t.W*tlog.HashSize]
		}
	}
	if err != nil {
		return nil, err
	}
	if len(body) != t.W*tlog.HashSize {
		return nil, fmt.Errorf("tile level=%d n=%d: got %d bytes, want %d", t.L, t.N, len(body), t.W*tlog.HashSize)
	}
	return body, nil
}
