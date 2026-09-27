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
// Package static (hashreader.go): tlog.HashReader implementation that
// fetches Static CT path tiles from <logURL>tile/<level>/<W> on demand
// and caches each fetched hash by its tlog stored-hash index. One
// reader per QueryDomain invocation; the cache lives for the duration
// of a single poll cycle.
//
// Spec: docs/superpowers/specs/2026-05-25-ct-plan-a-5-hardening-design.md
// §Item 1 — Merkle wiring
package static

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"

	"golang.org/x/mod/sumdb/tlog"
)

// errProofFetch is the sentinel returned when path-tile HTTP fetch or
// parse fails. Callers distinguish this from cryptographic mismatches
// via errors.Is — fetch failures log + skip the matched leaf; crypto
// mismatches abort the entire poll (split failure policy).
var errProofFetch = errors.New("static: path-tile fetch failed")

// tileHashReader implements tlog.HashReader over a path-tile-fetching
// cache. Single-purpose per QueryDomain call.
type tileHashReader struct {
	ctx     context.Context
	hc      *http.Client
	logURL  string
	size    int64 // tree size from the verified STH
	cacheMu sync.Mutex
	cache   map[int64]tlog.Hash
}

// newTileHashReader constructs a fresh reader with an empty cache. The
// http.Client may be nil for tests that pre-populate the cache and
// never trigger a fetch.
func newTileHashReader(ctx context.Context, hc *http.Client, logURL string, treeSize int64) *tileHashReader {
	return &tileHashReader{
		ctx:    ctx,
		hc:     hc,
		logURL: logURL,
		size:   treeSize,
		cache:  make(map[int64]tlog.Hash, 64),
	}
}

// ReadHashes implements tlog.HashReader. Returns cached hashes for
// every requested stored-hash index; cache misses trigger an HTTP
// fetch of the containing path tile, which populates the cache for
// all hashes in that tile before returning the requested hash.
func (r *tileHashReader) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, idx := range indexes {
		h, err := r.readOne(idx)
		if err != nil {
			return nil, err
		}
		out[i] = h
	}
	return out, nil
}

// readOne returns the hash for one stored-hash index, fetching its
// containing path tile if not yet cached. Holds the cache lock for
// the duration of the cache lookup; releases it for the HTTP fetch
// (which may block) and re-acquires to populate.
func (r *tileHashReader) readOne(idx int64) (tlog.Hash, error) {
	r.cacheMu.Lock()
	if h, ok := r.cache[idx]; ok {
		r.cacheMu.Unlock()
		return h, nil
	}
	r.cacheMu.Unlock()

	level, indexWithinLevel := tlog.SplitStoredHashIndex(idx)
	tileN := indexWithinLevel / 256
	tileBytes, err := r.fetchTile(level, tileN)
	if err != nil {
		var zero tlog.Hash
		return zero, fmt.Errorf("%w: level=%d tile=%d: %v", errProofFetch, level, tileN, err)
	}
	r.populateCacheFromTile(level, tileN, tileBytes)

	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	h, ok := r.cache[idx]
	if !ok {
		var zero tlog.Hash
		return zero, fmt.Errorf("%w: index %d not in fetched tile (level=%d, tile=%d)", errProofFetch, idx, level, tileN)
	}
	return h, nil
}

// fetchTile GETs <logURL>tile/<level>/<W> and returns the raw bytes.
// On 404 from the full-tile URL, falls back to the partial-tile URL
// (.p/<N>) where N is the number of entries remaining at this level.
func (r *tileHashReader) fetchTile(level int, tileN int64) ([]byte, error) {
	fullURL := r.logURL + "tile/" + strconv.Itoa(level) + "/" + tileIndexFormat(tileN)
	body, status, err := r.tryFetch(fullURL)
	if err == nil {
		return body, nil
	}
	if status != http.StatusNotFound {
		return nil, err
	}

	// 404 on full URL — fall back to the partial-tile URL.
	// Number of entries at this level: ceil(treeSize / 2^level).
	entriesAtLevel := (r.size + (1 << level) - 1) >> level
	partialN := entriesAtLevel - tileN*256
	if partialN <= 0 || partialN >= 256 {
		// Not actually a partial tile situation — the full URL really
		// is the right URL; the 404 was a real failure.
		return nil, fmt.Errorf("%s returned 404", fullURL)
	}
	partialURL := fullURL + ".p/" + strconv.FormatInt(partialN, 10)
	body, _, err = r.tryFetch(partialURL)
	return body, err
}

// tryFetch GETs the URL once. Returns (body, statusCode, error). On
// non-200, err is non-nil and statusCode is the HTTP status (so the
// caller can distinguish 404 from other failures).
func (r *tileHashReader) tryFetch(url string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}
	resp, err := r.hc.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("%s returned %d", url, resp.StatusCode)
	}
	const maxTileBytes = 256 * tlog.HashSize // exactly 8192 bytes for a full path tile
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTileBytes+1))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read body: %w", err)
	}
	if len(body) > maxTileBytes {
		return nil, resp.StatusCode, fmt.Errorf("tile too large (>%d bytes)", maxTileBytes)
	}
	if len(body)%tlog.HashSize != 0 {
		return nil, resp.StatusCode, fmt.Errorf("tile size %d is not a multiple of %d", len(body), tlog.HashSize)
	}
	return body, resp.StatusCode, nil
}

// populateCacheFromTile splits the packed tile bytes into 32-byte
// hashes and stores each under the appropriate stored-hash index.
func (r *tileHashReader) populateCacheFromTile(level int, tileN int64, tileBytes []byte) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	numEntries := len(tileBytes) / tlog.HashSize
	baseIndexWithinLevel := tileN * 256
	for i := 0; i < numEntries; i++ {
		var h tlog.Hash
		copy(h[:], tileBytes[i*tlog.HashSize:(i+1)*tlog.HashSize])
		idx := tlog.StoredHashIndex(level, baseIndexWithinLevel+int64(i))
		r.cache[idx] = h
	}
}
