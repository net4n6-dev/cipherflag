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
	"fmt"
	"io"
	"net/http"
	"strconv"

	"golang.org/x/crypto/cryptobyte"
)

// tileWidth is the number of entries in a full Static CT tile (tile
// height 8 → 2^8 entries), for both data tiles and hash tiles.
const tileWidth = 256

// tileIndexFormat encodes a tile index N as the c2sp.org/tlog-tiles
// path element(s): zero-padded 3-digit groups, every group but the last
// prefixed with "x". So 0 → "000", 999 → "999", 1000 → "x001/000",
// 1234067 → "x001/x234/067". Identical to golang.org/x/mod/sumdb/tlog's
// Tile.Path encoding of N.
//
// History: this previously rendered N >= 1000 as a bare decimal
// ("1234"), which 404s against any real log with more than 256,000
// leaves (i.e. every production Sunlight shard).
func tileIndexFormat(n int64) string {
	s := fmt.Sprintf("%03d", n%1000)
	for n >= 1000 {
		n /= 1000
		s = fmt.Sprintf("x%03d/%s", n%1000, s)
	}
	return s
}

// tileURL returns <logURL>tile/<level>/<N>[.p/<W>]. level is "data" for
// data tiles or the decimal tile level for hash tiles. width < tileWidth
// selects the partial-tile URL form.
func tileURL(logURL, level string, index int64, width int) string {
	u := logURL + "tile/" + level + "/" + tileIndexFormat(index)
	if width < tileWidth {
		u += ".p/" + strconv.Itoa(width)
	}
	return u
}

// errTileNotFound marks a 404 from a tile URL so callers can try the
// alternate (full vs. partial) form.
var errTileNotFound = errors.New("tile not found")

// fetchTileURL GETs one tile URL with a body-size cap. A 404 is returned
// wrapped in errTileNotFound.
func fetchTileURL(ctx context.Context, hc *http.Client, url string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s returned %d: %w", url, resp.StatusCode, errTileNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("%s: tile too large (>%d bytes)", url, maxBytes)
	}
	return body, nil
}

// FetchLeafTile fetches data tile `index` of a log whose verified
// checkpoint has tree size treeSize, and returns the raw tile bytes. The
// caller is responsible for parsing the tile into individual leaves (see
// ParseLeafTile below) and for ignoring any leaf at index >= treeSize.
//
// Full vs. partial tiles (c2sp.org/tlog-tiles, static-ct-api §1.1.3): a
// data tile holding fewer than 256 entries — always true of the LAST tile
// of a live, growing log — is served ONLY at the partial URL
// tile/data/<N>.p/<W>, where W = treeSize - N*256; the full URL 404s
// until the tile fills. Since W is known authoritatively from the signed
// checkpoint, a partial tile is requested at its .p/<W> URL directly;
// on 404 we fall back to the full URL, because a log MAY prune partial
// tiles once the full tile exists (the log grew past our checkpoint).
// A full tile's superset of entries is harmless: QueryDomain skips
// leaves at index >= treeSize.
//
// logURL must end with "/" (enforced by ValidateDomainConfig).
func FetchLeafTile(ctx context.Context, hc *http.Client, logURL string, index, treeSize int64) ([]byte, error) {
	const maxTileBytes = 16 << 20 // 16 MiB; a real 256-leaf data tile is well under 3 MiB
	remaining := treeSize - index*tileWidth
	if index < 0 || remaining <= 0 {
		return nil, fmt.Errorf("static: FetchLeafTile: tile %d is beyond tree size %d", index, treeSize)
	}
	width := tileWidth
	if remaining < tileWidth {
		width = int(remaining)
	}
	u := tileURL(logURL, "data", index, width)
	body, err := fetchTileURL(ctx, hc, u, maxTileBytes)
	if err != nil && width < tileWidth && errors.Is(err, errTileNotFound) {
		u = tileURL(logURL, "data", index, tileWidth)
		body, err = fetchTileURL(ctx, hc, u, maxTileBytes)
	}
	if err != nil {
		return nil, fmt.Errorf("static: FetchLeafTile: %w", err)
	}
	return body, nil
}

// LeafData is one parsed entry from a Static CT data tile, per
// c2sp.org/static-ct-api §1.1.3 (TileLeaf) wrapping RFC 6962 §3.4
// TimestampedEntry.
//
// Field semantics:
//   - Timestamp: TimestampedEntry.timestamp (uint64 ms since epoch).
//   - EntryType: TimestampedEntry.entry_type (0=x509, 1=precert).
//   - Certificate: signed_entry payload. For x509_entry this is the
//     full leaf certificate DER. For precert_entry this is the
//     TBSCertificate bytes (PreCert.tbs_certificate inside signed_entry).
//   - IssuerKeyHash: PreCert.issuer_key_hash, populated only when
//     EntryType == 1 (precert_entry); zero-valued otherwise.
//   - Extensions: CtExtensions raw bytes (uint16-length-prefixed in the
//     wire format; the length prefix is stripped here). For native
//     Sunlight entries this is typically the 8-byte leaf_index extension
//     (§1.1.5); for RFC 6962 archival leaves it is empty.
//   - PreCertificate: the §1.1.3 trailing `pre_certificate` field — the
//     ASN.1Cert that was actually submitted. Populated only when
//     EntryType == 1 (precert_entry).
//   - ChainFingerprints: §1.1.3 `certificate_chain<0..2^16-1>` as a list
//     of 32-byte SHA-256 fingerprints of the issuer chain certs.
type LeafData struct {
	Timestamp         uint64
	EntryType         uint16     // 0 = x509_entry, 1 = precert_entry
	Certificate       []byte     // full DER of the signed cert (leaf cert for x509; TBS for precert)
	IssuerKeyHash     [32]byte   // populated when EntryType == 1 (precert)
	Extensions        []byte     // raw extensions bytes (typically the 8-byte leaf_index extension)
	PreCertificate    []byte     // populated when EntryType == 1; the actual precert submitted
	ChainFingerprints [][32]byte // SHA-256 hashes of issuer chain certs
}

// ParseLeafTile decodes a Static CT data tile into individual leaf
// records per c2sp.org/static-ct-api §1.1.3 (TileLeaf) wrapping
// RFC 6962 §3.4 (TimestampedEntry).
//
// Canonical wire format (TLS-style, big-endian):
//
//	struct {
//	    TimestampedEntry timestamped_entry;
//	    select (entry_type) {
//	        case x509_entry: Empty;
//	        case precert_entry: ASN.1Cert pre_certificate;
//	    };
//	    Fingerprint certificate_chain<0..2^16-1>;
//	} TileLeaf;
//
//	opaque Fingerprint[32];
//
//	struct {
//	    uint64 timestamp;                       // big-endian
//	    LogEntryType entry_type;                // uint16 BE: 0=x509, 1=precert
//	    select(entry_type) {
//	        case x509_entry:   ASN.1Cert signed_entry;     // uint24-prefixed full cert DER
//	        case precert_entry: PreCert signed_entry;       // 32-byte IKH + uint24-prefixed TBS
//	    } signed_entry;
//	    CtExtensions extensions;                // uint16-prefixed; native Sunlight carries leaf_index ext
//	} TimestampedEntry;
//
// Matches Sunlight's `AppendTileLeaf()` reference implementation at
// github.com/FiloSottile/sunlight/blob/main/tile.go.
//
// Returns one LeafData per leaf record in the tile. A tile may hold
// fewer than 256 entries (partial trailing tile).
//
// History: prior to Fix Pass 2 (2026-05-27) this function read a
// fabricated wire format (timestamp + unconditional 32-byte IKH +
// uint24-prefixed TBS + uint24-prefixed chain_entry containing
// uint24-prefixed full cert DERs). That format misaligned the IKH to
// byte offset 8 — but real Sunlight tiles put entry_type at that
// offset — so the parser produced garbage against any production log.
// Test fixtures matched the wrong parser, so the test suite passed
// despite the bug. See `testdata/real_sunlight_tile_*.bin` for the
// ground-truth verification gate.
func ParseLeafTile(tile []byte) ([]LeafData, error) {
	var out []LeafData
	s := cryptobyte.String(tile)
	for !s.Empty() {
		var leaf LeafData

		if !s.ReadUint64(&leaf.Timestamp) {
			return nil, fmt.Errorf("static: ParseLeafTile: short read timestamp at offset %d", len(tile)-len(s))
		}
		if !s.ReadUint16(&leaf.EntryType) {
			return nil, fmt.Errorf("static: ParseLeafTile: short read entry_type")
		}
		switch leaf.EntryType {
		case 0: // x509_entry
			var cert cryptobyte.String
			if !s.ReadUint24LengthPrefixed(&cert) {
				return nil, fmt.Errorf("static: ParseLeafTile: short read x509 signed_entry")
			}
			leaf.Certificate = append([]byte(nil), cert...)
		case 1: // precert_entry
			var ikh cryptobyte.String
			if !s.ReadBytes((*[]byte)(&ikh), 32) {
				return nil, fmt.Errorf("static: ParseLeafTile: short read precert issuer_key_hash")
			}
			copy(leaf.IssuerKeyHash[:], ikh)
			var tbs cryptobyte.String
			if !s.ReadUint24LengthPrefixed(&tbs) {
				return nil, fmt.Errorf("static: ParseLeafTile: short read precert tbs")
			}
			leaf.Certificate = append([]byte(nil), tbs...)
		default:
			return nil, fmt.Errorf("static: ParseLeafTile: unknown entry_type %d", leaf.EntryType)
		}

		var ext cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&ext) {
			return nil, fmt.Errorf("static: ParseLeafTile: short read extensions")
		}
		leaf.Extensions = append([]byte(nil), ext...)

		if leaf.EntryType == 1 {
			var prec cryptobyte.String
			if !s.ReadUint24LengthPrefixed(&prec) {
				return nil, fmt.Errorf("static: ParseLeafTile: short read pre_certificate")
			}
			leaf.PreCertificate = append([]byte(nil), prec...)
		}

		var chain cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&chain) {
			return nil, fmt.Errorf("static: ParseLeafTile: short read chain_fingerprints")
		}
		for !chain.Empty() {
			var fp cryptobyte.String
			if !chain.ReadBytes((*[]byte)(&fp), 32) {
				return nil, fmt.Errorf("static: ParseLeafTile: short read chain fingerprint (need 32 bytes)")
			}
			var arr [32]byte
			copy(arr[:], fp)
			leaf.ChainFingerprints = append(leaf.ChainFingerprints, arr)
		}

		out = append(out, leaf)
	}
	return out, nil
}
