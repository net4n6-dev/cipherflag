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
	"fmt"
	"io"
	"net/http"

	"golang.org/x/crypto/cryptobyte"
)

// tileIndexFormat is the zero-padded three-digit decimal tile index
// used in Static CT URLs (`/tile/data/000`, `/tile/data/001`, etc.).
// Per the spec, indices >= 1000 use four digits and so on — i.e. the
// shortest decimal representation with at least three digits.
func tileIndexFormat(n int64) string {
	if n < 1000 {
		return fmt.Sprintf("%03d", n)
	}
	return fmt.Sprintf("%d", n)
}

// FetchLeafTile GETs <logURL>tile/data/<index> and returns the raw
// tile bytes. The caller is responsible for parsing the tile into
// individual leaves (see ParseLeafTile below) — keeping fetch and
// parse separate lets the poller stream-verify inclusion proofs
// without buffering an entire batch in memory if a future change
// needs that.
//
// logURL must end with "/" (enforced by Config.Validate).
//
// Spec: c2sp.org/static-ct-api §1.1.3 (tile URLs and format).
func FetchLeafTile(ctx context.Context, hc *http.Client, logURL string, index int64) ([]byte, error) {
	url := logURL + "tile/data/" + tileIndexFormat(index)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("static: FetchLeafTile: build request: %w", err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("static: FetchLeafTile: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("static: FetchLeafTile: %s returned %d", url, resp.StatusCode)
	}
	const maxTileBytes = 16 << 20 // 16 MiB; a real 256-leaf data tile is well under 3 MiB
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("static: FetchLeafTile: read body: %w", err)
	}
	if int64(len(body)) > maxTileBytes {
		return nil, fmt.Errorf("static: FetchLeafTile: tile too large (>%d bytes)", maxTileBytes)
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
