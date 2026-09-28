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
	"golang.org/x/crypto/cryptobyte"
)

// EncodeTileLeaf returns the bytes hashed (via tlog.RecordHash) to produce
// the Merkle-tree leaf hash for the given Static CT log entry. Follows the
// RFC 6962 §3.4 MerkleTreeLeaf structure as implemented in Sunlight's
// reference implementation (filippo.io/sunlight/tile.go MerkleTreeLeaf):
// version + leaf_type + TimestampedEntry + extensions.
//
// For native Sunlight log entries (archival=false), the extensions field
// carries a leaf_index extension per c2sp.org/static-ct-api §1.1.5.
// For RFC 6962 archival leaves migrated into Sunlight (archival=true),
// extensions is empty.
//
// Note: despite the function name, the output is NOT the c2sp.org §1.1.4
// TileLeaf storage record. §1.1.4 TileLeaf is the storage format
// (timestamp + IKH + TBS + chain); MerkleTreeLeaf is the hash input
// (prefix + timestamp + entry + extensions, no chain). The name
// EncodeTileLeaf is kept for project-local familiarity.
//
// leafIndex is the leaf's 0-based position in the log's Merkle tree;
// the caller computes it from tile_index * 256 + position_within_tile.
// Ignored when archival=true.
//
// Wire format produced (TLS-style, big-endian):
//
//	uint8  version            = 0   // v1
//	uint8  leaf_type          = 0   // timestamped_entry
//	uint64 timestamp                // TimestampedEntry.timestamp
//	uint16 entry_type               // 0=x509, 1=precert
//	select(entry_type) {
//	  case x509_entry:
//	    opaque  signed_entry<1..2^24-1>;     // leaf cert DER
//	  case precert_entry:
//	    opaque  issuer_key_hash[32];         // raw, no length prefix
//	    opaque  tbs_certificate<1..2^24-1>;
//	}
//	opaque extensions<0..2^16-1>;
//	  if archival:
//	    length = 0  // empty
//	  else:
//	    length = 8
//	    contents:
//	      uint8  extension_type     = 0   // leaf_index extension
//	      uint16 extension_data_len = 5
//	      uint40 leaf_index               // 5 raw big-endian bytes
//
// History: the original v1.25.1+v1.25.2-pre encoder (commits 22eac1f +
// e3d19dc) tried to encode the §1.1.4 TileLeaf storage record verbatim
// (timestamp + entry + extensions + pre_certificate + chain fingerprints)
// and use that as the hash input. That was internally consistent against
// our in-test fake log but produced wrong hashes against production
// Sunlight logs because the spec puts §1.1.4 TileLeaf on disk and a
// different structure into the Merkle tree. The bytes the log actually
// signs over are the RFC 6962 MerkleTreeLeaf above — verified against
// Sunlight's reference MerkleTreeLeaf() function at
// https://github.com/FiloSottile/sunlight/blob/main/tile.go.
//
// Spec: c2sp.org/static-ct-api §1.1.5 (data tile extensions, leaf_index);
// RFC 6962 §2.1 (leaf hash with 0x00 prefix), §3.4 (MerkleTreeLeaf and
// TimestampedEntry); Sunlight reference impl
// (github.com/FiloSottile/sunlight/blob/main/tile.go MerkleTreeLeaf).
func EncodeTileLeaf(leaf LeafData, leafIndex uint64, archival bool) []byte {
	b := cryptobyte.NewBuilder(nil)

	// MerkleTreeLeaf header (RFC 6962 §3.4):
	//   uint8 version    = v1 (0)
	//   uint8 leaf_type  = timestamped_entry (0)
	// Both are fixed for v1 Static CT logs.
	b.AddUint8(0) // version = v1
	b.AddUint8(0) // leaf_type = timestamped_entry

	// TimestampedEntry.timestamp (uint64 big-endian).
	b.AddUint64(leaf.Timestamp)

	precert := isPrecert(leaf)

	// TimestampedEntry.entry_type + signed_entry. The precert branch
	// inlines the PreCert struct (issuer_key_hash + TBSCertificate)
	// rather than the full precert DER — see RFC 6962 §3.4. The full
	// precert DER lives in the TileLeaf storage record (§1.1.4), not
	// in the hash input.
	//
	// LeafData.Certificate is semantically the signed_entry payload:
	// for x509 it's the full leaf cert DER; for precert it's the TBS
	// (PreCert.tbs_certificate) — the same field, repurposed per
	// entry_type, mirroring how Sunlight's TileLeaf storage record
	// writes signed_entry.
	if precert {
		b.AddUint16(1) // precert_entry
		// PreCert.issuer_key_hash (raw 32 bytes, no length prefix).
		b.AddBytes(leaf.IssuerKeyHash[:])
		// PreCert.tbs_certificate (uint24-length-prefixed).
		b.AddUint24LengthPrefixed(func(d *cryptobyte.Builder) {
			d.AddBytes(leaf.Certificate)
		})
	} else {
		b.AddUint16(0) // x509_entry
		// ASN.1Cert signed_entry (uint24-length-prefixed): the leaf
		// certificate DER.
		b.AddUint24LengthPrefixed(func(d *cryptobyte.Builder) {
			d.AddBytes(leaf.Certificate)
		})
	}

	// CtExtensions (uint16-length-prefixed). For native Sunlight log
	// entries this carries the leaf_index extension (§1.1.5). For
	// RFC 6962 archival leaves migrated into Sunlight the field is
	// empty — Sunlight detects this and routes via
	// ReadTileLeafMaybeArchival.
	if archival {
		b.AddUint16(0)
	} else {
		b.AddUint16LengthPrefixed(func(d *cryptobyte.Builder) {
			appendLeafIndexExtension(d, leafIndex)
		})
	}

	// NOTE: No pre_certificate field and no certificate_chain here.
	// Both live in the §1.1.4 TileLeaf storage record, NOT in the
	// MerkleTreeLeaf hash input. This is the load-bearing correction
	// from the prior encoder.

	// cryptobyte.Builder.Bytes only errors on integer-overflow length
	// prefixes; our inputs are bounded by data-tile parser limits well
	// below 2^24. Ignore the error per cryptobyte conventions.
	out, _ := b.Bytes()
	return out
}

// appendLeafIndexExtension marshals the c2sp.org/static-ct-api §1.1.5
// leaf_index extension into the given builder. Wire format:
//
//	uint8  extension_type     = 0   // leaf_index
//	uint16 extension_data_len = 5
//	uint40 leaf_index               // 5 raw big-endian bytes
//
// cryptobyte has no uint40 helper, so the 5 big-endian bytes are emitted
// by hand. Mirrors filippo.io/sunlight/extensions.go MarshalExtensions
// and addUint40.
func appendLeafIndexExtension(b *cryptobyte.Builder, leafIndex uint64) {
	b.AddUint8(0x00) // extension_type = leaf_index
	b.AddUint16LengthPrefixed(func(d *cryptobyte.Builder) {
		// uint40: 5 raw big-endian bytes. Each byte(leafIndex >> N) below
		// is the intended truncation (extracting one octet of a 40-bit
		// value), not an accidental overflow — gosec G115 can't tell
		// deliberate byte-splitting apart from an unsafe cast.
		d.AddBytes([]byte{
			byte(leafIndex >> 32), // #nosec G115
			byte(leafIndex >> 24), // #nosec G115
			byte(leafIndex >> 16), // #nosec G115
			byte(leafIndex >> 8),  // #nosec G115
			byte(leafIndex),       // #nosec G115
		})
	})
}

// isPrecert classifies a LeafData by its parsed EntryType field
// (set by ParseLeafTile from the wire-format entry_type per RFC 6962
// §3.4). EntryType == 1 → precert_entry; anything else (canonically 0)
// → x509_entry. Explicit and unambiguous — replaces the prior
// all-zero-issuer_key_hash heuristic, which was lossy because a
// precert with an all-zero IKH (theoretically possible) would have
// been misclassified.
func isPrecert(leaf LeafData) bool {
	return leaf.EntryType == 1
}
