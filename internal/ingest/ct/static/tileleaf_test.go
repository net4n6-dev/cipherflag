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
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

// TestEncodeTileLeaf_X509Entry checks the encoder produces the expected
// byte sequence for an x509_entry archival leaf (no leaf_index extension,
// so the expected bytes are minimal). The expected bytes are constructed
// from the spec field-by-field for transparency — if the encoder drifts
// from the spec this test breaks loudly.
//
// Exercises archival=true so the CtExtensions block is empty (per Sunlight
// addExtensions when RFC6962ArchivalLeaf=true).
func TestEncodeTileLeaf_X509Entry(t *testing.T) {
	leaf := LeafData{
		Timestamp:         0x0123456789abcdef,
		EntryType:         0, // x509_entry
		IssuerKeyHash:     [32]byte{},
		Certificate:       []byte{0xDE, 0xAD, 0xBE, 0xEF}, // full leaf cert DER for x509
		PreCertificate:    nil,
		ChainFingerprints: nil, // not encoded into hash bytes
	}

	got := EncodeTileLeaf(leaf, 0, true /* archival */)

	var want bytes.Buffer
	// MerkleTreeLeaf header (RFC 6962 §3.4): version=v1(0) || leaf_type=timestamped_entry(0)
	want.WriteByte(0x00)
	want.WriteByte(0x00)
	// TimestampedEntry.timestamp (uint64 big-endian)
	_ = binary.Write(&want, binary.BigEndian, uint64(0x0123456789abcdef))
	// TimestampedEntry.entry_type (uint16 big-endian, x509_entry=0)
	want.WriteByte(0x00)
	want.WriteByte(0x00)
	// signed_entry: ASN.1Cert (uint24-length-prefixed)
	want.WriteByte(0x00)
	want.WriteByte(0x00)
	want.WriteByte(0x04) // length = 4
	want.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	// CtExtensions (uint16-length-prefixed, empty for archival)
	want.WriteByte(0x00)
	want.WriteByte(0x00)

	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("EncodeTileLeaf x509: bytes mismatch\n got: %x\nwant: %x", got, want.Bytes())
	}
}

// TestEncodeTileLeaf_PrecertEntry checks the precert_entry variant in
// archival mode: non-zero issuer_key_hash → signed_entry is PreCert
// {ikh, tbs}. No pre_certificate field, no certificate_chain (those live
// only in the §1.1.4 TileLeaf storage record, not in the MerkleTreeLeaf
// hash input).
func TestEncodeTileLeaf_PrecertEntry(t *testing.T) {
	var ikh [32]byte
	for i := range ikh {
		ikh[i] = byte(i + 1) // non-zero
	}
	leaf := LeafData{
		Timestamp:         0x1122334455667788,
		EntryType:         1, // precert_entry
		IssuerKeyHash:     ikh,
		Certificate:       []byte{0xAA, 0xBB},       // TBSCertificate, per RFC 6962 §3.4 PreCert.tbs_certificate
		PreCertificate:    []byte{0xCC, 0xDD, 0xEE}, // not encoded into hash bytes for MerkleTreeLeaf
		ChainFingerprints: nil,
	}

	got := EncodeTileLeaf(leaf, 0, true /* archival */)

	var want bytes.Buffer
	// MerkleTreeLeaf header
	want.WriteByte(0x00) // version = v1
	want.WriteByte(0x00) // leaf_type = timestamped_entry
	// timestamp (uint64 big-endian)
	_ = binary.Write(&want, binary.BigEndian, uint64(0x1122334455667788))
	// entry_type = precert_entry (1)
	want.WriteByte(0x00)
	want.WriteByte(0x01)
	// PreCert.issuer_key_hash (32 raw bytes)
	want.Write(ikh[:])
	// PreCert.tbs_certificate (uint24-length-prefixed)
	want.WriteByte(0x00)
	want.WriteByte(0x00)
	want.WriteByte(0x02)
	want.Write([]byte{0xAA, 0xBB})
	// CtExtensions empty (archival)
	want.WriteByte(0x00)
	want.WriteByte(0x00)
	// No pre_certificate, no certificate_chain — those live only in §1.1.4 storage.

	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("EncodeTileLeaf precert: bytes mismatch\n got: %x\nwant: %x", got, want.Bytes())
	}
}

// TestEncodeTileLeaf_X509Native exercises a native Sunlight x509 leaf
// (archival=false), which carries the leaf_index extension per
// c2sp.org/static-ct-api §1.1.5. Chain DERs are not encoded into the
// hash bytes — they live only in the §1.1.4 storage record.
//
// Renamed from TestEncodeTileLeaf_X509WithChain (chain is no longer
// part of the hash input after the post-review correction).
func TestEncodeTileLeaf_X509Native(t *testing.T) {
	leaf := LeafData{
		Timestamp:     0,
		EntryType:     0,
		IssuerKeyHash: [32]byte{},
		Certificate:   []byte{0xAA},
		// Chain fingerprints present in LeafData but intentionally
		// NOT expected in hash output (chain lives only in storage).
		ChainFingerprints: [][32]byte{{0x11, 0x22, 0x33}, {0x44, 0x55, 0x66, 0x77}},
	}
	const leafIndex = uint64(42)

	got := EncodeTileLeaf(leaf, leafIndex, false /* native */)

	// Reconstruct expected:
	//   prefix(2) + timestamp(8) + entry_type(2) + signed_entry(3+1)
	//   + ext_outer_len(2) + ext_type(1) + ext_data_len(2) + uint40(5)
	want := make([]byte, 0, 2+8+2+4+2+8)
	want = append(want, 0x00, 0x00)                         // version || leaf_type
	want = append(want, 0, 0, 0, 0, 0, 0, 0, 0)             // timestamp = 0
	want = append(want, 0x00, 0x00)                         // entry_type = x509
	want = append(want, 0x00, 0x00, 0x01, 0xAA)             // signed_entry (uint24 len = 1)
	want = append(want, 0x00, 0x08)                         // CtExtensions uint16 outer len = 8
	want = append(want, 0x00)                               // extension_type = 0 (leaf_index)
	want = append(want, 0x00, 0x05)                         // extension_data_len = 5
	want = append(want, 0x00, 0x00, 0x00, 0x00, byte(0x2A)) // uint40 leafIndex = 42

	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeTileLeaf x509 native: bytes mismatch\n got: %x\nwant: %x", got, want)
	}
}

// TestEncodeTileLeaf_RecordHashStable confirms the leaf hash going into
// the Merkle tree is tlog.RecordHash of the encoded bytes — i.e. a wrapper
// over SHA-256(0x00 || encoded) per RFC 6962 §2.1.
//
// This is the load-bearing equation: VerifyInclusion will call
// tlog.RecordHash(EncodeTileLeaf(leaf, idx, archival)) and compare against
// the proof-derived root.
func TestEncodeTileLeaf_RecordHashStable(t *testing.T) {
	leaf := LeafData{
		Timestamp:   0,
		EntryType:   0,
		Certificate: []byte{0xAA, 0xBB, 0xCC},
	}
	encoded := EncodeTileLeaf(leaf, 99, false)
	h1 := tlog.RecordHash(encoded)
	h2 := tlog.RecordHash(encoded)
	if h1 != h2 {
		t.Errorf("RecordHash not deterministic: %x vs %x", h1, h2)
	}
	// Spot-check: changing one byte changes the hash.
	mutated := append([]byte(nil), encoded...)
	mutated[len(mutated)-1] ^= 0xFF
	h3 := tlog.RecordHash(mutated)
	if h1 == h3 {
		t.Errorf("RecordHash insensitive to mutation: should differ but didn't")
	}
	// Spot-check: different leafIndex → different bytes → different hash.
	encoded2 := EncodeTileLeaf(leaf, 100, false)
	if bytes.Equal(encoded, encoded2) {
		t.Errorf("EncodeTileLeaf insensitive to leafIndex: encodings should differ")
	}
	if tlog.RecordHash(encoded2) == h1 {
		t.Errorf("RecordHash insensitive to leafIndex shift")
	}
}

// TestEncodeTileLeaf_X509Golden locks down the x509 wire format against
// a committed golden vector. Fixture provenance documented in
// testdata/README.md.
func TestEncodeTileLeaf_X509Golden(t *testing.T) {
	leaf, leafIndex, archival := canonicalX509Fixture()
	got := EncodeTileLeaf(leaf, leafIndex, archival)
	want := mustReadGolden(t, "testdata/tileleaf_x509_golden.bin")
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeTileLeaf x509 golden mismatch\n got: %x\nwant: %x", got, want)
	}
}

func TestEncodeTileLeaf_PrecertGolden(t *testing.T) {
	leaf, leafIndex, archival := canonicalPrecertFixture()
	got := EncodeTileLeaf(leaf, leafIndex, archival)
	want := mustReadGolden(t, "testdata/tileleaf_precert_golden.bin")
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeTileLeaf precert golden mismatch\n got: %x\nwant: %x", got, want)
	}
}

// TestEncodeTileLeaf_LeafIndexExtension_BoundaryValues exercises the
// uint40 leaf_index encoding at both ends of its valid range:
//   - leafIndex = 0       → 00 00 00 00 00
//   - leafIndex = 2^40-1  → FF FF FF FF FF
//
// Catches any off-by-one or endianness bug in the hand-rolled uint40
// encoder (cryptobyte has no built-in uint40 helper).
func TestEncodeTileLeaf_LeafIndexExtension_BoundaryValues(t *testing.T) {
	leaf := LeafData{
		Timestamp:   0,
		EntryType:   0,
		Certificate: []byte{0xAA},
	}
	// The 5 trailing bytes of the encoded leaf are the uint40 leaf_index.
	cases := []struct {
		name      string
		leafIndex uint64
		want5     []byte
	}{
		{"zero", 0, []byte{0x00, 0x00, 0x00, 0x00, 0x00}},
		{"max_uint40", (1 << 40) - 1, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EncodeTileLeaf(leaf, tc.leafIndex, false /* native */)
			if len(got) < 5 {
				t.Fatalf("encoded too short: %d bytes", len(got))
			}
			gotTail := got[len(got)-5:]
			if !bytes.Equal(gotTail, tc.want5) {
				t.Fatalf("uint40 leaf_index encoding mismatch\n got tail: %x\nwant tail: %x", gotTail, tc.want5)
			}
		})
	}
}

// canonicalX509Fixture returns a deterministic (LeafData, leafIndex,
// archival) triple representing a native Sunlight x509_entry leaf with
// a small leaf DER. ChainFingerprints is set but not expected in the
// hash output. The leafIndex value is meaningful for review.
func canonicalX509Fixture() (LeafData, uint64, bool) {
	leaf := LeafData{
		Timestamp:     0x0000019345678ABC, // arbitrary fixed value
		EntryType:     0,                  // x509_entry
		IssuerKeyHash: [32]byte{},
		Certificate:   []byte("FAKE-CERT-LEAF-x509-DER-2026-05-27"),
		// ChainFingerprints present in storage but NOT in MerkleTreeLeaf hash output.
		ChainFingerprints: [][32]byte{sha256OfStringFixture("FAKE-ISSUER-INTERMEDIATE")},
	}
	const leafIndex = uint64(0x42)
	return leaf, leafIndex, false /* native */
}

func canonicalPrecertFixture() (LeafData, uint64, bool) {
	var ikh [32]byte
	for i := range ikh {
		ikh[i] = byte(0xA0 + i%16)
	}
	leaf := LeafData{
		Timestamp:         0x0000018012345678,
		EntryType:         1, // precert_entry
		IssuerKeyHash:     ikh,
		Certificate:       []byte("FAKE-TBS-CERT-PRECERT-2026-05-27"), // PreCert.tbs_certificate
		PreCertificate:    []byte("FAKE-PRECERT-FULL-DER-2026-05-27"), // §1.1.3 pre_certificate
		ChainFingerprints: [][32]byte{sha256OfStringFixture("FAKE-ISSUER-1"), sha256OfStringFixture("FAKE-ISSUER-2")},
	}
	const leafIndex = uint64(0x1234567890)
	return leaf, leafIndex, false /* native */
}

// sha256OfStringFixture is a tiny helper so the canonical fixtures can
// build [32]byte chain fingerprints from human-readable issuer names.
// Uses crypto/sha256 directly (kept local to avoid leaking the helper
// into non-test code).
func sha256OfStringFixture(s string) [32]byte {
	return sha256.Sum256([]byte(s))
}

func mustReadGolden(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (regenerate via the recipe in testdata/README.md)", path, err)
	}
	return data
}
