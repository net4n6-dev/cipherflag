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
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

func TestFetchLeafTile_OK(t *testing.T) {
	const tileBody = "fake-tile-bytes-for-test"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Static CT data-tile path: /tile/data/<index>
		if r.URL.Path != "/2024h2/tile/data/000" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte(tileBody))
	}))
	defer srv.Close()

	logURL := srv.URL + "/2024h2/"
	got, err := FetchLeafTile(context.Background(), srv.Client(), logURL, 0)
	if err != nil {
		t.Fatalf("FetchLeafTile: %v", err)
	}
	if string(got) != tileBody {
		t.Errorf("body = %q, want %q", got, tileBody)
	}
}

func TestFetchLeafTile_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := FetchLeafTile(context.Background(), srv.Client(), srv.URL+"/2024h2/", 0)
	if err == nil || !strings.Contains(err.Error(), "returned 500") {
		t.Errorf("err = %v, want substring \"returned 500\"", err)
	}
}

// buildTestX509Leaf appends one synthetic x509_entry TileLeaf to b,
// matching the canonical c2sp.org/static-ct-api §1.1.3 wire format.
// timestamp + entry_type(0) + signed_entry(cert) + ext + chainFP*32.
func buildTestX509Leaf(b *cryptobyte.Builder, timestamp uint64, certDER []byte, ext []byte, chainFPs [][32]byte) {
	b.AddUint64(timestamp)
	b.AddUint16(0) // x509_entry
	b.AddUint24LengthPrefixed(func(d *cryptobyte.Builder) { d.AddBytes(certDER) })
	b.AddUint16LengthPrefixed(func(d *cryptobyte.Builder) { d.AddBytes(ext) })
	b.AddUint16LengthPrefixed(func(d *cryptobyte.Builder) {
		for _, fp := range chainFPs {
			d.AddBytes(fp[:])
		}
	})
}

// buildTestPrecertLeaf appends one synthetic precert_entry TileLeaf
// per c2sp.org/static-ct-api §1.1.3. timestamp + entry_type(1)
// + IKH(32) + tbs + ext + pre_cert + chainFP*32.
func buildTestPrecertLeaf(b *cryptobyte.Builder, timestamp uint64, ikh [32]byte, tbs, ext, preCert []byte, chainFPs [][32]byte) {
	b.AddUint64(timestamp)
	b.AddUint16(1) // precert_entry
	b.AddBytes(ikh[:])
	b.AddUint24LengthPrefixed(func(d *cryptobyte.Builder) { d.AddBytes(tbs) })
	b.AddUint16LengthPrefixed(func(d *cryptobyte.Builder) { d.AddBytes(ext) })
	b.AddUint24LengthPrefixed(func(d *cryptobyte.Builder) { d.AddBytes(preCert) })
	b.AddUint16LengthPrefixed(func(d *cryptobyte.Builder) {
		for _, fp := range chainFPs {
			d.AddBytes(fp[:])
		}
	})
}

// TestParseLeafTile_X509RoundTrip exercises the x509_entry branch and
// the multi-leaf case. Builds two synthetic x509 leaves matching the
// canonical wire format, parses, and asserts every field round-trips
// (including a non-empty chain_fingerprints + a synthetic extensions
// payload).
func TestParseLeafTile_X509RoundTrip(t *testing.T) {
	fp1 := [32]byte{0x11, 0x22}
	fp1[31] = 0xEE
	fp2 := [32]byte{0xAA, 0xBB}
	fp2[31] = 0xFF
	ext := []byte{0x00, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04} // 7 raw bytes; not a real ext, just a payload

	b := cryptobyte.NewBuilder(nil)
	buildTestX509Leaf(b, 1000, []byte("cert-A"), ext, [][32]byte{fp1, fp2})
	buildTestX509Leaf(b, 1001, []byte("cert-B-longer"), nil, nil) // empty ext + empty chain
	tileBytes, err := b.Bytes()
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	got, err := ParseLeafTile(tileBytes)
	if err != nil {
		t.Fatalf("ParseLeafTile: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}

	if got[0].Timestamp != 1000 || got[1].Timestamp != 1001 {
		t.Errorf("timestamps wrong: %d, %d", got[0].Timestamp, got[1].Timestamp)
	}
	if got[0].EntryType != 0 || got[1].EntryType != 0 {
		t.Errorf("EntryType wrong: %d, %d", got[0].EntryType, got[1].EntryType)
	}
	if string(got[0].Certificate) != "cert-A" {
		t.Errorf("leaf 0 Certificate = %q, want cert-A", got[0].Certificate)
	}
	if string(got[1].Certificate) != "cert-B-longer" {
		t.Errorf("leaf 1 Certificate = %q, want cert-B-longer", got[1].Certificate)
	}
	if got[0].PreCertificate != nil {
		t.Errorf("x509 leaf 0 PreCertificate should be nil, got %v", got[0].PreCertificate)
	}
	var zeroIKH [32]byte
	if got[0].IssuerKeyHash != zeroIKH {
		t.Errorf("x509 leaf 0 IssuerKeyHash should be zero, got %x", got[0].IssuerKeyHash)
	}
	if string(got[0].Extensions) != string(ext) {
		t.Errorf("leaf 0 Extensions = %x, want %x", got[0].Extensions, ext)
	}
	if len(got[0].ChainFingerprints) != 2 {
		t.Fatalf("leaf 0 chain len = %d, want 2", len(got[0].ChainFingerprints))
	}
	if got[0].ChainFingerprints[0] != fp1 || got[0].ChainFingerprints[1] != fp2 {
		t.Errorf("chain fingerprints wrong: got[0]=%x got[1]=%x", got[0].ChainFingerprints[0], got[0].ChainFingerprints[1])
	}
	if len(got[1].ChainFingerprints) != 0 {
		t.Errorf("leaf 1 chain len = %d, want 0", len(got[1].ChainFingerprints))
	}
}

// TestParseLeafTile_PrecertRoundTrip exercises the precert_entry branch.
// Builds one synthetic precert leaf and asserts IKH, TBS-as-Certificate,
// PreCertificate, extensions, and chain fingerprints all round-trip.
func TestParseLeafTile_PrecertRoundTrip(t *testing.T) {
	var ikh [32]byte
	for i := range ikh {
		ikh[i] = byte(i + 1) // non-zero pattern
	}
	fp := [32]byte{0xCC, 0xDD}
	fp[31] = 0xEE
	ext := []byte{0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00} // 8-byte synthetic leaf_index ext payload

	b := cryptobyte.NewBuilder(nil)
	buildTestPrecertLeaf(b, 2000, ikh,
		[]byte("tbs-cert-bytes"),
		ext,
		[]byte("submitted-precert-DER"),
		[][32]byte{fp})
	tileBytes, err := b.Bytes()
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	got, err := ParseLeafTile(tileBytes)
	if err != nil {
		t.Fatalf("ParseLeafTile: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	leaf := got[0]
	if leaf.Timestamp != 2000 {
		t.Errorf("Timestamp = %d, want 2000", leaf.Timestamp)
	}
	if leaf.EntryType != 1 {
		t.Errorf("EntryType = %d, want 1 (precert)", leaf.EntryType)
	}
	if leaf.IssuerKeyHash != ikh {
		t.Errorf("IssuerKeyHash = %x, want %x", leaf.IssuerKeyHash, ikh)
	}
	if string(leaf.Certificate) != "tbs-cert-bytes" {
		t.Errorf("Certificate (TBS for precert) = %q, want tbs-cert-bytes", leaf.Certificate)
	}
	if string(leaf.Extensions) != string(ext) {
		t.Errorf("Extensions = %x, want %x", leaf.Extensions, ext)
	}
	if string(leaf.PreCertificate) != "submitted-precert-DER" {
		t.Errorf("PreCertificate = %q, want submitted-precert-DER", leaf.PreCertificate)
	}
	if len(leaf.ChainFingerprints) != 1 || leaf.ChainFingerprints[0] != fp {
		t.Errorf("ChainFingerprints wrong: %x", leaf.ChainFingerprints)
	}
}

// TestParseLeafTile_MultiLeafMixed mixes x509 + precert entries in one
// tile — the format that real Sunlight tiles use. Confirms the parser
// advances correctly between the two entry-type-dependent payload
// shapes (precert has an extra 32-byte IKH + trailing pre_certificate
// field that x509 does not).
func TestParseLeafTile_MultiLeafMixed(t *testing.T) {
	var ikh [32]byte
	ikh[0] = 0xA0
	b := cryptobyte.NewBuilder(nil)
	buildTestX509Leaf(b, 100, []byte("x509-leaf-0"), nil, nil)
	buildTestPrecertLeaf(b, 200, ikh, []byte("tbs-1"), nil, []byte("prec-1"), nil)
	buildTestX509Leaf(b, 300, []byte("x509-leaf-2"), nil, nil)
	tileBytes, err := b.Bytes()
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	got, err := ParseLeafTile(tileBytes)
	if err != nil {
		t.Fatalf("ParseLeafTile: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	want := []struct {
		ts      uint64
		et      uint16
		certStr string
	}{
		{100, 0, "x509-leaf-0"},
		{200, 1, "tbs-1"},
		{300, 0, "x509-leaf-2"},
	}
	for i, w := range want {
		if got[i].Timestamp != w.ts || got[i].EntryType != w.et || string(got[i].Certificate) != w.certStr {
			t.Errorf("leaf %d = {ts:%d, et:%d, cert:%q}, want {ts:%d, et:%d, cert:%q}",
				i, got[i].Timestamp, got[i].EntryType, got[i].Certificate, w.ts, w.et, w.certStr)
		}
	}
	if got[1].IssuerKeyHash != ikh {
		t.Errorf("precert leaf 1 IKH = %x, want %x", got[1].IssuerKeyHash, ikh)
	}
	if string(got[1].PreCertificate) != "prec-1" {
		t.Errorf("precert leaf 1 PreCertificate = %q, want prec-1", got[1].PreCertificate)
	}
}

func TestParseLeafTile_Empty(t *testing.T) {
	got, err := ParseLeafTile(nil)
	if err != nil {
		t.Errorf("empty tile err = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("empty tile = %+v, want nil", got)
	}
}

// TestParseLeafTile_UnknownEntryType — the parser must reject an
// out-of-range entry_type (not 0 or 1) rather than silently skipping
// or hanging.
func TestParseLeafTile_UnknownEntryType(t *testing.T) {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint64(1234)
	b.AddUint16(99) // bogus entry_type
	bs, err := b.Bytes()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	_, err = ParseLeafTile(bs)
	if err == nil {
		t.Fatal("ParseLeafTile accepted bogus entry_type; want error")
	}
	if !strings.Contains(err.Error(), "unknown entry_type") {
		t.Errorf("err = %v, want substring \"unknown entry_type\"", err)
	}
}

// TestParseLeafTile_TruncationErrors_X509 exercises each truncation
// point of a 1-leaf x509 tile. Confirms every short-read error path
// returns a descriptive error rather than a panic or garbage.
func TestParseLeafTile_TruncationErrors_X509(t *testing.T) {
	b := cryptobyte.NewBuilder(nil)
	buildTestX509Leaf(b, 1234, []byte("cert-body"), []byte{0xAA, 0xBB}, [][32]byte{{}})
	full, err := b.Bytes()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// Layout: ts(8) | et(2) | u24len(3) | cert(9) | extLen(2) | ext(2) | chainLen(2) | fp(32)
	cases := []struct {
		name   string
		tile   []byte
		wantIn string
	}{
		{"truncated-timestamp", full[:4], "timestamp"},
		{"truncated-entry-type", full[:8+1], "entry_type"},
		{"truncated-signed-entry-len", full[:8+2+1], "x509 signed_entry"},
		{"truncated-signed-entry-body", full[:8+2+3+2], "x509 signed_entry"},
		{"truncated-extensions-len", full[:8+2+3+9+1], "extensions"},
		{"truncated-extensions-body", full[:8+2+3+9+2+1], "extensions"},
		{"truncated-chain-len", full[:8+2+3+9+2+2+1], "chain_fingerprints"},
		// Underflow at the uint16 chain length prefix vs body: when the
		// outer chain length prefix says 32 but we only ship 10 body
		// bytes, ReadUint16LengthPrefixed itself rejects the read →
		// "chain_fingerprints" path. The inner "chain fingerprint"
		// (must-be-32-bytes-per-fp) path is exercised separately below
		// with a deliberately non-multiple-of-32 chain length.
		{"truncated-chain-body", full[:8+2+3+9+2+2+2+10], "chain_fingerprints"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseLeafTile(tc.tile)
			if err == nil {
				t.Fatalf("got nil err, want error containing %q", tc.wantIn)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("err = %v, want substring %q", err, tc.wantIn)
			}
		})
	}
}

// TestParseLeafTile_ChainNotMultipleOf32 — when the chain_fingerprints
// outer length is well-formed (the bytes are present) but is NOT a
// multiple of 32, the inner loop's per-fp `ReadBytes(_, 32)` fails on
// the trailing partial fingerprint. Exercises the inner "chain
// fingerprint" error path that the truncation-suite above can't reach.
func TestParseLeafTile_ChainNotMultipleOf32(t *testing.T) {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint64(1234)
	b.AddUint16(0) // x509_entry
	b.AddUint24LengthPrefixed(func(d *cryptobyte.Builder) { d.AddBytes([]byte("c")) })
	b.AddUint16(0) // empty extensions
	// chain_fingerprints: 40 bytes (one full 32-byte fp + 8 garbage bytes).
	b.AddUint16LengthPrefixed(func(d *cryptobyte.Builder) {
		d.AddBytes(make([]byte, 40))
	})
	bs, err := b.Bytes()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	_, err = ParseLeafTile(bs)
	if err == nil {
		t.Fatal("ParseLeafTile accepted non-multiple-of-32 chain; want error")
	}
	if !strings.Contains(err.Error(), "chain fingerprint") {
		t.Errorf("err = %v, want substring \"chain fingerprint\"", err)
	}
}

// TestParseLeafTile_TruncationErrors_Precert exercises the precert-only
// truncation paths (IKH and trailing pre_certificate). The x509 paths
// are covered above; this only guards the precert-specific reads.
func TestParseLeafTile_TruncationErrors_Precert(t *testing.T) {
	var ikh [32]byte
	ikh[0] = 0xA0
	b := cryptobyte.NewBuilder(nil)
	buildTestPrecertLeaf(b, 5678, ikh, []byte("tbs"), nil, []byte("prec"), nil)
	full, err := b.Bytes()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// Layout: ts(8) | et(2) | IKH(32) | tbsLen(3) | tbs(3) | extLen(2) | preLen(3) | pre(4) | chainLen(2)
	cases := []struct {
		name   string
		tile   []byte
		wantIn string
	}{
		{"truncated-ikh", full[:8+2+16], "issuer_key_hash"},
		{"truncated-tbs-len", full[:8+2+32+1], "precert tbs"},
		{"truncated-tbs-body", full[:8+2+32+3+2], "precert tbs"},
		{"truncated-pre-cert-len", full[:8+2+32+3+3+2+1], "pre_certificate"},
		{"truncated-pre-cert-body", full[:8+2+32+3+3+2+3+2], "pre_certificate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseLeafTile(tc.tile)
			if err == nil {
				t.Fatalf("got nil err, want error containing %q", tc.wantIn)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("err = %v, want substring %q", err, tc.wantIn)
			}
		})
	}
}

// TestParseLeafTile_AgainstRealSunlightTile is the load-bearing
// ground-truth gate: it parses an actual data tile fetched once from a
// production Sunlight log (committed under testdata/) and confirms the
// parser decodes every leaf without error. Without this test the parser
// could drift from the spec silently — synthetic-only tests can match
// any encoder the test author wrote.
//
// Fixture provenance documented in testdata/README.md.
func TestParseLeafTile_AgainstRealSunlightTile(t *testing.T) {
	data, err := os.ReadFile("testdata/real_sunlight_tile_trustasia_log2026a_000.bin")
	if err != nil {
		t.Fatalf("read real tile fixture: %v", err)
	}
	leaves, err := ParseLeafTile(data)
	if err != nil {
		t.Fatalf("ParseLeafTile failed on real Sunlight tile: %v", err)
	}
	if len(leaves) == 0 {
		t.Fatal("ParseLeafTile returned zero leaves from real tile")
	}

	now := uint64(time.Now().UnixMilli())
	// Allow timestamps anywhere from 5 years ago through 1 hour in the
	// future. Real production logs (like TrustAsia 'log2026a') started
	// admitting submissions in 2024 even though the shard is named for
	// the 2026 expiry window, so a 2-year window would have been too
	// tight. 1-hour future skew tolerates clock drift at fetch time.
	fiveYearsAgo := now - 5*365*24*3600*1000
	oneHourFuture := now + 3600*1000

	x509Seen, precertSeen := 0, 0
	for i, leaf := range leaves {
		if leaf.EntryType > 1 {
			t.Errorf("leaf %d entry_type %d invalid (must be 0 or 1)", i, leaf.EntryType)
		}
		if leaf.Timestamp < fiveYearsAgo || leaf.Timestamp > oneHourFuture {
			t.Errorf("leaf %d timestamp %d out of plausible range [%d, %d]", i, leaf.Timestamp, fiveYearsAgo, oneHourFuture)
		}
		switch leaf.EntryType {
		case 0:
			x509Seen++
			// x509 signed_entry is a full cert DER — must parse.
			if _, err := x509.ParseCertificate(leaf.Certificate); err != nil {
				t.Errorf("leaf %d (x509) Certificate did not parse: %v", i, err)
			}
			if leaf.PreCertificate != nil {
				t.Errorf("leaf %d (x509) has non-nil PreCertificate: %x", i, leaf.PreCertificate[:min(16, len(leaf.PreCertificate))])
			}
		case 1:
			precertSeen++
			// precert PreCertificate is the actual submitted cert DER — must parse.
			if _, err := x509.ParseCertificate(leaf.PreCertificate); err != nil {
				t.Errorf("leaf %d (precert) PreCertificate did not parse: %v", i, err)
			}
			// Certificate (= TBS) cannot be parsed by x509.ParseCertificate
			// (it lacks the outer SEQUENCE wrapping signature + algo),
			// so we only sanity-check it's non-empty and starts with ASN.1
			// SEQUENCE tag.
			if len(leaf.Certificate) < 2 || leaf.Certificate[0] != 0x30 {
				t.Errorf("leaf %d (precert) TBS does not start with ASN.1 SEQUENCE tag: %x", i, leaf.Certificate[:min(16, len(leaf.Certificate))])
			}
		}
	}

	t.Logf("real Sunlight tile parsed: %d leaves total (%d x509, %d precert); first leaf entry_type=%d timestamp=%d",
		len(leaves), x509Seen, precertSeen, leaves[0].EntryType, leaves[0].Timestamp)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
