# Static CT MerkleTreeLeaf golden fixtures

Two committed golden byte sequences for the `EncodeTileLeaf` encoder
(`tileleaf.go`). Locks down the RFC 6962 §3.4 MerkleTreeLeaf wire format
(as implemented in Sunlight's reference impl) against silent regression.

The function is named `EncodeTileLeaf` for project-local familiarity, but
the bytes it produces are the **MerkleTreeLeaf hash input**, not the
c2sp.org/static-ct-api §1.1.4 TileLeaf storage record. See the encoder
doc comment for the full deconstruction.

## Files

- `tileleaf_x509_golden.bin` — output of EncodeTileLeaf for the
  `canonicalX509Fixture()` triple (see `tileleaf_test.go`). Native
  Sunlight x509 leaf with leafIndex = 0x42.
- `tileleaf_precert_golden.bin` — output of EncodeTileLeaf for the
  `canonicalPrecertFixture()` triple. Native Sunlight precert leaf with
  leafIndex = 0x1234567890.

## Encoder signature

```go
func EncodeTileLeaf(leaf LeafData, leafIndex uint64, archival bool) []byte
```

Both golden fixtures use `archival=false` (native Sunlight entries) so
the CtExtensions block carries the c2sp.org/static-ct-api §1.1.5
`leaf_index` extension.

## Regeneration recipe

If an intentional spec change requires regenerating these fixtures
(unlikely outside a future schema bump), drop a throwaway helper at the
**repo root** — NOT under `/tmp` — so it can import the
`internal/ingest/ct/static` package (Go's internal-package visibility
rule blocks imports from outside the module tree).

```go
//go:build ignore

package main

import (
	"crypto/sha256"
	"os"

	"github.com/net4n6-dev/cipherflag/internal/ingest/ct/static"
)

func sha256Of(s string) [32]byte { return sha256.Sum256([]byte(s)) }

func main() {
	x509Leaf := static.LeafData{
		Timestamp:         0x0000019345678ABC,
		EntryType:         0, // x509_entry
		Certificate:       []byte("FAKE-CERT-LEAF-x509-DER-2026-05-27"),
		ChainFingerprints: [][32]byte{sha256Of("FAKE-ISSUER-INTERMEDIATE")},
	}
	_ = os.WriteFile("internal/ingest/ct/static/testdata/tileleaf_x509_golden.bin",
		static.EncodeTileLeaf(x509Leaf, 0x42, false), 0644)

	var ikh [32]byte
	for i := range ikh {
		ikh[i] = byte(0xA0 + i%16)
	}
	precert := static.LeafData{
		Timestamp:         0x0000018012345678,
		EntryType:         1, // precert_entry
		IssuerKeyHash:     ikh,
		Certificate:       []byte("FAKE-TBS-CERT-PRECERT-2026-05-27"), // PreCert.tbs_certificate
		PreCertificate:    []byte("FAKE-PRECERT-FULL-DER-2026-05-27"), // §1.1.3 pre_certificate
		ChainFingerprints: [][32]byte{sha256Of("FAKE-ISSUER-1"), sha256Of("FAKE-ISSUER-2")},
	}
	_ = os.WriteFile("internal/ingest/ct/static/testdata/tileleaf_precert_golden.bin",
		static.EncodeTileLeaf(precert, 0x1234567890, false), 0644)
}
```

Save as `regen_goldens_a6.go` at the repo root, then:

```bash
go run -tags ee ./regen_goldens_a6.go
rm regen_goldens_a6.go
```

**DO NOT regenerate to "fix" a failing test** without first auditing
whether the spec or encoder actually changed; the test failure may be a
real bug.

## Wire-format sanity check

The x509 golden should begin with `00 00 00 00 01 93 45 67 8A BC` —
version (0x00) || leaf_type (0x00) || 8-byte big-endian timestamp
0x0000019345678ABC. Use `xxd` to inspect:

```bash
xxd internal/ingest/ct/static/testdata/tileleaf_x509_golden.bin | head -1
```

The trailing 11 bytes are the CtExtensions block:
`00 08` (outer uint16 length = 8) || `00` (extension_type = leaf_index)
|| `00 05` (extension_data uint16 length = 5) || 5 bytes uint40
leaf_index. Neither golden contains SHA-256 fingerprints — the
certificate chain lives only in the §1.1.4 storage record, not in the
hash input.

---

## `real_sunlight_tile_trustasia_log2026a_000.bin`

A real Static CT data tile fetched once from a public Sunlight log,
committed as a ground-truth verification fixture for `ParseLeafTile`
(see `TestParseLeafTile_AgainstRealSunlightTile` in `tile_test.go`).

Without a real-log fixture, the parser could drift from the canonical
c2sp.org/static-ct-api §1.1.3 wire format silently — synthetic-only
tests can match any encoder the test author wrote (and indeed did,
prior to Fix Pass 2 — the parser read a fabricated wire format and
the test fixtures matched it).

### Provenance

- **URL:** `https://ct2026-a.trustasia.com/log2026a/tile/data/000`
- **Log operator:** TrustAsia
- **Log name:** `log2026a` (Sunlight-shaped Static CT log)
- **Tile index:** 0 (first data tile)
- **File size:** 377,152 bytes
- **Leaves contained:** 256 total (113 x509 + 143 precert)
- **First leaf:** precert_entry, timestamp = 1714463387874
  (2024-04-30 07:49:47 UTC)
- **Fetched:** 2026-05-27

The fixture is committed because regenerating against a live log
would (a) introduce flakiness, (b) fetch a different tile each
refresh as the log grows, (c) require network access in test runs.

### Refresh procedure

If a future spec revision invalidates this fixture, refresh by:

```bash
curl -sS -o internal/ingest/ct/static/testdata/real_sunlight_tile_trustasia_log2026a_000.bin \
  https://ct2026-a.trustasia.com/log2026a/tile/data/000
```

If TrustAsia's log2026a is no longer reachable, pick another active
Sunlight log from `https://www.gstatic.com/ct/log_list/v3/log_list.json`
that responds 200 OK to `<log_url>/checkpoint`. (Not every CT log in
the Google list is Sunlight-shaped — many are RFC 6962 only and do
not serve `/tile/data/<index>`.) Update the filename to reference the
new log, update the test's `os.ReadFile` path, and adjust the
provenance fields in this README.

### Test contract

`TestParseLeafTile_AgainstRealSunlightTile` asserts:
- All 256 leaves parse without error.
- Every `EntryType ∈ {0, 1}`.
- Every `Timestamp` lies within the last 5 years.
- For every x509 leaf, `Certificate` parses with
  `x509.ParseCertificate`.
- For every precert leaf, `PreCertificate` parses with
  `x509.ParseCertificate`.
- For every precert leaf, `Certificate` (the TBS) starts with the
  ASN.1 SEQUENCE tag (`0x30`) — `x509.ParseCertificate` can't directly
  consume a TBS, so this is the strongest sanity check available.
