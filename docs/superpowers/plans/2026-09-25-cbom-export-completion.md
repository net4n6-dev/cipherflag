# CBOM Export Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `GET /export/cbom/estate` and `GET /applications/{tag}/cbom`, make every BOM writer keep its JSF signature, make asset counts honest, and let syslog-over-TLS run without a client certificate.

**Architecture:** One shared serialiser package (`bomjson`) that every BOM writer calls, one shared assembly function (`buildBOMFromRows`) behind the scope, application and estate generators, and one handler helper (`writeBOM`) that also extends the response write deadline. The signed-output fix lands first, then a behaviour-preserving refactor guarded by the integration golden tests, then the new behaviour.

**Tech Stack:** Go 1.25.6, `github.com/CycloneDX/cyclonedx-go` v0.10.0, chi v5, zerolog, testify (`require`), Postgres for integration tests.

**Spec:** `docs/superpowers/specs/2026-09-25-cbom-export-completion-design.md` (read it first; this plan implements it). Deliberate refinements of the spec, to be folded back into it in Task 11: `bomjson` exposes `Encode` (returns bytes) instead of `Write(w, bom)`, because the handler helper must buffer the body before writing headers; and `buildBOMFromRows` carries a temporary `skipMapErrors` parameter (removed in Task 5) so the refactor task stays behaviour-preserving.

## Global Constraints

- Go 1.25.6; cyclonedx-go v0.10.0 (`cdx.SpecVersion1_6`).
- Every new `.go` file starts with the Apache-2.0 header used by the neighbouring files (copy the first 13 lines of `internal/export/cbom/generator.go`).
- Signed output must be `json.Marshal(bom)` plus the injected signature block (`bomjson.MarshalSigned`). Never emit a signed BOM with `cdx.NewBOMEncoder` or `encoding/json` directly: `cdx.JSFSignature` embeds `*JSFSigner` with `json:"-"`, so they emit `"signature":{}`.
- Commits: Erik approves every commit explicitly; the commit hook rejects a `Co-Authored-By` trailer, so never add one; stage only the files named in the task (never `git add -A`; `docs/CLAUDE.md` and the Layer 0 spec/plan files are untracked on purpose); conventional-commit subjects.
- Never push or tag without an explicit go. Never `rm`/delete without asking Erik first (`docs/CLAUDE.md`).
- At most 5 files touched per task (`docs/CLAUDE.md` phased-execution rule).
- After editing Go files run `gofmt -l <files>` and fix any output (import blocks must be sorted).
- Unit tests: `go test <pkgs> -count=1`. Integration tests (the golden tests live here and are the refactor's safety net) need a database: `CIPHERFLAG_TEST_DB="postgres://cipherflag:changeme@localhost:5434/cipherflag_test?sslmode=disable" go test -tags integration ./internal/export/cbom/... -count=1`. A plain `go test ./...` does **not** run them.

## Review Focus

Failure modes the spec implies but a straightforward implementation would miss; each has a test in the named task.

1. Estate or application export over an empty inventory must return a valid response, not a crash or an empty-but-valid-looking BOM: empty estate returns a valid BOM with `asset_count` `0` (Task 6); an application tag with no scored assets returns `404` (Task 8).
2. An application tag is caller-controlled and lands in a `Content-Disposition` header: quotes, CR/LF and `../` must not inject header syntax or path components (Task 8).
3. A signed BOM containing JSON- and HTML-special characters (`<`, `&`, `"`) must still verify after serialisation (Task 3, via the shared `cbomtest.SignedBOM` fixture).
4. Health reports whose asset was deleted must lower `asset_count` and be disclosed; a mapping *error* must fail the export with a `500`, never yield a partial `200` (Tasks 5 and 7).
5. Syslog TLS with only one of `cert_file`/`key_file` must be a config error, and `tls_insecure` must be the only way to skip verification (Task 10).

---

## File Structure

| File | Responsibility | Tasks |
|---|---|---|
| `internal/export/cbom/bomjson/bomjson.go` (new) | JSON serialisation of BOMs that keeps the JSF signature | 1 |
| `internal/export/cbom/signing.go` | keeps `SignBOM`; `MarshalSignedBOM` becomes a wrapper | 1 |
| `internal/export/cbom/sink.go` | `encodeBOM` delegates to `bomjson` | 1 |
| `internal/export/cbom/sinks/s3/s3.go` | S3 sink encodes BOMs through `bomjson` | 2 |
| `internal/export/cbom/cbomtest/cbomtest.go` (new) | test support: signed-BOM fixture, signing config, signature verifier | 3 |
| `internal/api/handler/cbom_write.go` (new) | `writeBOM`, `extendWriteDeadline` | 3 |
| `internal/api/handler/cbom.go` | scope download uses helpers; estate and application handlers | 3, 7, 8 |
| `internal/api/handler/repo_cbom.go` | repo download uses helpers | 3 |
| `internal/export/cbom/generator.go` | `buildBOMFromRows`, `bomParams`, `setAssetCounts`; `Generate` is a wrapper | 4, 5 |
| `internal/export/cbom/application.go` | `GenerateForApplication` is a wrapper; sentinel error | 4, 5, 8 |
| `internal/export/cbom/estate.go` (new) | `GenerateWholeEstate` | 6 |
| `internal/api/server.go` | routes for estate and application | 7, 8 |
| `internal/config/config_sinks.go`, `internal/export/cbom/sinks/syslog/syslog.go` | optional client cert, `tls_insecure` | 10 |
| `CHANGELOG.md`, `cmd/cipherflag/main.go`, spec | release notes and version | 11 |

---

### Task 0: Establish the integration-test baseline

No code changes; no commit. The golden tests guard Task 4's refactor, and they have not been run in this repository's recent history because `go test ./...` skips them.

- [ ] **Step 1: Start the test database** (ask Erik before creating the container; it pulls an image and uses port 5434)

```bash
docker run -d --name cipherflag-test-db \
  -e POSTGRES_DB=cipherflag -e POSTGRES_USER=cipherflag -e POSTGRES_PASSWORD=changeme \
  -p 5434:5432 postgres:15-alpine
docker exec cipherflag-test-db psql -U cipherflag -c "CREATE DATABASE cipherflag_test;"
```

If the container already exists: `docker start cipherflag-test-db`. Wait a few seconds for Postgres to accept connections.

- [ ] **Step 2: Run the CBOM integration tests on the unmodified tree**

```bash
CIPHERFLAG_TEST_DB="postgres://cipherflag:changeme@localhost:5434/cipherflag_test?sslmode=disable" \
  go test -tags integration ./internal/export/cbom/... -count=1 2>&1 | tail -20
```

Expected: `ok` for `internal/export/cbom` (and sinks). Record the result.

- [ ] **Step 3: Decide**

If anything FAILS on the unmodified tree, stop and report to Erik: those failures pre-date this work and Task 4 cannot be validated until they are understood. If green, proceed.

---

### Task 1: `bomjson` package

**Files:**
- Create: `internal/export/cbom/bomjson/bomjson.go`
- Create: `internal/export/cbom/bomjson/bomjson_test.go`
- Modify: `internal/export/cbom/signing.go` (remove the moved types and body; keep `SignBOM`, `canonicalizeBOM`)
- Modify: `internal/export/cbom/sink.go:43-62` (`encodeBOM`)
- Modify: `cmd/cipherflag/cbom_sign.go:52` (stale comment only)

**Interfaces:**
- Consumes: `cdx.BOM` (cyclonedx-go).
- Produces: `bomjson.Encode(bom *cdx.BOM) ([]byte, error)` (compact JSON; signed BOMs keep their signature; unsigned BOMs use the stock encoder, so output ends with a newline exactly as the handlers emitted before) and `bomjson.MarshalSigned(bom *cdx.BOM) ([]byte, error)` (the moved `MarshalSignedBOM` body). `cbom.MarshalSignedBOM` remains as a wrapper.

- [ ] **Step 1: Write the failing test** — create `internal/export/cbom/bomjson/bomjson_test.go` (Apache header, then):

```go
package bomjson

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func signedBOM() *cdx.BOM {
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_6
	bom.Signature = &cdx.JSFSignature{JSFSigner: &cdx.JSFSigner{
		Algorithm: "Ed25519",
		Value:     "c2ln",
		PublicKey: cdx.JSFPublicKey{KTY: "OKP", CRV: "Ed25519", X: "a2V5"},
	}}
	return bom
}

func TestEncode_SignedBOMKeepsSignatureBlock(t *testing.T) {
	raw, err := Encode(signedBOM())
	require.NoError(t, err)

	var doc struct {
		Signature map[string]any `json:"signature"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	require.Equal(t, "Ed25519", doc.Signature["algorithm"])
	require.Equal(t, "c2ln", doc.Signature["value"])
	pub, ok := doc.Signature["publicKey"].(map[string]any)
	require.True(t, ok, "publicKey must be an object")
	require.Equal(t, "OKP", pub["kty"])
	require.Equal(t, "Ed25519", pub["crv"])
	require.Equal(t, "a2V5", pub["x"])
}

func TestEncode_UnsignedBOMMatchesStockEncoder(t *testing.T) {
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_6

	raw, err := Encode(bom)
	require.NoError(t, err)
	require.NotContains(t, string(raw), `"signature"`)

	var want bytes.Buffer
	enc := cdx.NewBOMEncoder(&want, cdx.BOMFileFormatJSON)
	enc.SetPretty(false)
	require.NoError(t, enc.Encode(bom))
	require.Equal(t, want.String(), string(raw), "unsigned output must not change")
	require.True(t, strings.HasSuffix(string(raw), "\n"))
}

func TestMarshalSigned_WithoutSignatureIsPlainJSON(t *testing.T) {
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_6

	got, err := MarshalSigned(bom)
	require.NoError(t, err)
	want, err := json.Marshal(bom)
	require.NoError(t, err)
	require.Equal(t, string(want), string(got))
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/export/cbom/bomjson/ -count=1`
Expected: build failure, `undefined: Encode` / `undefined: MarshalSigned`.

- [ ] **Step 3: Write the implementation** — create `internal/export/cbom/bomjson/bomjson.go` (Apache header, then). The `MarshalSigned` body is the existing `MarshalSignedBOM` from `signing.go` with unchanged error strings:

```go
// Package bomjson serialises CycloneDX BOMs to JSON while keeping the JSF
// signature block that the stock cyclonedx-go encoders drop.
//
// cdx.JSFSignature embeds *JSFSigner with a json:"-" tag (cyclonedx-go
// v0.10.0, cyclonedx.go:852-853), so cdx.NewBOMEncoder and encoding/json emit
// "signature":{} for a signed BOM. Every writer of BOM JSON must go through
// Encode. The package depends only on cyclonedx-go so that leaf packages
// (the S3 sink) can import it without an import cycle.
package bomjson

import (
	"bytes"
	"encoding/json"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// jsfPublicKeyJSON mirrors cdx.JSFPublicKey with proper json tags for OKP key
// material.
type jsfPublicKeyJSON struct {
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	X   string `json:"x"`
}

// jsfSignatureJSON is the serialisable form of a JSF single-signer block. It
// becomes the value of the "signature" field in the BOM JSON object.
type jsfSignatureJSON struct {
	Algorithm string           `json:"algorithm"`
	Value     string           `json:"value"`
	PublicKey jsfPublicKeyJSON `json:"publicKey"`
}

// Encode returns the compact JSON encoding of bom. A BOM carrying a JSF
// signer is encoded with MarshalSigned so the signature survives; any other BOM
// uses the stock encoder, so unsigned output is byte-for-byte what the
// handlers and sinks emitted before this package existed.
func Encode(bom *cdx.BOM) ([]byte, error) {
	if bom.Signature != nil && bom.Signature.JSFSigner != nil {
		return MarshalSigned(bom)
	}
	var buf bytes.Buffer
	enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	enc.SetPretty(false)
	if err := enc.Encode(bom); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MarshalSigned serialises bom to JSON, preserving the JSF signature block even
// though cdx.JSFSignature embeds *JSFSigner with json:"-".
//
// When bom.Signature is nil it returns json.Marshal(bom) unchanged. Otherwise
// it marshals the body (which drops the signature fields), injects a
// hand-built "signature" key, and re-marshals. The result is compact; callers
// that need indentation should json.Indent it.
func MarshalSigned(bom *cdx.BOM) ([]byte, error) {
	body, err := json.Marshal(bom)
	if err != nil {
		return nil, fmt.Errorf("cbom: MarshalSignedBOM: marshal body: %w", err)
	}
	if bom.Signature == nil || bom.Signature.JSFSigner == nil {
		return body, nil
	}
	sigJSON := jsfSignatureJSON{
		Algorithm: bom.Signature.Algorithm,
		Value:     bom.Signature.Value,
		PublicKey: jsfPublicKeyJSON{
			KTY: bom.Signature.PublicKey.KTY,
			CRV: bom.Signature.PublicKey.CRV,
			X:   bom.Signature.PublicKey.X,
		},
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, fmt.Errorf("cbom: MarshalSignedBOM: unmarshal fields: %w", err)
	}
	sigBytes, err := json.Marshal(sigJSON)
	if err != nil {
		return nil, fmt.Errorf("cbom: MarshalSignedBOM: marshal signature: %w", err)
	}
	fields["signature"] = json.RawMessage(sigBytes)
	out, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("cbom: MarshalSignedBOM: re-marshal: %w", err)
	}
	return out, nil
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/export/cbom/bomjson/ -count=1`
Expected: `ok`.

- [ ] **Step 5: Point `signing.go` at it** — in `internal/export/cbom/signing.go`: delete the `jsfPublicKeyJSON` type, the `jsfSignatureJSON` type and the whole `MarshalSignedBOM` function body (lines 25-90), and put this in their place:

```go
// MarshalSignedBOM serialises bom to JSON, preserving the JSF signature block.
// It is a thin wrapper kept for existing callers; new code should call
// bomjson.Encode.
func MarshalSignedBOM(bom *cdx.BOM) ([]byte, error) {
	return bomjson.MarshalSigned(bom)
}
```

Add `"github.com/net4n6-dev/cipherflag/internal/export/cbom/bomjson"` to the imports. `base64`, `json`, `fmt` and `cdx` are still used by `SignBOM` / `canonicalizeBOM`; if the compiler reports an unused import, remove it.

- [ ] **Step 6: Make `encodeBOM` delegate** — in `internal/export/cbom/sink.go` replace the whole `encodeBOM` function (and its doc comment) with:

```go
// encodeBOM encodes a *cdx.BOM to compact JSON bytes, keeping the JSF
// signature block when present. See the bomjson package for why the stock
// encoder cannot be used for signed BOMs.
func encodeBOM(bom *cdx.BOM) ([]byte, error) {
	return bomjson.Encode(bom)
}
```

Add the `bomjson` import; remove any import the compiler now reports unused (`bytes` is still used by `HTTPSink`).

- [ ] **Step 7: Fix the stale comment** — `cmd/cipherflag/cbom_sign.go:52` says the production path uses `cbom.jsfSignatureJSON`; change that line to reference `bomjson.MarshalSigned` instead.

- [ ] **Step 8: Verify nothing regressed**

```bash
gofmt -l internal/export/cbom cmd/cipherflag
go build ./... && go vet ./internal/export/cbom/... ./cmd/...
go test ./internal/export/cbom/... ./cmd/... -count=1
```

Expected: no gofmt output for the touched files, build and vet clean, all `ok`.

- [ ] **Step 9: Commit** (after Erik's go)

```bash
git add internal/export/cbom/bomjson/bomjson.go internal/export/cbom/bomjson/bomjson_test.go \
  internal/export/cbom/signing.go internal/export/cbom/sink.go cmd/cipherflag/cbom_sign.go
git commit -m "refactor(cbom): extract bomjson for signature-preserving BOM JSON"
```

---

### Task 2: S3 sink keeps the signature

**Files:**
- Modify: `internal/export/cbom/sinks/s3/s3.go` (`encode`, around lines 111-125)
- Create: `internal/export/cbom/sinks/s3/s3_signed_test.go`

**Interfaces:**
- Consumes: `bomjson.Encode` (Task 1).
- Produces: S3 objects for signed BOMs contain the full signature block.

- [ ] **Step 1: Write the failing test** — create `internal/export/cbom/sinks/s3/s3_signed_test.go` (Apache header, then; `stubPutAPI` and `newWithClient` already exist in this package's tests/code):

```go
package s3

import (
	"context"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom/sinks/types"
)

// A signed BOM must reach the bucket with its signature. The stock cyclonedx
// encoder emits "signature":{} because cdx.JSFSignature embeds *JSFSigner with
// json:"-".
func TestS3Sink_SignedCBOMKeepsSignature(t *testing.T) {
	stub := &stubPutAPI{}
	sink := newWithClient(
		config.S3SinkConfig{Bucket: "cbom-test", Region: "us-east-1", Prefix: "cf/{scope}/"},
		config.SinkConfig{},
		"prod",
		stub,
	)
	bom := &cdx.BOM{
		SpecVersion:  cdx.SpecVersion1_6,
		SerialNumber: "urn:uuid:x",
		Signature: &cdx.JSFSignature{JSFSigner: &cdx.JSFSigner{
			Algorithm: "Ed25519",
			Value:     "c2ln",
			PublicKey: cdx.JSFPublicKey{KTY: "OKP", CRV: "Ed25519", X: "a2V5"},
		}},
	}
	if err := sink.Send(context.Background(), &types.SinkPayload{BOM: bom}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	body := string(stub.bodyBytes)
	if strings.Contains(body, `"signature":{}`) {
		t.Fatalf("uploaded object carries an empty signature block: %s", body)
	}
	for _, want := range []string{`"algorithm":"Ed25519"`, `"value":"c2ln"`, `"x":"a2V5"`} {
		if !strings.Contains(body, want) {
			t.Errorf("uploaded object missing %s: %s", want, body)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/export/cbom/sinks/s3/ -run TestS3Sink_SignedCBOMKeepsSignature -count=1`
Expected: FAIL, `uploaded object carries an empty signature block` (this is the first runtime reproduction of the signed-output bug in CE; record the output).

- [ ] **Step 3: Fix the encoder** — in `s3.go`, in `(*Sink).encode`, replace the BOM branch:

```go
	if payload.BOM != nil {
		var buf bytes.Buffer
		enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
		enc.SetPretty(false)
		if err := enc.Encode(payload.BOM); err != nil {
			return nil, "", err
		}
		return buf.Bytes(), "application/vnd.cyclonedx+json; version=1.6", nil
	}
```

with:

```go
	if payload.BOM != nil {
		b, err := bomjson.Encode(payload.BOM)
		if err != nil {
			return nil, "", err
		}
		return b, "application/vnd.cyclonedx+json; version=1.6", nil
	}
```

Add the import `"github.com/net4n6-dev/cipherflag/internal/export/cbom/bomjson"`. `bytes` is still used by the events branch; remove the `cdx` import only if the compiler reports it unused.

- [ ] **Step 4: Run to verify it passes, plus the whole package**

```bash
gofmt -l internal/export/cbom/sinks/s3
go test ./internal/export/cbom/sinks/s3/ -count=1
go build ./...
```

Expected: `ok`, build clean.

- [ ] **Step 5: Commit** (after Erik's go)

```bash
git add internal/export/cbom/sinks/s3/s3.go internal/export/cbom/sinks/s3/s3_signed_test.go
git commit -m "fix(cbom): S3 sink no longer drops the JSF signature"
```

---

### Task 3: Shared writer for the scope and repo downloads

**Files:**
- Create: `internal/export/cbom/cbomtest/cbomtest.go`
- Create: `internal/api/handler/cbom_write.go`
- Create: `internal/api/handler/cbom_write_test.go`
- Modify: `internal/api/handler/cbom.go` (imports; `Download`)
- Modify: `internal/api/handler/repo_cbom.go` (`Download`)

**Interfaces:**
- Consumes: `bomjson.Encode` (Task 1); `cbom.NewFileSigner`, `cbom.SignBOM`, `cbom.Canonicalize`, `config.CBOMSigningConfig`; the existing `fakeCBOMGen`/`fakeRepoCBOMStore` test fakes and `writeError`, `cbomContentType`.
- Produces: `cbomtest.SigningConfig(t testing.TB) config.CBOMSigningConfig`, `cbomtest.SignedBOM(t testing.TB) *cdx.BOM`, `cbomtest.AssertValidSignature(t testing.TB, raw []byte)`; handler helpers `extendWriteDeadline(w http.ResponseWriter)` and `writeBOM(w http.ResponseWriter, bom *cdx.BOM, filename string, pretty bool)`. Later tasks call these.

- [ ] **Step 1: Create the test-support package** — `internal/export/cbom/cbomtest/cbomtest.go` (Apache header, then). It lives in the production tree (like `internal/testdb`) so several packages' tests can share it; only tests import it.

```go
// Package cbomtest provides shared test support for code that emits signed
// CBOMs. Import it from tests only.
package cbomtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom"
)

// SigningConfig writes a fresh Ed25519 private key under t.TempDir() and
// returns a signing config that uses it.
func SigningConfig(t testing.TB) config.CBOMSigningConfig {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "signing.key")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return config.CBOMSigningConfig{Enabled: true, Signer: "file", Path: path}
}

// SignedBOM returns a small BOM signed with a fresh key. The component name
// contains JSON- and HTML-special characters so tests also prove the signature
// survives escaping.
func SignedBOM(t testing.TB) *cdx.BOM {
	t.Helper()
	signer, err := cbom.NewFileSigner(SigningConfig(t).Path)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_6
	bom.Components = &[]cdx.Component{{
		Type:    cdx.ComponentTypeLibrary,
		BOMRef:  "lib:1",
		Name:    `svc<&>"quoted"`,
		Version: "1.0",
	}}
	if err := cbom.SignBOM(bom, signer); err != nil {
		t.Fatalf("sign BOM: %v", err)
	}
	return bom
}

// AssertValidSignature fails the test unless raw is a JSON document with a
// complete JSF Ed25519 signature that verifies over the document's RFC 8785
// canonical form: the same check `cipherflag verify-cbom` performs. A bare
// "signature":{} counts as a failure.
func AssertValidSignature(t testing.TB, raw []byte) {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	sigRaw, ok := fields["signature"]
	if !ok {
		t.Fatalf("output has no signature key")
	}
	var sig struct {
		Algorithm string `json:"algorithm"`
		Value     string `json:"value"`
		PublicKey struct {
			X string `json:"x"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(sigRaw, &sig); err != nil {
		t.Fatalf("signature block malformed: %v", err)
	}
	if sig.Algorithm != "Ed25519" || sig.Value == "" || sig.PublicKey.X == "" {
		t.Fatalf("incomplete signature block: %s", sigRaw)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil {
		t.Fatalf("signature value not base64: %v", err)
	}
	pub, err := base64.RawURLEncoding.DecodeString(sig.PublicKey.X)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("embedded public key invalid (len %d): %v", len(pub), err)
	}
	delete(fields, "signature")
	stripped, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	canonical, err := cbom.Canonicalize(stripped)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), canonical, sigBytes) {
		t.Fatalf("signature does not verify over the canonical document")
	}
}
```

- [ ] **Step 2: Write the failing tests** — create `internal/api/handler/cbom_write_test.go` (Apache header, then). Only the two tests that compile against the *current* handlers go in first:

```go
package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom/cbomtest"
)

func TestCBOMHandler_Download_SignedBOMKeepsSignature(t *testing.T) {
	h := newTestCBOMHandler(&fakeCBOMGen{bom: cbomtest.SignedBOM(t)}, &config.CBOMConfig{})

	rr := httptest.NewRecorder()
	h.Download(rr, httptest.NewRequest(http.MethodGet, "/api/v1/export/cbom?asset_type=certificate", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rr.Code, rr.Body.String())
	}
	cbomtest.AssertValidSignature(t, rr.Body.Bytes())
}

func TestRepoCBOMHandler_SignedDownloadKeepsSignature(t *testing.T) {
	h := NewRepoCBOMHandler(&fakeRepoCBOMStore{}, cbomtest.SigningConfig(t))

	rr := httptest.NewRecorder()
	h.Download(rr, httptest.NewRequest(http.MethodGet,
		"/api/v1/repo/exports/cbom?repo_id=11111111-1111-1111-1111-111111111111", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rr.Code, rr.Body.String())
	}
	cbomtest.AssertValidSignature(t, rr.Body.Bytes())
	if !strings.Contains(rr.Body.String(), "\n  ") {
		t.Errorf("repo CBOM output should stay indented")
	}
	if !strings.HasSuffix(rr.Body.String(), "\n") {
		t.Errorf("repo CBOM output should end with a newline, as it did before")
	}
}
```

- [ ] **Step 3: Run to verify they fail**

Run: `go test ./internal/api/handler/ -run 'SignedBOMKeepsSignature|SignedDownloadKeepsSignature' -count=1`
Expected: both FAIL with `incomplete signature block: {}` (runtime confirmation of the bug on the download and repo writers).

- [ ] **Step 4: Write the helpers** — create `internal/api/handler/cbom_write.go` (Apache header, then):

```go
package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom/bomjson"
	"github.com/rs/zerolog/log"
)

// extendWriteDeadline clears the response write deadline for the current
// request. The server applies a 30s WriteTimeout to every route, but a CBOM
// export builds its whole document before writing, so a large estate can
// outlive it. Call it first in every export handler, before generation starts.
// Response writers without deadline support (httptest recorders) are ignored.
func extendWriteDeadline(w http.ResponseWriter) {
	err := http.NewResponseController(w).SetWriteDeadline(time.Time{})
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		log.Warn().Err(err).Msg("cbom: could not extend write deadline")
	}
}

// writeBOM serialises bom with bomjson (which keeps a JSF signature) and
// writes it as a CycloneDX response. The body is built before any header is
// sent, so a serialisation failure becomes a 500 instead of a truncated 200.
// filename, when non-empty, adds a Content-Disposition attachment header;
// pretty indents the JSON.
func writeBOM(w http.ResponseWriter, bom *cdx.BOM, filename string, pretty bool) {
	body, err := bomjson.Encode(bom)
	if err == nil && pretty {
		var buf bytes.Buffer
		if err = json.Indent(&buf, body, "", "  "); err == nil {
			body = buf.Bytes()
			// The old repo handler used json.Encoder, so its output always
			// ended with a newline. Signed output (MarshalSigned) has none.
			if !bytes.HasSuffix(body, []byte("\n")) {
				body = append(body, '\n')
			}
		}
	}
	if err != nil {
		log.Error().Err(err).Msg("cbom: serialise BOM failed")
		writeError(w, http.StatusInternalServerError, "CBOM serialisation failed")
		return
	}
	w.Header().Set("Content-Type", cbomContentType)
	if filename != "" {
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
```

- [ ] **Step 5: Route the scope download through it** — in `internal/api/handler/cbom.go`, add `extendWriteDeadline(w)` as the first statement of `Download`, and replace its tail (from `bom, err := h.gen.Generate(...)` to the closing brace):

```go
	bom, err := h.gen.Generate(r.Context(), h.store, scope)
	if err != nil {
		log.Error().Err(err).Msg("cbom: generate failed")
		writeError(w, http.StatusInternalServerError, "CBOM generation failed")
		return
	}
	writeBOM(w, bom, "", false)
}
```

Add `"github.com/rs/zerolog/log"` to the imports. `cdx` is still used by the `cbomGenerator` interface.

- [ ] **Step 6: Route the repo download through it** — in `internal/api/handler/repo_cbom.go`, add `extendWriteDeadline(w)` as the first statement of `Download`, and replace everything after the `GenerateForRepo` error check:

```go
	writeBOM(w, bom, repoID+".cdx.json", true)
}
```

Remove the now-unused `"encoding/json"` import.

- [ ] **Step 7: Run to verify the first two pass, then add the guard tests** — run `go test ./internal/api/handler/ -run 'SignedBOMKeepsSignature|SignedDownloadKeepsSignature' -count=1` (expected `ok`). Then append these tests (they need the helpers, so they could not be written earlier) to `cbom_write_test.go`, adding `"time"` and `cdx "github.com/CycloneDX/cyclonedx-go"` to its imports:

```go
func TestExtendWriteDeadline_IgnoresRecorder(t *testing.T) {
	extendWriteDeadline(httptest.NewRecorder()) // must not panic or log an error
}

// The server-wide WriteTimeout would cut off a slow export. A real server with
// a short timeout shows the helper lets a slow handler finish, and that the
// control case (no extension) really is cut off.
func TestExtendWriteDeadline_LetsSlowHandlerFinish(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("extend") == "1" {
			extendWriteDeadline(w)
		}
		time.Sleep(400 * time.Millisecond)
		_, _ = w.Write([]byte("done"))
	}))
	srv.Config.WriteTimeout = 150 * time.Millisecond
	srv.Start()
	defer srv.Close()

	if resp, err := http.Get(srv.URL + "/?extend=0"); err == nil {
		resp.Body.Close()
		t.Fatalf("control request should have been cut off by WriteTimeout")
	}

	resp, err := http.Get(srv.URL + "/?extend=1")
	if err != nil {
		t.Fatalf("extended request failed: %v", err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 4)
	if n, _ := resp.Body.Read(buf); string(buf[:n]) != "done" {
		t.Errorf("body = %q, want done", buf[:n])
	}
}

func TestWriteBOM_SerialisationFailureIs500(t *testing.T) {
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_1 // the JSON encoder rejects spec versions below 1.2

	rr := httptest.NewRecorder()
	writeBOM(rr, bom, "x.cdx.json", false)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body = %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Content-Disposition") != "" {
		t.Errorf("no attachment header should be sent for a failed serialisation")
	}
}
```

- [ ] **Step 8: Verify**

```bash
gofmt -l internal/api/handler internal/export/cbom/cbomtest
go build ./... && go vet ./internal/api/... ./internal/export/cbom/cbomtest/
go test ./internal/api/... ./internal/export/cbom/... -count=1
```

Expected: all `ok`; the existing `repo_cbom_test.go` and `cbom_test.go` tests still pass (Content-Disposition, Content-Type and JSON-shape assertions unchanged).

- [ ] **Step 9: Commit** (after Erik's go)

```bash
git add internal/export/cbom/cbomtest/cbomtest.go internal/api/handler/cbom_write.go \
  internal/api/handler/cbom_write_test.go internal/api/handler/cbom.go internal/api/handler/repo_cbom.go
git commit -m "fix(cbom): download and repo-CBOM handlers no longer drop the JSF signature"
```

---

### Task 4: Extract `buildBOMFromRows` (behaviour-preserving)

**Files:**
- Modify: `internal/export/cbom/generator.go` (`Generate`, lines 41-~215)
- Modify: `internal/export/cbom/application.go` (`GenerateForApplication`, lines 36-175)

**Interfaces:**
- Consumes: existing `mapRow`, `resolveHostIDsForScope`, `issuanceLookupForStore`, `computeDependencies`, `annotateUnresolvedAndInferred`, `buildBOMRefSet`, `logAlgorithmDrift`, `logUnresolvedDeps`, `SignBOM`, `reduceExecEnv`, `certificationLevelForAlgo`.
- Produces: `type bomParams struct { root *cdx.Component; label string; depsInBOMOnly bool; skipMapErrors bool }` and `func (g *Generator) buildBOMFromRows(ctx context.Context, st store.CryptoStore, rows []store.ScopeAssetRow, p bomParams) (*cdx.BOM, error)`. Tasks 5, 6 and 8 build on these exact names.

This task adds no behaviour and no new test: the existing unit tests and the integration goldens are the proof. `skipMapErrors` exists only so `GenerateForApplication` keeps its current skip-on-error behaviour until Task 5.

- [ ] **Step 1: Re-confirm the baseline** — run the Task 0 integration command again on the untouched tree (expected `ok`), plus `go test ./internal/export/cbom/... -count=1`.

- [ ] **Step 2: Replace `Generate` in `generator.go`** — replace the function from its doc comment (`// Generate produces a CycloneDX 1.6 BOM ...`) through its closing brace (just before `// mapRow loads the full asset record`) with the code below. It is the current body, with steps 3-6 moved into `buildBOMFromRows` unchanged except where noted. Keep every existing comment that explains *why* (dedup order, sort stability, monomorphic-only certification policy) when you move the blocks; the code is:

```go
// Generate produces a CycloneDX 1.6 BOM for the given scope. (The target format
// is 1.7, but cyclonedx-go v0.10.0 caps at 1.6; upgrade the assignment in
// buildBOMFromRows when the library adds SpecVersion1_7.)
func (g *Generator) Generate(ctx context.Context, st store.CryptoStore, scope *Scope) (*cdx.BOM, error) {
	// 1. Resolve scope host IDs (patterns → UUIDs).
	hostIDs, err := resolveHostIDsForScope(ctx, st, scope)
	if err != nil {
		return nil, fmt.Errorf("cbom: resolve hosts for scope %q: %w", scope.Name, err)
	}

	// 2. Fetch matching asset health rows.
	rows, err := st.ListScopeAssets(ctx, store.ScopeAssetQuery{
		HostIDs:      hostIDs,
		AssetTypes:   scope.AssetTypes,
		MinRiskScore: scope.MinRiskScore,
	})
	if err != nil {
		return nil, fmt.Errorf("cbom: list scope assets for %q: %w", scope.Name, err)
	}

	root := &cdx.Component{
		Type:   cdx.ComponentTypeApplication,
		BOMRef: "scope:" + scope.Name,
		Name:   scope.Name,
		Properties: &[]cdx.Property{
			{Name: "cipherflag:scope.host_count", Value: strconv.Itoa(len(hostIDs))},
			{Name: "cipherflag:scope.asset_count", Value: strconv.Itoa(len(rows))},
		},
	}
	return g.buildBOMFromRows(ctx, st, rows, bomParams{root: root, label: "scope:" + scope.Name})
}

// bomParams configures buildBOMFromRows for one export flavour.
type bomParams struct {
	// root is the BOM's metadata.component. The caller sets its identity and
	// its cipherflag:*.asset_count property.
	root *cdx.Component
	// label tags the drift and unresolved-dependency log lines ("scope:prod").
	label string
	// depsInBOMOnly restricts dependency edges to refs whose component is in
	// this BOM (application exports). When false every ref counts as in scope
	// (scope and estate exports).
	depsInBOMOnly bool
	// skipMapErrors drops a row whose asset cannot be loaded instead of failing
	// the export. Temporary: removed in the honest-counts task.
	skipMapErrors bool
}

// buildBOMFromRows maps asset rows to a CycloneDX 1.6 BOM: components, enriched
// algorithm components, dependency graph, and (when a signer is configured) the
// JSF signature. Shared by Generate, GenerateForApplication and
// GenerateWholeEstate.
func (g *Generator) buildBOMFromRows(ctx context.Context, st store.CryptoStore, rows []store.ScopeAssetRow, p bomParams) (*cdx.BOM, error) {
	// 3. Map each row to a CycloneDX component; collect referenced algo BOM refs.
	var components []cdx.Component
	// enrichedAlgos deduplicates algorithm components by BOMRef, preserving
	// the first (enriched) version seen. Cert-sourced components carry
	// padding; later duplicates (e.g. from SSH keys using the same algo)
	// are dropped in favour of the already-stored enriched one.
	enrichedAlgos := make(map[string]cdx.Component)
	// algoSources tracks every asset_provenance.source seen for each algo BOMRef,
	// used to derive CryptoExecutionEnvironment via reduceExecEnv.
	algoSources := make(map[string][]string)
	// libEntries collects (LibraryName, LibraryVersion) from every crypto_library
	// row in scope; used to build AlgorithmObservations in the post-enrichment pass.
	type libEntry struct{ name, version string }
	var libEntries []libEntry

	for _, row := range rows {
		comp, algoComps, err := g.mapRow(ctx, st, row)
		if err != nil {
			if p.skipMapErrors {
				continue
			}
			return nil, fmt.Errorf("cbom: map %s %s: %w", row.AssetType, row.AssetID, err)
		}
		if comp != nil {
			components = append(components, *comp)
		}
		for _, ac := range algoComps {
			if _, seen := enrichedAlgos[ac.BOMRef]; !seen {
				enrichedAlgos[ac.BOMRef] = ac
			}
			algoSources[ac.BOMRef] = append(algoSources[ac.BOMRef], row.Sources...)
		}
		if row.LibraryName != "" {
			libEntries = append(libEntries, libEntry{row.LibraryName, row.LibraryVersion})
		}
	}

	// 4. Post-enrichment: executionEnvironment and certificationLevel per algo
	//    (see the comments in the current Generate; move them here verbatim).
	for bomRef, ac := range enrichedAlgos {
		canonical := bomRef
		if len(bomRef) > 5 && bomRef[:5] == "algo:" {
			canonical = bomRef[5:]
		}
		execEnv := reduceExecEnv(algoSources[bomRef])
		if ac.CryptoProperties == nil {
			ac.CryptoProperties = &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeAlgorithm}
		}
		if ac.CryptoProperties.AlgorithmProperties == nil {
			ac.CryptoProperties.AlgorithmProperties = &cdx.CryptoAlgorithmProperties{}
		}
		ac.CryptoProperties.AlgorithmProperties.ExecutionEnvironment = execEnv

		var observations []AlgorithmObservation
		for _, lib := range libEntries {
			observations = append(observations, AlgorithmObservation{
				Algorithm: canonical,
				Library:   lib.name,
				FIPSLevel: g.libraryFIPSLevel(lib.name, lib.version),
			})
		}
		certLevel := certificationLevelForAlgo(canonical, observations)
		if certLevel != cdx.CryptoCertificationLevelNone {
			ac.CryptoProperties.AlgorithmProperties.CertificationLevel = &[]cdx.CryptoCertificationLevel{certLevel}
		}
		enrichedAlgos[bomRef] = ac
	}

	// 5. Emit one algorithm component per unique canonical name, sorted by
	//    BOMRef so the signed bytes are reproducible (see the existing comment
	//    about map iteration and JCS array order; move it here verbatim).
	algoRefs := make([]string, 0, len(enrichedAlgos))
	for ref := range enrichedAlgos {
		algoRefs = append(algoRefs, ref)
	}
	sort.Strings(algoRefs)
	for _, ref := range algoRefs {
		components = append(components, enrichedAlgos[ref])
	}

	// 6. Assemble BOM.
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_6 // cyclonedx-go v0.10.0 caps at 1.6; upgrade when library adds 1.7
	bom.SerialNumber = "urn:uuid:" + uuid.New().String()
	bom.Metadata = &cdx.Metadata{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{{
				Type:    cdx.ComponentTypeApplication,
				Name:    "cipherflag",
				Version: cbomVersion,
			}},
		},
		Component: p.root,
	}

	// 6b. Compute the dependency graph from the assembled components.
	lookup := issuanceLookupForStore(ctx, st)
	inBom := buildBOMRefSet(components)
	inScope := func(string) bool { return true }
	if p.depsInBOMOnly {
		inScope = func(ref string) bool { return inBom[ref] }
	}
	deps := computeDependencies(components, lookup, inScope)

	// 6c. Annotate components with unresolved/inferred dep signals.
	components = annotateUnresolvedAndInferred(components, deps, inBom, lookup)

	if len(components) > 0 {
		bom.Components = &components
	}
	if len(deps) > 0 {
		bom.Dependencies = &deps
	}
	logAlgorithmDrift(components, p.label)
	logUnresolvedDeps(components, p.label)

	// Opt-in JSF signing: sign after the BOM is fully assembled so the
	// signature covers components + dependencies.
	if g.signer != nil {
		if err := SignBOM(bom, g.signer); err != nil {
			return nil, fmt.Errorf("cbom: sign BOM: %w", err)
		}
	}
	return bom, nil
}
```

- [ ] **Step 3: Replace `GenerateForApplication` in `application.go`** — keep its doc comment (lines 29-35); replace the function from `func (g *Generator) GenerateForApplication` through its closing brace with:

```go
func (g *Generator) GenerateForApplication(ctx context.Context, st store.CryptoStore, tag string) (*cdx.BOM, error) {
	rows, err := st.ListApplicationScopeAssets(ctx, tag)
	if err != nil {
		return nil, fmt.Errorf("cbom: list assets for application %q: %w", tag, err)
	}

	// The root application component identifies the application tag. Treat the
	// tag as the FISMA system identifier for OMB M-23-02 cross-reference
	// purposes (see OMB §II.A field 1).
	root := &cdx.Component{
		Type:   cdx.ComponentTypeApplication,
		BOMRef: "application:" + tag,
		Name:   tag,
		Properties: &[]cdx.Property{
			{Name: "cipherflag:application.tag", Value: tag},
			{Name: "cipherflag:application.asset_count", Value: strconv.Itoa(len(rows))},
			{Name: "cipherflag:application.fisma_id_alias", Value: tag},
		},
	}
	return g.buildBOMFromRows(ctx, st, rows, bomParams{
		root:          root,
		label:         "application:" + tag,
		depsInBOMOnly: true,
		skipMapErrors: true,
	})
}
```

Drop any imports the compiler reports unused in either file (`sort`, `time`, `uuid` may move entirely to `generator.go`).

- [ ] **Step 4: Unit-level verification**

```bash
gofmt -l internal/export/cbom
go build ./... && go vet ./internal/export/cbom/
go test ./internal/export/cbom/... -count=1
```

Expected: clean and `ok`.

- [ ] **Step 5: Golden verification (the actual safety net)**

```bash
CIPHERFLAG_TEST_DB="postgres://cipherflag:changeme@localhost:5434/cipherflag_test?sslmode=disable" \
  go test -tags integration ./internal/export/cbom/... -count=1
```

Expected: `ok` with **no golden file changes** (`git status` shows nothing under `internal/export/cbom/testdata`). If a golden diff appears, the refactor changed behaviour: fix the refactor, never regenerate the golden with `-update`.

- [ ] **Step 6: Commit** (after Erik's go)

```bash
git add internal/export/cbom/generator.go internal/export/cbom/application.go
git commit -m "refactor(cbom): share one BOM assembly pipeline across scope and application exports"
```

---

### Task 5: Honest asset counts and one mapping-error policy

**Files:**
- Modify: `internal/export/cbom/generator.go` (`buildBOMFromRows`, new `setAssetCounts`; remove `skipMapErrors`)
- Modify: `internal/export/cbom/application.go` (drop `skipMapErrors: true`)
- Create: `internal/export/cbom/generator_counts_test.go`

**Interfaces:**
- Consumes: `bomParams`, `buildBOMFromRows` (Task 4); test fakes `fakeGenStore`, `healthReport` from `generator_test.go`.
- Produces: root `*.asset_count` = emitted components; `*.assets_omitted` and `*.assets_omitted_types` when rows are dropped; `appRowsStore` test fake reused by Task 8.

- [ ] **Step 1: Write the failing tests** — create `internal/export/cbom/generator_counts_test.go` (Apache header, then):

```go
package cbom

import (
	"context"
	"errors"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
	"github.com/stretchr/testify/require"
)

func rootProps(t *testing.T, bom *cdx.BOM) map[string]string {
	t.Helper()
	require.NotNil(t, bom.Metadata)
	require.NotNil(t, bom.Metadata.Component)
	require.NotNil(t, bom.Metadata.Component.Properties)
	m := map[string]string{}
	for _, p := range *bom.Metadata.Component.Properties {
		m[p.Name] = p.Value
	}
	return m
}

func validCert(fp string) *model.Certificate {
	return &model.Certificate{
		FingerprintSHA256:  fp,
		Subject:            model.DistinguishedName{CommonName: "test.example.com", Full: "CN=test.example.com"},
		Issuer:             model.DistinguishedName{Full: "CN=CA"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(365 * 24 * time.Hour),
		SignatureAlgorithm: model.SigSHA256WithRSA,
	}
}

// appRowsStore returns fixed application rows; embedded fakeGenStore supplies
// the per-asset lookups.
type appRowsStore struct {
	fakeGenStore
	rows []store.ScopeAssetRow
}

func (s *appRowsStore) ListApplicationScopeAssets(context.Context, string) ([]store.ScopeAssetRow, error) {
	return s.rows, nil
}

// certErrStore fails every certificate lookup.
type certErrStore struct{ fakeGenStore }

func (*certErrStore) GetCertificate(context.Context, string) (*model.Certificate, error) {
	return nil, errors.New("db down")
}

func TestGenerate_AssetCountReflectsEmittedComponents(t *testing.T) {
	fake := &fakeGenStore{
		hostIDs: []string{"h1"},
		assetRows: []store.ScopeAssetRow{
			{AssetType: "certificate", AssetID: "fp1", Report: healthReport("certificate", "fp1")},
			// A health report can outlive its asset: no component can be built.
			{AssetType: "certificate", AssetID: "gone", Report: healthReport("certificate", "gone")},
			{AssetType: "ssh_key", AssetID: "gone-key", Report: healthReport("ssh_key", "gone-key")},
		},
		certs: map[string]*model.Certificate{"fp1": validCert("fp1")},
	}

	bom, err := NewGenerator().Generate(context.Background(), fake, &Scope{Name: "s", HostIDs: []string{"h1"}})
	require.NoError(t, err)

	props := rootProps(t, bom)
	require.Equal(t, "1", props["cipherflag:scope.asset_count"], "asset_count must equal emitted components")
	require.Equal(t, "2", props["cipherflag:scope.assets_omitted"])
	require.Equal(t, "certificate,ssh_key", props["cipherflag:scope.assets_omitted_types"])
	require.Equal(t, "1", props["cipherflag:scope.host_count"], "host_count is unaffected")
}

func TestGenerate_NoOmissionPropertiesWhenEverythingMapped(t *testing.T) {
	fake := &fakeGenStore{
		hostIDs:   []string{"h1"},
		assetRows: []store.ScopeAssetRow{{AssetType: "certificate", AssetID: "fp1", Report: healthReport("certificate", "fp1")}},
		certs:     map[string]*model.Certificate{"fp1": validCert("fp1")},
	}

	bom, err := NewGenerator().Generate(context.Background(), fake, &Scope{Name: "s", HostIDs: []string{"h1"}})
	require.NoError(t, err)

	props := rootProps(t, bom)
	require.Equal(t, "1", props["cipherflag:scope.asset_count"])
	require.NotContains(t, props, "cipherflag:scope.assets_omitted")
	require.NotContains(t, props, "cipherflag:scope.assets_omitted_types")
}

func TestGenerate_MappingErrorFailsExport(t *testing.T) {
	fake := &certErrStore{fakeGenStore{
		hostIDs:   []string{"h1"},
		assetRows: []store.ScopeAssetRow{{AssetType: "certificate", AssetID: "fp1", Report: healthReport("certificate", "fp1")}},
	}}

	_, err := NewGenerator().Generate(context.Background(), fake, &Scope{Name: "s", HostIDs: []string{"h1"}})
	require.Error(t, err, "a partial signed BOM must never be returned")
}

// appErrStore serves application rows but fails every certificate lookup.
type appErrStore struct {
	fakeGenStore
	rows []store.ScopeAssetRow
}

func (s *appErrStore) ListApplicationScopeAssets(context.Context, string) ([]store.ScopeAssetRow, error) {
	return s.rows, nil
}
func (*appErrStore) GetCertificate(context.Context, string) (*model.Certificate, error) {
	return nil, errors.New("db down")
}

func TestGenerateForApplication_MappingErrorFailsExport(t *testing.T) {
	st := &appErrStore{rows: []store.ScopeAssetRow{
		{AssetType: "certificate", AssetID: "fp1", Report: healthReport("certificate", "fp1")},
	}}

	_, err := NewGenerator().GenerateForApplication(context.Background(), st, "app-1")
	require.Error(t, err, "application export must fail on a mapping error like the scope export")
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/export/cbom/ -run 'AssetCount|NoOmission|MappingError' -count=1`
Expected: `AssetCountReflectsEmittedComponents` FAILS (`asset_count` is `3`, want `1`; omission properties missing); `GenerateForApplication_MappingErrorFailsExport` FAILS (no error returned, the row is silently skipped). `NoOmission…` and `Generate_MappingErrorFailsExport` already pass; they pin behaviour that must survive.

- [ ] **Step 3: Implement** — in `generator.go`:

(a) Add `"strings"` to the imports if absent.

(b) In `buildBOMFromRows`, replace the row loop's head and add counters:

```go
	mapped := 0
	omittedByType := map[string]int{}
	for _, row := range rows {
		comp, algoComps, err := g.mapRow(ctx, st, row)
		if err != nil {
			return nil, fmt.Errorf("cbom: map %s %s: %w", row.AssetType, row.AssetID, err)
		}
		if comp != nil {
			components = append(components, *comp)
			mapped++
		} else {
			omittedByType[row.AssetType]++
		}
```

(the rest of the loop body is unchanged), and immediately after the loop:

```go
	setAssetCounts(p.root, mapped, len(rows)-mapped, omittedByType)
```

(c) Remove the `skipMapErrors` field from `bomParams` and its doc comment.

(d) Add the helper below `buildBOMFromRows`:

```go
// setAssetCounts makes the root's *.asset_count describe the components the BOM
// actually contains, and discloses rows that produced no component (in CE, a
// health report whose asset was deleted). The count value is patched in place
// and the disclosure properties are appended, so existing property order (and
// therefore the golden output) is unchanged when nothing was omitted.
func setAssetCounts(root *cdx.Component, mapped, omitted int, omittedByType map[string]int) {
	if root == nil || root.Properties == nil {
		return
	}
	props := *root.Properties
	for i := range props {
		if !strings.HasSuffix(props[i].Name, ".asset_count") {
			continue
		}
		props[i].Value = strconv.Itoa(mapped)
		if omitted > 0 {
			types := make([]string, 0, len(omittedByType))
			for typ := range omittedByType {
				types = append(types, typ)
			}
			sort.Strings(types)
			prefix := strings.TrimSuffix(props[i].Name, "asset_count")
			props = append(props,
				cdx.Property{Name: prefix + "assets_omitted", Value: strconv.Itoa(omitted)},
				cdx.Property{Name: prefix + "assets_omitted_types", Value: strings.Join(types, ",")},
			)
			*root.Properties = props
		}
		return
	}
}
```

In `application.go`, delete the `skipMapErrors: true,` line from the `bomParams` literal.

- [ ] **Step 4: Run to verify they pass**

```bash
gofmt -l internal/export/cbom
go vet ./internal/export/cbom/
go test ./internal/export/cbom/ -count=1
```

Expected: `ok`.

- [ ] **Step 5: Goldens unchanged**

```bash
CIPHERFLAG_TEST_DB="postgres://cipherflag:changeme@localhost:5434/cipherflag_test?sslmode=disable" \
  go test -tags integration ./internal/export/cbom/... -count=1
```

Expected: `ok`, no golden diff (fixtures have no orphaned rows, so no disclosure properties appear).

- [ ] **Step 6: Commit** (after Erik's go)

```bash
git add internal/export/cbom/generator.go internal/export/cbom/application.go internal/export/cbom/generator_counts_test.go
git commit -m "fix(cbom): asset_count reflects emitted components; fail exports on mapping errors"
```

---

### Task 6: `GenerateWholeEstate`

**Files:**
- Create: `internal/export/cbom/estate.go`
- Create: `internal/export/cbom/estate_test.go`

**Interfaces:**
- Consumes: `buildBOMFromRows`, `bomParams` (Task 4); `store.CryptoStore.ListAllAssetHealthReports`; test helpers `fakeGenStore`, `healthReport`, `validCert`, `rootProps` (Tasks 5 and earlier).
- Produces: `func (g *Generator) GenerateWholeEstate(ctx context.Context, st store.CryptoStore) (*cdx.BOM, error)`; root component `bom-ref` `estate`, property `cipherflag:estate.asset_count`.

- [ ] **Step 1: Write the failing tests** — `internal/export/cbom/estate_test.go` (Apache header, then):

```go
package cbom

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
	"github.com/stretchr/testify/require"
)

// estateStore serves a fixed whole-estate row set; the embedded fakeGenStore
// supplies the per-asset lookups.
type estateStore struct {
	fakeGenStore
	all []store.ScopeAssetRow
	err error
}

func (s *estateStore) ListAllAssetHealthReports(context.Context) ([]store.ScopeAssetRow, error) {
	return s.all, s.err
}

func TestGenerateWholeEstate_IncludesEveryScoredAsset(t *testing.T) {
	st := &estateStore{
		fakeGenStore: fakeGenStore{
			certs: map[string]*model.Certificate{"fp1": validCert("fp1")},
			sshKeys: map[string]*model.SSHKey{
				"key-1": {ID: "key-1", FingerprintSHA256: "fp-key-1", KeyType: "ssh-ed25519",
					KeySizeBits: 256, FirstSeen: time.Now(), DiscoveryStatus: "active"},
			},
		},
		all: []store.ScopeAssetRow{
			{AssetType: "certificate", AssetID: "fp1", Report: healthReport("certificate", "fp1")},
			{AssetType: "ssh_key", AssetID: "key-1", Report: healthReport("ssh_key", "key-1")},
		},
	}

	bom, err := NewGenerator().GenerateWholeEstate(context.Background(), st)
	require.NoError(t, err)

	require.Equal(t, "estate", bom.Metadata.Component.BOMRef)
	require.Equal(t, "estate", bom.Metadata.Component.Name)
	require.Equal(t, "2", rootProps(t, bom)["cipherflag:estate.asset_count"])

	refs := map[string]bool{}
	for _, c := range *bom.Components {
		refs[c.BOMRef] = true
	}
	require.True(t, refs["cert:fp1"], "certificate component missing")
	require.True(t, refs["sshkey:fp-key-1"], "ssh key component missing")
}

func TestGenerateWholeEstate_EmptyInventoryIsAValidBOM(t *testing.T) {
	bom, err := NewGenerator().GenerateWholeEstate(context.Background(), &estateStore{})
	require.NoError(t, err)
	require.NotNil(t, bom)
	require.Equal(t, "0", rootProps(t, bom)["cipherflag:estate.asset_count"])
	require.Nil(t, bom.Components, "an empty estate has no components")
}

func TestGenerateWholeEstate_ListErrorIsReturned(t *testing.T) {
	_, err := NewGenerator().GenerateWholeEstate(context.Background(), &estateStore{err: errors.New("db down")})
	require.ErrorContains(t, err, "list all assets")
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/export/cbom/ -run GenerateWholeEstate -count=1`
Expected: build failure, `GenerateWholeEstate undefined`.

- [ ] **Step 3: Implement** — `internal/export/cbom/estate.go` (Apache header, then):

```go
package cbom

import (
	"context"
	"fmt"
	"strconv"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// GenerateWholeEstate produces a CycloneDX 1.6 CBOM over every scored asset in
// the database, independent of host provenance or application tag. Signed when
// a signer is configured.
//
// The BOM is assembled in memory with one store lookup per asset (a signed BOM
// must be, because JCS canonicalisation cannot stream), so very large
// inventories cost memory and time proportional to their size.
func (g *Generator) GenerateWholeEstate(ctx context.Context, st store.CryptoStore) (*cdx.BOM, error) {
	rows, err := st.ListAllAssetHealthReports(ctx)
	if err != nil {
		return nil, fmt.Errorf("cbom: list all assets: %w", err)
	}
	root := &cdx.Component{
		Type:   cdx.ComponentTypeApplication,
		BOMRef: "estate",
		Name:   "estate",
		Properties: &[]cdx.Property{
			{Name: "cipherflag:estate.asset_count", Value: strconv.Itoa(len(rows))},
		},
	}
	return g.buildBOMFromRows(ctx, st, rows, bomParams{root: root, label: "estate"})
}
```

- [ ] **Step 4: Run to verify they pass**

```bash
gofmt -l internal/export/cbom
go test ./internal/export/cbom/ -run 'GenerateWholeEstate' -count=1 -v
go test ./internal/export/cbom/... -count=1
```

Expected: `ok`.

- [ ] **Step 5: Commit** (after Erik's go)

```bash
git add internal/export/cbom/estate.go internal/export/cbom/estate_test.go
git commit -m "feat(cbom): whole-estate CBOM generator"
```

---

### Task 7: Estate download endpoint

**Files:**
- Modify: `internal/api/handler/cbom.go` (interface, `DownloadEstate`, imports)
- Modify: `internal/api/handler/cbom_test.go` (fake gains `GenerateWholeEstate`; new tests)
- Modify: `internal/api/server.go` (route, after `r.Get("/export/cbom", cbomH.Download)`)

**Interfaces:**
- Consumes: `Generator.GenerateWholeEstate` (Task 6); `writeBOM`, `extendWriteDeadline` (Task 3); `cbomtest` (Task 3).
- Produces: `GET /api/v1/export/cbom/estate`; `(*CBOMHandler).DownloadEstate`; the `cbomGenerator` interface now also requires `GenerateWholeEstate`.

- [ ] **Step 1: Write the failing tests** — first give the test fake the new method: in `internal/api/handler/cbom_test.go`, after `func (f *fakeCBOMGen) Generate(...)`, add:

```go
func (f *fakeCBOMGen) GenerateWholeEstate(_ context.Context, _ store.CryptoStore) (*cdx.BOM, error) {
	return f.bom, f.err
}
```

Then append these tests to the same file (add `"regexp"` and `cbomtest` to its imports: `"github.com/net4n6-dev/cipherflag/internal/export/cbom/cbomtest"`):

```go
func TestCBOMHandler_DownloadEstate_200(t *testing.T) {
	h := newTestCBOMHandler(&fakeCBOMGen{bom: minimalTestBOM()}, &config.CBOMConfig{})

	rr := httptest.NewRecorder()
	h.DownloadEstate(rr, httptest.NewRequest(http.MethodGet, "/api/v1/export/cbom/estate", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/vnd.cyclonedx+json") {
		t.Errorf("Content-Type = %q", ct)
	}
	cd := rr.Header().Get("Content-Disposition")
	if !regexp.MustCompile(`^attachment; filename="cipherflag-cbom-estate-\d{4}-\d{2}-\d{2}\.cdx\.json"$`).MatchString(cd) {
		t.Errorf("Content-Disposition = %q", cd)
	}
	if !strings.Contains(rr.Body.String(), `"bomFormat":"CycloneDX"`) {
		t.Errorf("body is not a CycloneDX document: %s", rr.Body.String())
	}
}

func TestCBOMHandler_DownloadEstate_GenerationErrorIs500WithoutDetail(t *testing.T) {
	h := newTestCBOMHandler(&fakeCBOMGen{err: fmt.Errorf("pq: password authentication failed")}, &config.CBOMConfig{})

	rr := httptest.NewRecorder()
	h.DownloadEstate(rr, httptest.NewRequest(http.MethodGet, "/api/v1/export/cbom/estate", nil))

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "password") {
		t.Errorf("internal error detail leaked to the client: %s", rr.Body.String())
	}
}

func TestCBOMHandler_DownloadEstate_SignedBOMKeepsSignature(t *testing.T) {
	h := newTestCBOMHandler(&fakeCBOMGen{bom: cbomtest.SignedBOM(t)}, &config.CBOMConfig{})

	rr := httptest.NewRecorder()
	h.DownloadEstate(rr, httptest.NewRequest(http.MethodGet, "/api/v1/export/cbom/estate", nil))

	cbomtest.AssertValidSignature(t, rr.Body.Bytes())
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/api/handler/ -run DownloadEstate -count=1`
Expected: build failure, `h.DownloadEstate undefined` (and the fake does not yet satisfy the extended interface once Step 3 begins, which is why the fake changed first).

- [ ] **Step 3: Implement** — in `internal/api/handler/cbom.go`:

(a) Extend the interface:

```go
type cbomGenerator interface {
	Generate(ctx context.Context, st store.CryptoStore, scope *cbom.Scope) (*cdx.BOM, error)
	GenerateWholeEstate(ctx context.Context, st store.CryptoStore) (*cdx.BOM, error)
}
```

(b) Add `"time"` to the imports, then add the handler after `Download`:

```go
// DownloadEstate handles GET /api/v1/export/cbom/estate: a CycloneDX 1.6 CBOM
// over every scored asset. Signed when [cbom.signing] is enabled.
func (h *CBOMHandler) DownloadEstate(w http.ResponseWriter, r *http.Request) {
	extendWriteDeadline(w)
	bom, err := h.gen.GenerateWholeEstate(r.Context(), h.store)
	if err != nil {
		log.Error().Err(err).Msg("cbom: estate generation failed")
		writeError(w, http.StatusInternalServerError, "CBOM generation failed")
		return
	}
	filename := "cipherflag-cbom-estate-" + time.Now().UTC().Format("2006-01-02") + ".cdx.json"
	writeBOM(w, bom, filename, false)
}
```

(c) In `internal/api/server.go`, directly after `r.Get("/export/cbom", cbomH.Download)`:

```go
			r.Get("/export/cbom/estate", cbomH.DownloadEstate)
```

- [ ] **Step 4: Run to verify they pass**

```bash
gofmt -l internal/api
go build ./... && go vet ./internal/api/...
go test ./internal/api/... -count=1
```

Expected: `ok`.

- [ ] **Step 5: Commit** (after Erik's go)

```bash
git add internal/api/handler/cbom.go internal/api/handler/cbom_test.go internal/api/server.go
git commit -m "feat(api): GET /export/cbom/estate"
```

---

### Task 8: Application CBOM endpoint

**Files:**
- Modify: `internal/export/cbom/application.go` (sentinel error and zero-row check)
- Create: `internal/export/cbom/application_test.go`
- Modify: `internal/api/handler/cbom.go` (interface, `DownloadApplication`, `filenameSafe`, imports)
- Modify: `internal/api/handler/cbom_test.go` (fake method; tests)
- Modify: `internal/api/server.go` (route beside the application metadata GET, near line 298)

**Interfaces:**
- Consumes: `buildBOMFromRows` (Task 4); `appRowsStore`, `healthReport`, `rootProps` (Task 5); `writeBOM`, `extendWriteDeadline` (Task 3).
- Produces: `cbom.ErrNoApplicationAssets`; `(*CBOMHandler).DownloadApplication`; `GET /api/v1/applications/{tag}/cbom`; `filenameSafe(string) string` in the handler package. The `cbomGenerator` interface also requires `GenerateForApplication`.

- [ ] **Step 1: Write the failing generator tests** — `internal/export/cbom/application_test.go` (Apache header, then):

```go
package cbom

import (
	"context"
	"errors"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/store"
	"github.com/stretchr/testify/require"
)

func TestGenerateForApplication_NoRowsIsErrNoApplicationAssets(t *testing.T) {
	_, err := NewGenerator().GenerateForApplication(context.Background(), &appRowsStore{}, "typo-tag")
	require.True(t, errors.Is(err, ErrNoApplicationAssets), "got %v", err)
}

func TestGenerateForApplication_AllRowsOrphanedStillReturnsBOMWithDisclosure(t *testing.T) {
	st := &appRowsStore{rows: []store.ScopeAssetRow{
		{AssetType: "certificate", AssetID: "gone", Report: healthReport("certificate", "gone")},
	}}

	bom, err := NewGenerator().GenerateForApplication(context.Background(), st, "app-1")
	require.NoError(t, err, "orphaned rows are disclosed, not an error")

	props := rootProps(t, bom)
	require.Equal(t, "0", props["cipherflag:application.asset_count"])
	require.Equal(t, "1", props["cipherflag:application.assets_omitted"])
	require.Equal(t, "certificate", props["cipherflag:application.assets_omitted_types"])
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/export/cbom/ -run GenerateForApplication_ -count=1`
Expected: build failure, `ErrNoApplicationAssets undefined`.

- [ ] **Step 3: Implement the sentinel** — in `application.go` add `"errors"` to the imports and:

```go
// ErrNoApplicationAssets is returned by GenerateForApplication when no scored
// asset carries the tag, so callers can tell a typo'd or unused tag from a real
// (possibly all-omitted) application.
var ErrNoApplicationAssets = errors.New("cbom: no scored assets for application")
```

then, in `GenerateForApplication` directly after the `ListApplicationScopeAssets` error check:

```go
	if len(rows) == 0 {
		return nil, fmt.Errorf("%w: %q", ErrNoApplicationAssets, tag)
	}
```

Run `go test ./internal/export/cbom/ -count=1` (expected `ok`), and re-run the integration goldens (Task 0 command); they use app-1, which has assets, so expected `ok`, no golden diff.

- [ ] **Step 4: Write the failing handler tests** — in `internal/api/handler/cbom_test.go`, add the fake method:

```go
func (f *fakeCBOMGen) GenerateForApplication(_ context.Context, _ store.CryptoStore, _ string) (*cdx.BOM, error) {
	return f.bom, f.err
}
```

and append (add `"context"` if missing, and `"github.com/go-chi/chi/v5"` to imports):

```go
// appRequest builds a request whose chi route context carries the given raw
// (already decoded) tag, as the router would supply it.
func appRequest(tag string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/applications/x/cbom", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tag", tag)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func TestCBOMHandler_DownloadApplication_200(t *testing.T) {
	h := newTestCBOMHandler(&fakeCBOMGen{bom: minimalTestBOM()}, &config.CBOMConfig{})

	rr := httptest.NewRecorder()
	h.DownloadApplication(rr, appRequest("payments-api"))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rr.Code, rr.Body.String())
	}
	cd := rr.Header().Get("Content-Disposition")
	if !regexp.MustCompile(`^attachment; filename="cipherflag-cbom-app-payments-api-\d{4}-\d{2}-\d{2}\.cdx\.json"$`).MatchString(cd) {
		t.Errorf("Content-Disposition = %q", cd)
	}
}

func TestCBOMHandler_DownloadApplication_UnknownTagIs404(t *testing.T) {
	err := fmt.Errorf("%w: %q", cbom.ErrNoApplicationAssets, "typo")
	h := newTestCBOMHandler(&fakeCBOMGen{err: err}, &config.CBOMConfig{})

	rr := httptest.NewRecorder()
	h.DownloadApplication(rr, appRequest("typo"))

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %s", rr.Code, rr.Body.String())
	}
}

func TestCBOMHandler_DownloadApplication_BlankTagIs400(t *testing.T) {
	h := newTestCBOMHandler(&fakeCBOMGen{bom: minimalTestBOM()}, &config.CBOMConfig{})

	rr := httptest.NewRecorder()
	h.DownloadApplication(rr, appRequest("   "))

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestCBOMHandler_DownloadApplication_GenerationErrorIs500(t *testing.T) {
	h := newTestCBOMHandler(&fakeCBOMGen{err: fmt.Errorf("db down")}, &config.CBOMConfig{})

	rr := httptest.NewRecorder()
	h.DownloadApplication(rr, appRequest("payments-api"))

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
}

// The tag is caller-controlled and lands in a header: quotes, CR/LF and path
// separators must not survive into the filename.
func TestCBOMHandler_DownloadApplication_TagCannotInjectHeaderSyntax(t *testing.T) {
	h := newTestCBOMHandler(&fakeCBOMGen{bom: minimalTestBOM()}, &config.CBOMConfig{})

	rr := httptest.NewRecorder()
	h.DownloadApplication(rr, appRequest("a\"b\r\nX-Evil: y/../z"))

	cd := rr.Header().Get("Content-Disposition")
	if !regexp.MustCompile(`^attachment; filename="cipherflag-cbom-app-[A-Za-z0-9._-]+-\d{4}-\d{2}-\d{2}\.cdx\.json"$`).MatchString(cd) {
		t.Errorf("unsafe characters reached Content-Disposition: %q", cd)
	}
}

func TestCBOMHandler_DownloadApplication_SignedBOMKeepsSignature(t *testing.T) {
	h := newTestCBOMHandler(&fakeCBOMGen{bom: cbomtest.SignedBOM(t)}, &config.CBOMConfig{})

	rr := httptest.NewRecorder()
	h.DownloadApplication(rr, appRequest("payments-api"))

	cbomtest.AssertValidSignature(t, rr.Body.Bytes())
}
```

(add `"github.com/net4n6-dev/cipherflag/internal/export/cbom"` is already imported in this test file.)

- [ ] **Step 5: Run to verify they fail**

Run: `go test ./internal/api/handler/ -run DownloadApplication -count=1`
Expected: build failure, `h.DownloadApplication undefined`.

- [ ] **Step 6: Implement the handler and route** — in `internal/api/handler/cbom.go`: add `"strings"` and `"github.com/go-chi/chi/v5"` to the imports; extend the interface:

```go
type cbomGenerator interface {
	Generate(ctx context.Context, st store.CryptoStore, scope *cbom.Scope) (*cdx.BOM, error)
	GenerateWholeEstate(ctx context.Context, st store.CryptoStore) (*cdx.BOM, error)
	GenerateForApplication(ctx context.Context, st store.CryptoStore, tag string) (*cdx.BOM, error)
}
```

and add:

```go
// DownloadApplication handles GET /api/v1/applications/{tag}/cbom: a CycloneDX
// 1.6 CBOM of the assets carrying the application tag. An empty tag is a 400; a
// tag no scored asset carries is a 404 (an empty BOM would look valid and hide
// a typo). Signed when [cbom.signing] is enabled.
func (h *CBOMHandler) DownloadApplication(w http.ResponseWriter, r *http.Request) {
	extendWriteDeadline(w)
	tag := strings.TrimSpace(chi.URLParam(r, "tag"))
	if tag == "" {
		writeError(w, http.StatusBadRequest, "application tag is required")
		return
	}
	bom, err := h.gen.GenerateForApplication(r.Context(), h.store, tag)
	if errors.Is(err, cbom.ErrNoApplicationAssets) {
		writeError(w, http.StatusNotFound, "no scored assets carry this application tag")
		return
	}
	if err != nil {
		log.Error().Err(err).Str("application_tag", tag).Msg("cbom: application generation failed")
		writeError(w, http.StatusInternalServerError, "CBOM generation failed")
		return
	}
	filename := "cipherflag-cbom-app-" + filenameSafe(tag) + "-" + time.Now().UTC().Format("2006-01-02") + ".cdx.json"
	writeBOM(w, bom, filename, false)
}

// filenameSafe restricts s to [A-Za-z0-9._-]; every other rune becomes "_". It
// keeps a caller-controlled application tag from injecting header syntax or
// path components into Content-Disposition.
func filenameSafe(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == '-' {
			b.WriteRune(c)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}
```

In `internal/api/server.go`, directly after `r.Get("/applications/{tag}/metadata", appMetaH.Get)`:

```go
			r.Get("/applications/{tag}/cbom", cbomH.DownloadApplication)
```

- [ ] **Step 7: Run to verify they pass**

```bash
gofmt -l internal/api internal/export/cbom
go build ./... && go vet ./internal/api/... ./internal/export/cbom/
go test ./internal/api/... ./internal/export/cbom/... -count=1
```

Expected: `ok`.

- [ ] **Step 8: Commit** (after Erik's go)

```bash
git add internal/export/cbom/application.go internal/export/cbom/application_test.go \
  internal/api/handler/cbom.go internal/api/handler/cbom_test.go internal/api/server.go
git commit -m "feat(api): GET /applications/{tag}/cbom"
```

---

### Task 9: Router-level access tests for the new routes

**Files:**
- Create: `internal/api/server_cbom_export_test.go`

**Interfaces:**
- Consumes: `NewRouter`; the `authGateStore` fake and imports pattern from `internal/api/server_import_gate_test.go` (same package `api`); routes from Tasks 7 and 8.
- Produces: proof through the real router that the routes require authentication but not admin.

- [ ] **Step 1: Write the tests** — `internal/api/server_cbom_export_test.go` (Apache header, then):

```go
package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/analysis/scoring"
	"github.com/net4n6-dev/cipherflag/internal/auth"
	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/venafi"
	"github.com/net4n6-dev/cipherflag/internal/ingest/observcache"
	"github.com/net4n6-dev/cipherflag/internal/sse"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// exportGateStore adds empty inventories to the auth fake so the export routes
// can run end to end without a database.
type exportGateStore struct{ authGateStore }

func (*exportGateStore) ListAllAssetHealthReports(context.Context) ([]store.ScopeAssetRow, error) {
	return nil, nil
}
func (*exportGateStore) ListApplicationScopeAssets(context.Context, string) ([]store.ScopeAssetRow, error) {
	return nil, nil
}

// The CBOM export routes are readable by any authenticated caller (viewer and
// agent tokens included) but never anonymously.
func TestRouter_CBOMExportRoutes_AuthenticatedButNotAdminOnly(t *testing.T) {
	secret := []byte("test-secret")
	sum := sha256.Sum256([]byte("agent-secret"))
	st := &exportGateStore{authGateStore{agentHash: hex.EncodeToString(sum[:])}}
	router := NewRouter(st, &config.Config{}, "", "", secret,
		observcache.NewNoop(), scoring.NewNoopScorer(), sse.NewHub(),
		venafi.NewLiveConfig(config.VenafiExportConfig{}))

	viewer := func(r *http.Request) {
		tok, err := auth.SignJWT(secret, "u1", "u1@example.com", "viewer")
		if err != nil {
			t.Fatalf("SignJWT: %v", err)
		}
		r.AddCookie(&http.Cookie{Name: auth.CookieName, Value: tok})
	}
	agent := func(r *http.Request) { r.Header.Set("Authorization", "Bearer agent-secret") }
	anon := func(*http.Request) {}

	cases := []struct {
		name string
		path string
		auth func(*http.Request)
		want int
	}{
		{"estate anonymous", "/api/v1/export/cbom/estate", anon, http.StatusUnauthorized},
		{"estate viewer", "/api/v1/export/cbom/estate", viewer, http.StatusOK},
		{"estate agent token", "/api/v1/export/cbom/estate", agent, http.StatusOK},
		{"application anonymous", "/api/v1/applications/payments-api/cbom", anon, http.StatusUnauthorized},
		{"application viewer, unknown tag", "/api/v1/applications/payments-api/cbom", viewer, http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			tc.auth(req)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.want, rec.Body.String())
			}
			if tc.want == http.StatusOK && !strings.Contains(rec.Body.String(), `"bomFormat":"CycloneDX"`) {
				t.Errorf("200 response is not a CycloneDX document: %s", rec.Body.String())
			}
		})
	}
}
```

- [ ] **Step 2: Run**

Run: `go test ./internal/api/ -run TestRouter_CBOMExportRoutes -count=1 -v`
Expected: PASS (the routes exist from Tasks 7 and 8; this task adds coverage only). If a case fails, that is a real routing or auth bug: investigate before changing the test.

- [ ] **Step 3: Verify and commit** (after Erik's go)

```bash
gofmt -l internal/api
go vet ./internal/api/ && go test ./internal/api/... -count=1
git add internal/api/server_cbom_export_test.go
git commit -m "test(api): router-level access tests for CBOM estate and application routes"
```

---

### Task 10: Syslog TLS without a client certificate

**Files:**
- Modify: `internal/config/config_sinks.go` (`SyslogSinkConfig`, `Validate`)
- Modify: `internal/config/config_sinks_test.go` (lines 96-98 pinned the old behaviour)
- Modify: `internal/export/cbom/sinks/syslog/syslog.go` (`New`, `dial` TLS case)
- Modify: `internal/export/cbom/sinks/syslog/syslog_test.go` (new tests)
- Modify: `docs/configuration.md` (new section before `### [pcap]`)

**Interfaces:**
- Consumes: existing `SyslogSinkConfig`, `Sink`, `New`, `dial`.
- Produces: `SyslogSinkConfig.TLSInsecure bool` (`toml:"tls_insecure"`); `cert_file`/`key_file` optional but both-or-neither.

- [ ] **Step 1: Update the config tests** — in `internal/config/config_sinks_test.go`, replace lines 96-98 (the assertion that `tls` with no cert/key is an error; it pinned the bug) with:

```go
	if err := (&SyslogSinkConfig{Protocol: "tls", Address: "x", Format: "cef"}).Validate("s"); err != nil {
		t.Errorf("tls without a client cert is server-authenticated TLS and must validate: %v", err)
	}
	if err := (&SyslogSinkConfig{Protocol: "tls", Address: "x", Format: "cef", CertFile: "c.pem"}).Validate("s"); err == nil {
		t.Error("expected error for cert_file without key_file")
	}
	if err := (&SyslogSinkConfig{Protocol: "tls", Address: "x", Format: "cef", KeyFile: "k.pem"}).Validate("s"); err == nil {
		t.Error("expected error for key_file without cert_file")
	}
	if err := (&SyslogSinkConfig{Protocol: "tls", Address: "x", Format: "cef", CertFile: "c.pem", KeyFile: "k.pem"}).Validate("s"); err != nil {
		t.Errorf("mutual TLS config must validate: %v", err)
	}
```

- [ ] **Step 2: Write the failing sink tests** — append to `internal/export/cbom/sinks/syslog/syslog_test.go`, adding these imports: `"crypto/ecdsa"`, `"crypto/elliptic"`, `"crypto/rand"`, `"crypto/tls"`, `"crypto/x509"`, `"crypto/x509/pkix"`, `"encoding/pem"`, `"math/big"`, `"os"`, `"path/filepath"`:

```go
func selfSignedServerCert(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, caPath
}

// startTLSSyslogServer accepts one TLS connection that does NOT require a
// client certificate and reports the first bytes it reads.
func startTLSSyslogServer(t *testing.T, cert tls.Certificate) (string, <-chan string) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		got <- string(buf[:n])
	}()
	return ln.Addr().String(), got
}

func tlsSink(t *testing.T, cfg config.SyslogSinkConfig) *Sink {
	t.Helper()
	cfg.Protocol, cfg.Format = "tls", "rfc5424"
	sink, err := New(cfg, config.SinkConfig{Timeout: 2 * time.Second}, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sink.Close() })
	return sink
}

var tlsTestEvents = &types.SinkPayload{Events: []types.SinkEvent{{Payload: map[string]interface{}{"x": 1}}}}

func TestSyslogSink_TLSServerAuthOnly_NoClientCert(t *testing.T) {
	cert, caPath := selfSignedServerCert(t)
	addr, got := startTLSSyslogServer(t, cert)

	sink := tlsSink(t, config.SyslogSinkConfig{Address: addr, CAFile: caPath})
	if err := sink.Send(context.Background(), tlsTestEvents); err != nil {
		t.Fatalf("Send without a client cert failed: %v", err)
	}
	select {
	case line := <-got:
		if line == "" {
			t.Errorf("server received nothing")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not receive a line")
	}
}

func TestSyslogSink_TLSUntrustedServerIsRejectedByDefault(t *testing.T) {
	cert, _ := selfSignedServerCert(t)
	addr, _ := startTLSSyslogServer(t, cert)

	sink := tlsSink(t, config.SyslogSinkConfig{Address: addr}) // no ca_file, no tls_insecure
	err := sink.Send(context.Background(), tlsTestEvents)
	if err == nil {
		t.Fatal("expected certificate verification to fail")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Errorf("error should be a certificate verification failure, got: %v", err)
	}
}

func TestSyslogSink_TLSInsecureSkipsVerification(t *testing.T) {
	cert, _ := selfSignedServerCert(t)
	addr, got := startTLSSyslogServer(t, cert)

	sink := tlsSink(t, config.SyslogSinkConfig{Address: addr, TLSInsecure: true})
	if err := sink.Send(context.Background(), tlsTestEvents); err != nil {
		t.Fatalf("Send with tls_insecure failed: %v", err)
	}
	select {
	case <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not receive a line")
	}
}
```

- [ ] **Step 3: Run to verify they fail**

Run: `go test ./internal/config/ ./internal/export/cbom/sinks/syslog/ -count=1`
Expected: build failure (`TLSInsecure undefined`). After adding only the struct field (Step 4a) and re-running, the server-auth and insecure tests FAIL with `load cert: open : no such file or directory` (the bug), and the config test fails on the "must validate" assertion.

- [ ] **Step 4: Implement**

(a) `internal/config/config_sinks.go`: add the field to `SyslogSinkConfig` (after `KeyFile`):

```go
	// TLSInsecure disables server certificate verification for protocol="tls".
	// Operator opt-in for lab or self-signed receivers; mirrors the Splunk sink.
	TLSInsecure bool `toml:"tls_insecure"`
```

and replace the TLS block in `Validate`:

```go
	if c.Protocol == "tls" && (c.CertFile == "") != (c.KeyFile == "") {
		return fmt.Errorf("%s: cert_file and key_file must be set together for protocol=\"tls\"", location)
	}
```

(b) `internal/export/cbom/sinks/syslog/syslog.go`: in `New`, before the `return &Sink{...}` line:

```go
	if cfg.Protocol == "tls" && cfg.TLSInsecure {
		log.Warn().Str("scope", scopeName).Str("address", cfg.Address).
			Msg("cbom: syslog sink has tls_insecure enabled; the receiver's certificate is NOT verified")
	}
```

and in `dial`, replace the start of the `case "tls":` branch (the `LoadX509KeyPair` call and the `tls.Config` literal) with:

```go
	case "tls":
		serverName, _, _ := net.SplitHostPort(s.cfg.Address)
		tlsCfg := &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: s.cfg.TLSInsecure, //nolint:gosec // operator opt-in, mirrors the Splunk sink
		}
		// A client certificate is optional; Validate guarantees key_file is set
		// whenever cert_file is.
		if s.cfg.CertFile != "" {
			cert, err := tls.LoadX509KeyPair(s.cfg.CertFile, s.cfg.KeyFile)
			if err != nil {
				return fmt.Errorf("load cert: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
```

leaving the `ca_file` handling and dial/handshake code below it unchanged.

- [ ] **Step 5: Document it** — in `docs/configuration.md`, insert this section immediately before `### [pcap]`:

````markdown
### CBOM syslog sink (`[cbom.scopes.sinks.syslog]`)

A CBOM scope can forward per-asset or per-finding events to a syslog receiver:

```toml
[[cbom.scopes]]
name = "prod"

[[cbom.scopes.sinks]]
type = "syslog"

[cbom.scopes.sinks.syslog]
protocol = "tls"                # "udp" | "tcp" | "tls"
address  = "siem.example.com:6514"
format   = "rfc5424"            # "rfc5424" | "cef"
ca_file  = "/etc/cipherflag/siem-ca.pem"   # optional; system roots if unset
# cert_file = "/etc/cipherflag/client.pem" # optional client certificate (mutual TLS)
# key_file  = "/etc/cipherflag/client.key" # required if, and only if, cert_file is set
# tls_insecure = false          # true skips server certificate verification
```

For `protocol = "tls"`:

- Without `cert_file`/`key_file` the sink does server-authenticated TLS only. Set both for mutual TLS; setting only one is a configuration error.
- The receiver's certificate is verified against `ca_file` (or the system roots). `tls_insecure = true` disables that check, which exposes the feed to interception; use it only for lab receivers. A warning is logged when it is on.
````

- [ ] **Step 6: Run to verify they pass**

```bash
gofmt -l internal/config internal/export/cbom/sinks/syslog
go build ./... && go vet ./internal/config/ ./internal/export/cbom/sinks/syslog/
go test ./internal/config/ ./internal/export/cbom/... -count=1
```

Expected: `ok`. Confirm the TOML example parses by checking that `[cbom]`, `scopes`, `name`, `sinks`, `syslog` match the `toml:` tags (`config.go:35,384,389,394,409`).

- [ ] **Step 7: Commit** (after Erik's go)

```bash
git add internal/config/config_sinks.go internal/config/config_sinks_test.go \
  internal/export/cbom/sinks/syslog/syslog.go internal/export/cbom/sinks/syslog/syslog_test.go docs/configuration.md
git commit -m "fix(cbom): syslog TLS works without a client cert; add tls_insecure"
```

---

### Task 11: Release notes, version, and spec reconciliation

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `cmd/cipherflag/main.go` (`const Version`)
- Modify: `docs/superpowers/specs/2026-09-25-cbom-export-completion-design.md`

- [ ] **Step 1: Full verification before touching release files**

```bash
go build ./... && go vet ./...
go test ./... -count=1 2>&1 | grep -v "no test files" | grep -vE '^ok ' ; echo "(no lines above = all packages ok)"
CIPHERFLAG_TEST_DB="postgres://cipherflag:changeme@localhost:5434/cipherflag_test?sslmode=disable" \
  go test -tags integration ./internal/export/cbom/... -count=1
```

Expected: no non-ok lines; integration `ok` with no golden diff. If anything fails, stop; do not write release notes over a red build.

- [ ] **Step 2: Version and changelog** — set `const Version = "2.3.0"` in `cmd/cipherflag/main.go`, and insert this section at the top of `CHANGELOG.md` above the current newest entry. Use the actual release date: run `date +%F` and put its output where `RELEASE_DATE` appears in the heading (do not commit the literal text `RELEASE_DATE`):

```markdown
## [2.3.0] - RELEASE_DATE

### Security
- **Signed BOMs were emitted without their signature on three paths.**
  With `[cbom.signing]` enabled, `GET /api/v1/export/cbom`, the repo-CBOM
  download and the S3 sink wrote `"signature":{}`: the signature was
  computed but lost when the BOM was serialised. The server logged
  "CBOM signing enabled" at startup, so these outputs looked signed. All
  writers now go through one serialiser that keeps the signature, and
  tests verify the signature on every path. Re-download any BOM you
  relied on as signed. (File and HTTP sinks were not affected.)

### Added
- `GET /api/v1/export/cbom/estate`: a CBOM over every scored asset.
- `GET /api/v1/applications/{tag}/cbom`: a CBOM of the assets carrying an
  application tag (`404` when no scored asset carries it).
- Both are readable by any authenticated user and signed when signing is
  enabled.
- Syslog sink: `tls_insecure` option, and `cert_file`/`key_file` are now
  optional for `protocol = "tls"` (server-authenticated TLS). Setting only
  one of the two is a configuration error.

### Fixed
- **`asset_count` overstated BOM contents.** It now equals the number of
  asset components in the BOM. When health reports were dropped because
  their asset no longer exists, `assets_omitted` and `assets_omitted_types`
  properties disclose it.
- Application exports now fail on a mapping error instead of silently
  omitting the asset, matching scope exports.
- CBOM export handlers no longer time out at the server's 30-second write
  limit, no longer discard generation errors silently, and return a real
  `500` if serialisation fails instead of a truncated `200`.

### Notes
- The estate export is assembled in memory with one lookup per asset; very
  large inventories cost memory and time proportional to their size.
```

- [ ] **Step 3: Reconcile the spec** — in `docs/superpowers/specs/2026-09-25-cbom-export-completion-design.md`: change the header line to `Status: implemented; see the plan at docs/superpowers/plans/2026-09-25-cbom-export-completion.md.`; in "Units", change the `bomjson` bullet from `Write(w io.Writer, bom *cdx.BOM) error` to `Encode(bom *cdx.BOM) ([]byte, error)` with the reason ("handlers must buffer the body before sending headers"); and add to the syslog subsection the note that CE had no CBOM sink documentation, so `docs/configuration.md` gained a syslog section rather than an edit.

- [ ] **Step 4: Verify and commit** (after Erik's go on each; two commits)

```bash
go build ./... && go test ./cmd/... -count=1
git add CHANGELOG.md cmd/cipherflag/main.go
git commit -m "chore(release): bump version to 2.3.0; document CBOM export completion"

git add docs/superpowers/specs/2026-09-25-cbom-export-completion-design.md docs/superpowers/plans/2026-09-25-cbom-export-completion.md
git commit -m "docs: reconcile CBOM export completion spec with the implemented design; add plan"
```

- [ ] **Step 5: Stop.** Do not tag or push. Report to Erik: the tag `v2.3.0` and the push need his explicit go (verify `git remote -v` shows `net4n6-dev/cipherflag` and remote `main` is an ancestor of `HEAD` first, as for 2.2.2 and 2.2.3), and tell him the test container `cipherflag-test-db` is still running (`docker stop cipherflag-test-db` when done).
