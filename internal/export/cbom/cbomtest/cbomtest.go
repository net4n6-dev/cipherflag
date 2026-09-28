// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
