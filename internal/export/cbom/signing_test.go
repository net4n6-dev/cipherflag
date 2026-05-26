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

package cbom

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

// TestSignBOM_AttachesJSFSignature verifies that SignBOM populates bom.Signature
// with a non-nil JSFSignature block carrying algorithm and a non-empty value.
// Spec ref: docs/superpowers/plans/2026-05-16-l4-d-cbom-depth-pass.md §Task 13, Step 1.
func TestSignBOM_AttachesJSFSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_ = pub
	bom := &cdx.BOM{BOMFormat: "CycloneDX", SpecVersion: cdx.SpecVersion1_6}
	signer := &FileSigner{priv: priv}

	require.NoError(t, SignBOM(bom, signer))
	require.NotNil(t, bom.Signature)
	require.NotNil(t, bom.Signature.JSFSigner)
	require.Equal(t, "Ed25519", bom.Signature.Algorithm)
	require.NotEmpty(t, bom.Signature.Value)
}

// TestSignBOM_VerifyRoundTrip verifies the full sign→strip→re-canonicalize→verify
// cycle: the embedded public key decodes to the original key and the signature
// verifies against the canonical BOM bytes.
// Spec ref: docs/superpowers/plans/2026-05-16-l4-d-cbom-depth-pass.md §Task 13, Step 1.
func TestSignBOM_VerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	bom := &cdx.BOM{BOMFormat: "CycloneDX", SpecVersion: cdx.SpecVersion1_6, Version: 1}
	signer := &FileSigner{priv: priv}

	require.NoError(t, SignBOM(bom, signer))
	require.NotNil(t, bom.Signature)

	// Capture embedded sig + public key, then strip the signature to reconstruct
	// the exact canonical bytes that were signed.
	sigVal := bom.Signature.Value
	embeddedPub := bom.Signature.PublicKey
	bom.Signature = nil
	canonical, err := canonicalizeBOM(bom)
	require.NoError(t, err)

	pubBytes, err := base64.RawURLEncoding.DecodeString(embeddedPub.X)
	require.NoError(t, err)
	sigBytes, err := base64.StdEncoding.DecodeString(sigVal)
	require.NoError(t, err)
	require.True(t, ed25519.Verify(ed25519.PublicKey(pubBytes), canonical, sigBytes),
		"signature must verify against re-canonicalized BOM")
	require.Equal(t, []byte(pub), pubBytes,
		"embedded public key must match the signer's public key")
}

// TestMarshalSignedBOM_SignaturePresent is the regression test for the
// json:"-" bug on cdx.JSFSignature.*JSFSigner: verifies that the production
// emit path (MarshalSignedBOM) preserves the JSF signature block so that a
// signed BOM is not silently stripped of its Algorithm/Value/PublicKey fields
// when serialized to disk or an HTTP response.
//
// Spec ref: docs/superpowers/plans/2026-05-16-l4-d-cbom-depth-pass.md Workstream A.
func TestMarshalSignedBOM_SignaturePresent(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	bom := &cdx.BOM{BOMFormat: "CycloneDX", SpecVersion: cdx.SpecVersion1_6, Version: 1}
	signer := &FileSigner{priv: priv}

	require.NoError(t, SignBOM(bom, signer))
	require.NotNil(t, bom.Signature)

	// Call MarshalSignedBOM — this is the function used by encodeBOM when
	// bom.Signature is set, which covers both FileSink and HTTPSink production paths.
	out, err := MarshalSignedBOM(bom)
	require.NoError(t, err)

	// Parse the output as a raw JSON map to assert the "signature" key survived.
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &fields))

	sigRaw, ok := fields["signature"]
	require.True(t, ok, "signature key must be present in marshaled BOM JSON")

	var sig struct {
		Algorithm string `json:"algorithm"`
		Value     string `json:"value"`
		PublicKey struct {
			X string `json:"x"`
		} `json:"publicKey"`
	}
	require.NoError(t, json.Unmarshal(sigRaw, &sig))
	require.Equal(t, "Ed25519", sig.Algorithm, "algorithm field must be Ed25519")
	require.NotEmpty(t, sig.Value, "value (signature bytes) must be non-empty")
	require.NotEmpty(t, sig.PublicKey.X, "publicKey.x must be non-empty")

	// Verify the embedded public key decodes to the original public key.
	pubBytes, err := base64.RawURLEncoding.DecodeString(sig.PublicKey.X)
	require.NoError(t, err)
	require.Equal(t, []byte(pub), pubBytes, "embedded public key must match signer's public key")
}

// TestMarshalSignedBOM_NilSignature verifies that MarshalSignedBOM returns
// valid JSON without a "signature" key when bom.Signature is nil.
func TestMarshalSignedBOM_NilSignature(t *testing.T) {
	bom := &cdx.BOM{BOMFormat: "CycloneDX", SpecVersion: cdx.SpecVersion1_6}
	out, err := MarshalSignedBOM(bom)
	require.NoError(t, err)

	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &fields))
	_, hasSig := fields["signature"]
	require.False(t, hasSig, "unsigned BOM must not carry a signature key")
}

// TestSignBOM_TamperDetection verifies that mutating a BOM field after signing
// causes the signature to fail verification — the signing covers the canonical
// payload, not just the metadata.
// Spec ref: docs/superpowers/plans/2026-05-16-l4-d-cbom-depth-pass.md §Task 13, Step 1.
func TestSignBOM_TamperDetection(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	bom := &cdx.BOM{BOMFormat: "CycloneDX", SpecVersion: cdx.SpecVersion1_6, Version: 1}
	signer := &FileSigner{priv: priv}
	require.NoError(t, SignBOM(bom, signer))
	require.NotNil(t, bom.Signature)

	// Tamper: change Version after signing; strip sig to re-canonicalize.
	sigVal := bom.Signature.Value
	embeddedPub := bom.Signature.PublicKey
	bom.Version = 2
	bom.Signature = nil
	canonical, err := canonicalizeBOM(bom)
	require.NoError(t, err)

	pubBytes, err := base64.RawURLEncoding.DecodeString(embeddedPub.X)
	require.NoError(t, err)
	sigBytes, err := base64.StdEncoding.DecodeString(sigVal)
	require.NoError(t, err)
	require.False(t, ed25519.Verify(ed25519.PublicKey(pubBytes), canonical, sigBytes),
		"tampered BOM must fail verification")
}
