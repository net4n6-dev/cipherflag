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
	"encoding/base64"
	"encoding/json"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// jsfPublicKeyJSON mirrors cdx.JSFPublicKey with proper json tags for OKP key
// material. Used by MarshalSignedBOM to inject the signature block into the
// raw JSON map, working around cdx.JSFSignature's json:"-" tag on *JSFSigner.
type jsfPublicKeyJSON struct {
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	X   string `json:"x"`
}

// jsfSignatureJSON is the serializable representation of a JSF single-signer
// block. It serializes as the "signature" field value inside the BOM JSON
// object. Kept in this package so both the production emit path (sink.go) and
// the CLI (cbom_sign.go) share one definition.
type jsfSignatureJSON struct {
	Algorithm string           `json:"algorithm"`
	Value     string           `json:"value"`
	PublicKey jsfPublicKeyJSON `json:"publicKey"`
}

// MarshalSignedBOM serializes bom to JSON, preserving the JSF signature block
// even though cdx.JSFSignature embeds *JSFSigner with json:"-" (which causes
// standard json.Marshal to silently drop Algorithm/Value/PublicKey).
//
// When bom.Signature is nil the function falls back to a plain json.Marshal of
// bom and returns those bytes unchanged — callers do not need to branch.
//
// Algorithm:
//  1. Marshal the full BOM (drops signature fields due to json:"-").
//  2. If bom.Signature != nil, unmarshal into map[string]json.RawMessage,
//     inject a hand-built "signature" key, and re-marshal.
//
// The resulting JSON is compact (no indentation). Callers that need pretty
// output should json.Indent the result.
func MarshalSignedBOM(bom *cdx.BOM) ([]byte, error) {
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

// SignBOM attaches a JSF (JSON Signature Format) detached signature to bom.
// It:
//  1. Clears any existing bom.Signature so the canonical payload is signature-free.
//  2. Marshals the BOM to JSON and runs JCS (RFC 8785) canonicalization via
//     canonicalizeBOM.
//  3. Signs the canonical bytes with signer.
//  4. Embeds the algorithm identifier, base64-encoded signature value, and the
//     raw public key (JWK OKP encoding) in bom.Signature.
//
// The embedded public key lets verifiers reconstruct canonical bytes and check
// the signature without an out-of-band key distribution step — while operators
// SHOULD compare public_key_sha256 at startup against their trusted copy.
//
// Spec ref: docs/superpowers/plans/2026-05-16-l4-d-cbom-depth-pass.md §Task 13.
func SignBOM(bom *cdx.BOM, signer Signer) error {
	// Nullify existing signature so it is not included in the canonical payload.
	bom.Signature = nil

	canonical, err := canonicalizeBOM(bom)
	if err != nil {
		return fmt.Errorf("cbom: sign: canonicalize: %w", err)
	}

	sig, err := signer.Sign(canonical)
	if err != nil {
		return fmt.Errorf("cbom: sign: %w", err)
	}

	pub, err := signer.PublicKey()
	if err != nil {
		return fmt.Errorf("cbom: sign: public key: %w", err)
	}

	// JSFSignature embeds *JSFSigner (promoted fields). We set the embedded
	// JSFSigner to carry Algorithm, Value, and PublicKey. PublicKey uses the
	// JWK OKP encoding: kty="OKP", crv="Ed25519", x=base64url(raw public key).
	bom.Signature = &cdx.JSFSignature{
		JSFSigner: &cdx.JSFSigner{
			Algorithm: signer.Algorithm(),
			Value:     base64.StdEncoding.EncodeToString(sig),
			PublicKey: cdx.JSFPublicKey{
				KTY: "OKP",
				CRV: "Ed25519",
				X:   base64.RawURLEncoding.EncodeToString(pub),
			},
		},
	}
	return nil
}

// canonicalizeBOM marshals bom to JSON and returns the RFC 8785 canonical form.
// The caller is responsible for ensuring bom.Signature is nil before calling
// this function if a signature-free canonical payload is needed.
func canonicalizeBOM(bom *cdx.BOM) ([]byte, error) {
	raw, err := json.Marshal(bom)
	if err != nil {
		return nil, fmt.Errorf("cbom: marshal: %w", err)
	}
	return Canonicalize(raw)
}
