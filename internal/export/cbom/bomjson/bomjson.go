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
