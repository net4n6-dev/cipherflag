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
