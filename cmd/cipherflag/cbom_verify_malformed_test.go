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

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

// verify-cbom reads the signature block from untrusted input. A structurally
// valid signature whose embedded key or algorithm metadata has been altered
// must be rejected with exit 2, never panic (ed25519.Verify panics on a public
// key that is not 32 bytes) and never be treated as Ed25519 when it claims
// something else. The signed content is untouched by these mutations because
// the signature block is stripped before canonicalisation, so any outcome
// other than exit 2 is down to missing validation.
func TestVerifyCBOM_MalformedSignatureBlockExits2(t *testing.T) {
	short := base64.RawURLEncoding.EncodeToString(make([]byte, 16))

	cases := []struct {
		name   string
		mutate func(sig, pub map[string]any)
	}{
		{"public key too short", func(_, pub map[string]any) { pub["x"] = short }},
		{"public key empty", func(_, pub map[string]any) { pub["x"] = "" }},
		{"algorithm not Ed25519", func(sig, _ map[string]any) { sig["algorithm"] = "RS256" }},
		{"kty not OKP", func(_, pub map[string]any) { pub["kty"] = "RSA" }},
		{"crv not Ed25519", func(_, pub map[string]any) { pub["crv"] = "P-256" }},
		{"signature value wrong length", func(sig, _ map[string]any) {
			sig["value"] = base64.StdEncoding.EncodeToString(make([]byte, 10))
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			prefix := filepath.Join(dir, "key")
			require.NoError(t, runGenerateSigningKey(ctx, prefix))

			bom := cdx.BOM{BOMFormat: "CycloneDX", SpecVersion: cdx.SpecVersion1_6, Version: 1}
			raw, err := json.Marshal(bom)
			require.NoError(t, err)
			bomPath := filepath.Join(dir, "test.bom.json")
			require.NoError(t, os.WriteFile(bomPath, raw, 0644))
			require.NoError(t, runSignCBOM(ctx, bomPath, "", prefix+".key"))

			// Rewrite the signature block with the mutation applied.
			signed, err := os.ReadFile(bomPath)
			require.NoError(t, err)
			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(signed, &fields))
			var sig map[string]any
			require.NoError(t, json.Unmarshal(fields["signature"], &sig))
			pub, ok := sig["publicKey"].(map[string]any)
			require.True(t, ok, "signed BOM should carry a publicKey object")
			tc.mutate(sig, pub)
			fields["signature"], err = json.Marshal(sig)
			require.NoError(t, err)
			mutated, err := json.Marshal(fields)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(bomPath, mutated, 0644))

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("verify-cbom panicked on a malformed signature block: %v", r)
				}
			}()
			code, err := runVerifyCBOM(ctx, bomPath, "")
			require.NoError(t, err)
			require.Equal(t, 2, code, "malformed signature block should exit 2")
		})
	}
}
