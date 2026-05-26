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
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestGenerateSigningKey_WritesValidKeypair(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "test")
	require.NoError(t, runGenerateSigningKey(context.Background(), prefix))
	require.FileExists(t, prefix+".key")
	require.FileExists(t, prefix+".pub")

	// Verify the private file has mode 0600.
	info, err := os.Stat(prefix + ".key")
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())

	// Verify the keypair is consistent (signature with priv verifies with pub).
	privPEM, err := os.ReadFile(prefix + ".key")
	require.NoError(t, err)
	privBlock, _ := pem.Decode(privPEM)
	require.NotNil(t, privBlock)
	priv := ed25519.PrivateKey(privBlock.Bytes)

	pubPEM, err := os.ReadFile(prefix + ".pub")
	require.NoError(t, err)
	pubBlock, _ := pem.Decode(pubPEM)
	require.NotNil(t, pubBlock)
	pub := ed25519.PublicKey(pubBlock.Bytes)

	sig := ed25519.Sign(priv, []byte("test"))
	require.True(t, ed25519.Verify(pub, []byte("test"), sig))
}

func TestSignAndVerifyCBOM_RoundTrip(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	prefix := filepath.Join(dir, "key")
	require.NoError(t, runGenerateSigningKey(ctx, prefix))

	// Write an unsigned BOM.
	bom := cdx.BOM{BOMFormat: "CycloneDX", SpecVersion: cdx.SpecVersion1_6, Version: 1}
	raw, err := json.Marshal(bom)
	require.NoError(t, err)
	bomPath := filepath.Join(dir, "test.bom.json")
	require.NoError(t, os.WriteFile(bomPath, raw, 0644))

	// Sign.
	require.NoError(t, runSignCBOM(ctx, bomPath, "" /* in-place */, prefix+".key"))

	// Verify with the matching trusted key — exit 0.
	code, err := runVerifyCBOM(ctx, bomPath, prefix+".pub")
	require.NoError(t, err)
	require.Equal(t, 0, code)

	// Verify with a wrong key — exit 1.
	wrongPrefix := filepath.Join(dir, "wrong")
	require.NoError(t, runGenerateSigningKey(ctx, wrongPrefix))
	code, err = runVerifyCBOM(ctx, bomPath, wrongPrefix+".pub")
	require.NoError(t, err)
	require.Equal(t, 1, code, "valid sig but untrusted key should exit 1")
}

func TestVerifyCBOM_TamperedBOMFails(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	prefix := filepath.Join(dir, "key")
	require.NoError(t, runGenerateSigningKey(ctx, prefix))

	bom := cdx.BOM{BOMFormat: "CycloneDX", SpecVersion: cdx.SpecVersion1_6, Version: 1}
	raw, _ := json.Marshal(bom)
	bomPath := filepath.Join(dir, "test.bom.json")
	require.NoError(t, os.WriteFile(bomPath, raw, 0644))
	require.NoError(t, runSignCBOM(ctx, bomPath, "", prefix+".key"))

	// Tamper: change Version after signing.
	signed, _ := os.ReadFile(bomPath)
	var signedBom cdx.BOM
	require.NoError(t, json.Unmarshal(signed, &signedBom))
	signedBom.Version = 999
	tampered, _ := json.Marshal(signedBom)
	require.NoError(t, os.WriteFile(bomPath, tampered, 0644))

	code, err := runVerifyCBOM(ctx, bomPath, prefix+".pub")
	require.NoError(t, err)
	require.Equal(t, 2, code, "tampered BOM should exit 2 (sig invalid)")
}
