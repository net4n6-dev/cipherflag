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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

// Key-format interop for sign-cbom and verify-cbom. verify-cbom used to cast
// the trusted-key PEM body straight to a key, so a standard SPKI .pub (from
// openssl, or from EE 4.11's generate-signing-key) was read as a 44-byte
// "key", never matched, and a genuine BOM was reported as a trust mismatch.

func writeKeyPEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0600))
}

// writeUnsignedBOM writes a minimal CycloneDX BOM and returns its path.
func writeUnsignedBOM(t *testing.T, dir string) string {
	t.Helper()
	raw, err := json.Marshal(cdx.BOM{BOMFormat: "CycloneDX", SpecVersion: cdx.SpecVersion1_6, Version: 1})
	require.NoError(t, err)
	p := filepath.Join(dir, "test.bom.json")
	require.NoError(t, os.WriteFile(p, raw, 0644))
	return p
}

// ed25519KeyFiles generates a keypair and writes it in both encodings:
// raw.key/raw.pub (Go's raw bytes) and std.key/std.pub (PKCS#8/SPKI).
func ed25519KeyFiles(t *testing.T, dir string) (rawKey, rawPub, stdKey, stdPub string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	spki, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	rawKey, rawPub = filepath.Join(dir, "raw.key"), filepath.Join(dir, "raw.pub")
	stdKey, stdPub = filepath.Join(dir, "std.key"), filepath.Join(dir, "std.pub")
	writeKeyPEM(t, rawKey, "PRIVATE KEY", priv)
	writeKeyPEM(t, rawPub, "PUBLIC KEY", pub)
	writeKeyPEM(t, stdKey, "PRIVATE KEY", pkcs8)
	writeKeyPEM(t, stdPub, "PUBLIC KEY", spki)
	return rawKey, rawPub, stdKey, stdPub
}

// Every signing-key encoding verifies against every trusted-key encoding of
// the same key, and a different SPKI key is still a trust mismatch.
func TestVerifyCBOM_KeyEncodingMatrix(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	rawKey, rawPub, stdKey, stdPub := ed25519KeyFiles(t, dir)
	_, _, _, otherStdPub := ed25519KeyFiles(t, t.TempDir())

	for _, signKey := range []string{rawKey, stdKey} {
		for _, trusted := range []string{rawPub, stdPub} {
			t.Run(filepath.Base(signKey)+" verified by "+filepath.Base(trusted), func(t *testing.T) {
				bomPath := writeUnsignedBOM(t, t.TempDir())
				require.NoError(t, runSignCBOM(ctx, bomPath, "", signKey))
				code, err := runVerifyCBOM(ctx, bomPath, trusted)
				require.NoError(t, err)
				require.Equal(t, 0, code)

				code, err = runVerifyCBOM(ctx, bomPath, otherStdPub)
				require.NoError(t, err)
				require.Equal(t, 1, code, "a different SPKI key must still be a trust mismatch")
			})
		}
	}
}

// A trusted key that is not an Ed25519 public key is a load error naming the
// file, not a trust-mismatch verdict against garbage bytes.
func TestVerifyCBOM_NonEd25519TrustedKeyIsAnError(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	rawKey, _, _, _ := ed25519KeyFiles(t, dir)
	bomPath := writeUnsignedBOM(t, dir)
	require.NoError(t, runSignCBOM(ctx, bomPath, "", rawKey))

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecSPKI, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	require.NoError(t, err)
	ecPub := filepath.Join(dir, "ec.pub")
	writeKeyPEM(t, ecPub, "PUBLIC KEY", ecSPKI)

	_, err = runVerifyCBOM(ctx, bomPath, ecPub)
	require.Error(t, err)
	require.Contains(t, err.Error(), ecPub)
	require.Contains(t, err.Error(), "Ed25519")
}

// requireOpenSSL skips when openssl is missing, except in CI: these are the
// only tests that feed CipherFlag a key made by another tool, and a silent
// skip there would report green while proving nothing.
func requireOpenSSL(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("openssl is required in CI for the Ed25519 key-format interop tests")
		}
		t.Skip("openssl not on PATH")
	}
}

func runOpenSSL(t *testing.T, args ...string) []byte {
	t.Helper()
	out, err := exec.Command("openssl", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl %v: %v\n%s", args, err, out)
	}
	return out
}

// A keypair made by openssl signs through sign-cbom and verifies as trusted
// through verify-cbom against its openssl public key.
func TestOpenSSLKeypair_SignAndVerifyCBOM(t *testing.T) {
	requireOpenSSL(t)
	ctx := context.Background()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "signing.key")
	pubPath := filepath.Join(dir, "signing.pub")
	runOpenSSL(t, "genpkey", "-algorithm", "ed25519", "-out", keyPath)
	runOpenSSL(t, "pkey", "-in", keyPath, "-pubout", "-out", pubPath)

	bomPath := writeUnsignedBOM(t, dir)
	require.NoError(t, runSignCBOM(ctx, bomPath, "", keyPath))
	code, err := runVerifyCBOM(ctx, bomPath, pubPath)
	require.NoError(t, err)
	require.Equal(t, 0, code, "a BOM signed with an openssl key must verify as trusted against its openssl public key")
}
