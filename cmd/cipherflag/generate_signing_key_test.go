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
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// generate-signing-key writes a standard PKCS#8 private key and SPKI public
// key, so OpenSSL, HSM and KMS tooling can read what CipherFlag makes. The
// printed fingerprint stays the SHA-256 of the raw 32-byte public key, so
// fingerprints recorded for keys made by earlier versions stay valid.
// Ported from CipherFlag EE (rm:0797).

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	fn()
	require.NoError(t, w.Close())
	var buf bytes.Buffer
	_, err = buf.ReadFrom(r)
	require.NoError(t, err)
	return buf.String()
}

func readPEMBody(t *testing.T, path, wantType string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	block, _ := pem.Decode(raw)
	require.NotNil(t, block, "%s: no PEM block", path)
	require.Equal(t, wantType, block.Type, "%s: PEM block type", path)
	return block.Bytes
}

// generateSigningKey runs generate-signing-key into a temp dir and returns
// the file prefix and the fingerprint it printed.
func generateSigningKey(t *testing.T) (prefix, fingerprint string) {
	t.Helper()
	prefix = filepath.Join(t.TempDir(), "signing")
	var genErr error
	out := captureStdout(t, func() { genErr = runGenerateSigningKey(context.Background(), prefix) })
	require.NoError(t, genErr)
	m := regexp.MustCompile(`Public key SHA-256 fingerprint: ([0-9a-f]{64})`).FindStringSubmatch(out)
	require.NotNil(t, m, "no fingerprint in output:\n%s", out)
	return prefix, m[1]
}

func TestGenerateSigningKeyWritesStandardEncodings(t *testing.T) {
	prefix, fingerprint := generateSigningKey(t)

	key, err := x509.ParsePKCS8PrivateKey(readPEMBody(t, prefix+".key", "PRIVATE KEY"))
	require.NoError(t, err, "private key is not PKCS#8")
	priv, ok := key.(ed25519.PrivateKey)
	require.True(t, ok, "private key is %T, want ed25519.PrivateKey", key)

	pubAny, err := x509.ParsePKIXPublicKey(readPEMBody(t, prefix+".pub", "PUBLIC KEY"))
	require.NoError(t, err, "public key is not SPKI")
	pub, ok := pubAny.(ed25519.PublicKey)
	require.True(t, ok, "public key is %T, want ed25519.PublicKey", pubAny)
	require.Equal(t, priv.Public(), pub, ".pub does not hold the public key of .key")

	info, err := os.Stat(prefix + ".key")
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	sum := sha256.Sum256(pub)
	require.Equal(t, hex.EncodeToString(sum[:]), fingerprint, "fingerprint must be the SHA-256 of the raw 32-byte key")
}

// The fingerprint an operator records at keygen is the one verify-cbom
// reports for a BOM signed with that key, checked on the emitted bytes.
func TestGenerateSigningKeyFingerprintMatchesVerifyCBOM(t *testing.T) {
	ctx := context.Background()
	prefix, fingerprint := generateSigningKey(t)
	bomPath := writeUnsignedBOM(t, t.TempDir())
	require.NoError(t, runSignCBOM(ctx, bomPath, "", prefix+".key"))

	var code int
	var verifyErr error
	out := captureStdout(t, func() { code, verifyErr = runVerifyCBOM(ctx, bomPath, prefix+".pub") })
	require.NoError(t, verifyErr)
	require.Equal(t, 0, code)
	require.Contains(t, out, "Embedded public key SHA-256: "+fingerprint)
}

// OpenSSL, not Go's own parser, reads both files, and the fingerprint
// pipeline documented in docs/configuration.md, run verbatim, matches the
// printed fingerprint.
func TestGenerateSigningKeyOutputReadsWithOpenSSL(t *testing.T) {
	requireOpenSSL(t)
	prefix, fingerprint := generateSigningKey(t)

	runOpenSSL(t, "pkey", "-in", prefix+".key", "-noout")
	runOpenSSL(t, "pkey", "-pubin", "-in", prefix+".pub", "-noout")

	pipeline := "openssl pkey -pubin -in /etc/cipherflag/signing.pub -outform DER | tail -c 32 | sha256sum"
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "configuration.md"))
	require.NoError(t, err)
	require.Contains(t, string(doc), pipeline, "the documented pipeline changed; update this test with it")

	out, err := exec.Command("sh", "-c", strings.Replace(pipeline, "/etc/cipherflag/signing.pub", "'"+prefix+".pub'", 1)).CombinedOutput()
	require.NoError(t, err, "documented pipeline failed:\n%s", out)
	require.Equal(t, fingerprint, strings.Fields(string(out))[0],
		"the documented openssl pipeline must print the fingerprint generate-signing-key printed")
}
