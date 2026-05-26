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
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func makeEd25519PEM(t *testing.T) (privPath string, pubKey ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: priv, // raw seed + public, 64 bytes total for ed25519
	})
	dir := t.TempDir()
	privPath = filepath.Join(dir, "signing.key")
	require.NoError(t, os.WriteFile(privPath, privPEM, 0600))
	return privPath, pub
}

func TestFileSigner_RoundTrip(t *testing.T) {
	privPath, pub := makeEd25519PEM(t)
	signer, err := NewFileSigner(privPath)
	require.NoError(t, err)
	require.Equal(t, "Ed25519", signer.Algorithm())

	canonical := []byte(`{"a":1}`)
	sig, err := signer.Sign(canonical)
	require.NoError(t, err)
	require.True(t, ed25519.Verify(pub, canonical, sig))

	pubBytes, err := signer.PublicKey()
	require.NoError(t, err)
	require.Equal(t, []byte(pub), pubBytes,
		"PublicKey() should return the raw ed25519 public key bytes")
}

func TestFileSigner_RejectsMissingFile(t *testing.T) {
	_, err := NewFileSigner("/nonexistent/path/key.pem")
	require.Error(t, err)
}

func TestFileSigner_RejectsNonEd25519(t *testing.T) {
	// Write a PEM with the wrong type → should reject.
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.key")
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1, 2, 3}})
	require.NoError(t, os.WriteFile(badPath, badPEM, 0600))
	_, err := NewFileSigner(badPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Ed25519")
}

func TestEnvSigner_PEMEncoded(t *testing.T) {
	privPath, pub := makeEd25519PEM(t)
	privPEM, err := os.ReadFile(privPath)
	require.NoError(t, err)
	t.Setenv("CIPHERFLAG_TEST_SIGNING_KEY", string(privPEM))

	signer, err := NewEnvSigner("CIPHERFLAG_TEST_SIGNING_KEY")
	require.NoError(t, err)

	canonical := []byte(`hello`)
	sig, err := signer.Sign(canonical)
	require.NoError(t, err)
	require.True(t, ed25519.Verify(pub, canonical, sig))
}

func TestEnvSigner_Base64Raw(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	privB64 := base64.StdEncoding.EncodeToString(priv)
	t.Setenv("CIPHERFLAG_TEST_SIGNING_KEY_B64", privB64)
	signer, err := NewEnvSigner("CIPHERFLAG_TEST_SIGNING_KEY_B64")
	require.NoError(t, err)
	sig, err := signer.Sign([]byte(`hi`))
	require.NoError(t, err)
	require.True(t, ed25519.Verify(pub, []byte(`hi`), sig))
}

func TestEnvSigner_RejectsMissingEnv(t *testing.T) {
	_, err := NewEnvSigner("DEFINITELY_NOT_SET_42")
	require.Error(t, err)
}
