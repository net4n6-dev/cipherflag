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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The signing-key readers accepted only Go's raw key bytes, so a standard
// PKCS#8 private key or SPKI public key (what openssl, HSMs, KMS exports and
// EE 4.11's generate-signing-key produce) was rejected, or in verify-cbom's
// case misread as a different key. Both encodings are accepted now.

func mustPKCS8(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return der
}

func mustSPKI(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	require.NoError(t, err)
	return der
}

func writePEMFile(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0600))
}

func TestParseEd25519PrivateKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// A raw key whose public half does not belong to its seed signs with a
	// public key that no verifier will match.
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	mismatched := append(append([]byte{}, priv[:ed25519.SeedSize]...), otherPub...)

	cases := []struct {
		name    string
		der     []byte
		wantPub ed25519.PublicKey
		wantErr string
	}{
		{name: "raw 64-byte key", der: priv, wantPub: pub},
		{name: "PKCS#8 Ed25519 key", der: mustPKCS8(t, priv), wantPub: pub},
		{name: "PKCS#8 key of another type", der: mustPKCS8(t, ecKey), wantErr: "Ed25519"},
		{name: "raw key whose halves disagree", der: mismatched, wantErr: "public half"},
		{name: "neither encoding", der: make([]byte, 48), wantErr: "48 bytes"},
		{name: "empty", der: nil, wantErr: "0 bytes"},
		{name: "malformed PKCS#8 keeps the parse reason", der: mustPKCS8(t, priv)[:40], wantErr: "data truncated"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseEd25519PrivateKey(tc.der)
			if tc.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Len(t, got, ed25519.PrivateKeySize)
			require.Equal(t, tc.wantPub, got.Public())
		})
	}
}

func TestParseEd25519PublicKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cases := []struct {
		name    string
		der     []byte
		wantPub ed25519.PublicKey
		wantErr string
	}{
		{name: "raw 32-byte key", der: pub, wantPub: pub},
		{name: "SPKI Ed25519 key", der: mustSPKI(t, pub), wantPub: pub},
		{name: "SPKI key of another type", der: mustSPKI(t, &ecKey.PublicKey), wantErr: "Ed25519"},
		{name: "neither encoding", der: make([]byte, 31), wantErr: "31 bytes"},
		{name: "empty", der: nil, wantErr: "0 bytes"},
		{name: "malformed SPKI keeps the parse reason", der: mustSPKI(t, pub)[:40], wantErr: "data truncated"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseEd25519PublicKey(tc.der)
			if tc.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantPub, got)
		})
	}
}

// Each private-key reader accepts the standard encoding: the file signer and
// both env signer paths.
func TestSigningKeyReadersAcceptPKCS8(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, priv)})
	msg := []byte("pkcs8 signing key")

	requireSignsFor := func(t *testing.T, s Signer) {
		t.Helper()
		sig, err := s.Sign(msg)
		require.NoError(t, err)
		require.True(t, ed25519.Verify(pub, msg, sig))
		gotPub, err := s.PublicKey()
		require.NoError(t, err)
		require.Equal(t, []byte(pub), gotPub)
	}

	t.Run("file signer", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "pkcs8.key")
		require.NoError(t, os.WriteFile(p, pkcs8PEM, 0600))
		s, err := NewFileSigner(p)
		require.NoError(t, err)
		requireSignsFor(t, s)
	})

	t.Run("env signer PEM", func(t *testing.T) {
		t.Setenv("CF_TEST_PKCS8_PEM", string(pkcs8PEM))
		s, err := NewEnvSigner("CF_TEST_PKCS8_PEM")
		require.NoError(t, err)
		requireSignsFor(t, s)
	})

	t.Run("env signer base64 DER", func(t *testing.T) {
		t.Setenv("CF_TEST_PKCS8_B64", base64.StdEncoding.EncodeToString(mustPKCS8(t, priv)))
		s, err := NewEnvSigner("CF_TEST_PKCS8_B64")
		require.NoError(t, err)
		requireSignsFor(t, s)
	})
}

// A raw key with mismatched halves was accepted before and produced
// signatures that carry a public key no verifier accepts; every private-key
// reader now refuses it.
func TestSigningKeyReadersRejectInconsistentRawKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	mismatched := append(append([]byte{}, priv[:ed25519.SeedSize]...), otherPub...)

	p := filepath.Join(t.TempDir(), "mismatched.key")
	writePEMFile(t, p, "PRIVATE KEY", mismatched)
	_, err = NewFileSigner(p)
	require.ErrorContains(t, err, "public half")

	t.Setenv("CF_TEST_MISMATCHED_B64", base64.StdEncoding.EncodeToString(mismatched))
	_, err = NewEnvSigner("CF_TEST_MISMATCHED_B64")
	require.ErrorContains(t, err, "public half")
}

func TestLoadTrustedKeys(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	dir := t.TempDir()

	spki := filepath.Join(dir, "spki.pub")
	writePEMFile(t, spki, "PUBLIC KEY", mustSPKI(t, pub))
	raw := filepath.Join(dir, "raw.pub")
	writePEMFile(t, raw, "PUBLIC KEY", pub)
	// The label the signer's "ED25519 PRIVATE KEY" pairs with. verify-cbom
	// accepted any label before LoadTrustedKeys, so refusing this one would
	// break a working setup on upgrade.
	edLabel := filepath.Join(dir, "ed25519-label.pub")
	writePEMFile(t, edLabel, "ED25519 PUBLIC KEY", pub)
	ecPub := filepath.Join(dir, "ec.pub")
	writePEMFile(t, ecPub, "PUBLIC KEY", mustSPKI(t, &ecKey.PublicKey))
	privateKey := filepath.Join(dir, "signing.key")
	writePEMFile(t, privateKey, "PRIVATE KEY", mustPKCS8(t, priv))
	notPEM := filepath.Join(dir, "not.pem")
	require.NoError(t, os.WriteFile(notPEM, []byte("not a key"), 0600))
	missing := filepath.Join(dir, "missing.pub")

	keys, err := LoadTrustedKeys([]string{spki, raw, edLabel})
	require.NoError(t, err)
	require.Equal(t, []ed25519.PublicKey{pub, pub, pub}, keys)

	// Every failure names the file so the operator knows which key to fix.
	for name, tc := range map[string]struct{ path, wantErr string }{
		"ECDSA SPKI":   {ecPub, "Ed25519"},
		"private key":  {privateKey, `expected PUBLIC KEY PEM, got "PRIVATE KEY"`},
		"not PEM":      {notPEM, "no PEM block"},
		"missing file": {missing, "no such file"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadTrustedKeys([]string{spki, tc.path})
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.path)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
