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
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/net4n6-dev/cipherflag/internal/config"
)

// signingCase is one [cbom.signing] configuration and what every signer
// loader must conclude about it.
type signingCase struct {
	name string
	cfg  config.CBOMSigningConfig
	env  map[string]string
	// wantPub is the public key the loaded signer must carry; nil means
	// no signer (disabled or error).
	wantPub ed25519.PublicKey
	// wantErr lists substrings the error must contain; empty means no error.
	wantErr []string
}

func signingCases(t *testing.T) []signingCase {
	t.Helper()
	dir := t.TempDir()

	rawPath, rawPub := makeEd25519PEM(t)

	pkcs8Pub, pkcs8Priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pkcs8Path := filepath.Join(dir, "pkcs8.pem")
	writePEMFile(t, pkcs8Path, "PRIVATE KEY", mustPKCS8(t, pkcs8Priv))

	// A well-formed PKCS#8 key of the wrong type: the realistic unusable key.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecPath := filepath.Join(dir, "ecdsa.pem")
	writePEMFile(t, ecPath, "PRIVATE KEY", mustPKCS8(t, ecKey))

	missingPath := filepath.Join(dir, "does-not-exist.pem")
	notPEMPath := filepath.Join(dir, "not-pem.key")
	require.NoError(t, os.WriteFile(notPEMPath, []byte("not a key"), 0600))

	envPub, envPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	return []signingCase{
		{
			name: "disabled ignores an unusable path",
			cfg:  config.CBOMSigningConfig{Enabled: false, Signer: "file", Path: missingPath},
		},
		{
			name:    "file signer with a valid raw key",
			cfg:     config.CBOMSigningConfig{Enabled: true, Signer: "file", Path: rawPath},
			wantPub: rawPub,
		},
		{
			name:    "file signer with a standard PKCS#8 Ed25519 key",
			cfg:     config.CBOMSigningConfig{Enabled: true, Signer: "file", Path: pkcs8Path},
			wantPub: pkcs8Pub,
		},
		{
			name:    "file signer with a key the loader rejects names the path",
			cfg:     config.CBOMSigningConfig{Enabled: true, Signer: "file", Path: ecPath},
			wantErr: []string{ecPath, "Ed25519"},
		},
		{
			name:    "file signer with a file that is not PEM names the path",
			cfg:     config.CBOMSigningConfig{Enabled: true, Signer: "file", Path: notPEMPath},
			wantErr: []string{notPEMPath, "no PEM block"},
		},
		{
			name:    "file signer with a missing key names the path",
			cfg:     config.CBOMSigningConfig{Enabled: true, Signer: "file", Path: missingPath},
			wantErr: []string{missingPath},
		},
		{
			name:    "env signer with a valid base64 key",
			cfg:     config.CBOMSigningConfig{Enabled: true, Signer: "env", EnvVar: "CF_TEST_SIGNING_GOOD"},
			env:     map[string]string{"CF_TEST_SIGNING_GOOD": base64.StdEncoding.EncodeToString(envPriv)},
			wantPub: envPub,
		},
		{
			name:    "env signer with the variable unset names the variable",
			cfg:     config.CBOMSigningConfig{Enabled: true, Signer: "env", EnvVar: "CF_TEST_SIGNING_UNSET"},
			wantErr: []string{"CF_TEST_SIGNING_UNSET"},
		},
		{
			name:    "env signer with a malformed value names the variable",
			cfg:     config.CBOMSigningConfig{Enabled: true, Signer: "env", EnvVar: "CF_TEST_SIGNING_BAD"},
			env:     map[string]string{"CF_TEST_SIGNING_BAD": "not base64 !!"},
			wantErr: []string{"CF_TEST_SIGNING_BAD"},
		},
		{
			name:    "unknown signer type names the type",
			cfg:     config.CBOMSigningConfig{Enabled: true, Signer: "kms"},
			wantErr: []string{`"kms"`},
		},
		{
			name:    "enabled with no signer type is an error",
			cfg:     config.CBOMSigningConfig{Enabled: true},
			wantErr: []string{`""`},
		},
	}
}

func setEnv(t *testing.T, env map[string]string) {
	t.Helper()
	for k, v := range env {
		t.Setenv(k, v)
	}
}

func signerPub(t *testing.T, s Signer) ed25519.PublicKey {
	t.Helper()
	if s == nil {
		return nil
	}
	pub, err := s.PublicKey()
	require.NoError(t, err)
	return ed25519.PublicKey(pub)
}

// TestLoadSigner pins the one decision every signing site shares: a
// disabled config yields no signer, a usable key yields a signer carrying
// that key, and anything else is an error that names what the operator
// has to fix.
func TestLoadSigner(t *testing.T) {
	for _, tc := range signingCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			setEnv(t, tc.env)
			s, err := LoadSigner(tc.cfg)
			if len(tc.wantErr) > 0 {
				require.Error(t, err)
				require.Nil(t, s)
				// Exactly once: this error is the whole startup fatal line,
				// and a path or variable repeated by each layer buries the
				// reason.
				for _, want := range tc.wantErr {
					require.Equal(t, 1, strings.Count(err.Error(), want), "%q in %q", want, err.Error())
				}
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantPub, signerPub(t, s))
		})
	}
}

// TestSignerLoadersAgree guards the startup check against drifting from the
// constructors it protects: NewGeneratorWithSigning (the CBOM runtime and
// the download handlers) must reach the same verdict as LoadSigner on every
// configuration, or serve could pass the check and still panic.
func TestSignerLoadersAgree(t *testing.T) {
	for _, tc := range signingCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			setEnv(t, tc.env)
			gen, genErr := NewGeneratorWithSigning(tc.cfg)
			if len(tc.wantErr) > 0 {
				require.Error(t, genErr)
				return
			}
			require.NoError(t, genErr)
			require.Equal(t, tc.wantPub, signerPub(t, gen.signer))
		})
	}
}
