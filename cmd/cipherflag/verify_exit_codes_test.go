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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// verify-cbom documents 0 (valid), 1 (valid, signed by a different key) and
// 2 (invalid). A run that could not verify anything (bad usage, help, an
// unreadable file, an unloadable trusted key) used to exit 0, 1 or 2 as
// well, so a script read it as a verdict. It now exits exitCouldNotVerify
// (3). Ported from CipherFlag EE (rm:0798).

func TestRunVerifyCBOM_ReturnsCouldNotVerify(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist")
	rawKey, _, _, _ := ed25519KeyFiles(t, dir)
	bomPath := writeUnsignedBOM(t, dir)
	require.NoError(t, runSignCBOM(ctx, bomPath, "", rawKey))

	cases := []struct {
		name, bom, trusted, wantErr string
	}{
		{"unreadable BOM", missing, "", "read BOM"},
		{"unreadable trusted key", bomPath, missing, missing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, err := runVerifyCBOM(ctx, tc.bom, tc.trusted)
			require.Error(t, err, "want an error saying what could not be done")
			require.Contains(t, err.Error(), tc.wantErr)
			require.Equal(t, 3, code, "could not verify")
		})
	}
}

// A signed BOM edited to carry a number JSON accepts but RFC 8785 cannot
// canonicalise (it overflows float64) has no canonical form, so no valid
// signature can cover it: the signer canonicalises with the same code. It is
// invalid (2), not a failure to run (3); otherwise an attacker could turn
// "reject this tampered BOM" into "the tool could not run" at will.
func TestRunVerifyCBOM_UncanonicalisableBOMIsInvalid(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	rawKey, rawPub, _, _ := ed25519KeyFiles(t, dir)
	bomPath := writeUnsignedBOM(t, dir)
	require.NoError(t, runSignCBOM(ctx, bomPath, "", rawKey))

	signed := mustReadFile(t, bomPath)
	uncanonical := filepath.Join(dir, "uncanonical.json")
	edited := bytes.Replace(signed, []byte(`"version"`), []byte(`"x": 1e400, "version"`), 1)
	require.NotEqual(t, signed, edited, "edit must change the BOM")
	require.NoError(t, os.WriteFile(uncanonical, edited, 0644))

	for _, trusted := range []string{"", rawPub} {
		code, err := runVerifyCBOM(ctx, uncanonical, trusted)
		require.NoError(t, err)
		require.Equal(t, 2, code, "trusted key %q", trusted)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return b
}

// The command-line wrapper calls os.Exit, so it is tested on the binary.
func TestVerifyCBOMCommandExitCodes(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the cipherflag binary")
	}
	bin := buildCipherflag(t)
	dir := t.TempDir()
	// verify-cbom does not read the server config; any path will do.
	cfg := filepath.Join(dir, "unused.toml")
	missing := filepath.Join(dir, "does-not-exist.json")

	// A real signed BOM, made with the binary itself, so the harness is
	// shown to observe 0, 1 and 2 as well as 3.
	prefix := filepath.Join(dir, "signing")
	if out, code := runCipherflag(t, bin, cfg, "generate-signing-key", "--out", prefix); code != 0 {
		t.Fatalf("generate-signing-key exit %d: %s", code, out)
	}
	other := filepath.Join(dir, "other")
	if out, code := runCipherflag(t, bin, cfg, "generate-signing-key", "--out", other); code != 0 {
		t.Fatalf("generate-signing-key exit %d: %s", code, out)
	}
	bom := writeUnsignedBOM(t, dir)
	signed := filepath.Join(dir, "signed.json")
	if out, code := runCipherflag(t, bin, cfg, "sign-cbom", "--bom", bom, "--key", prefix+".key", "--out", signed); code != 0 {
		t.Fatalf("sign-cbom exit %d: %s", code, out)
	}
	pub := prefix + ".pub"
	signedBytes, err := os.ReadFile(signed)
	require.NoError(t, err)
	tampered := filepath.Join(dir, "tampered.json")
	require.NoError(t, os.WriteFile(tampered, bytes.Replace(signedBytes, []byte(`"version": 1`), []byte(`"version": 2`), 1), 0644))
	require.NotEqual(t, signedBytes, mustReadFile(t, tampered), "tamper must change the BOM")
	malformed := filepath.Join(dir, "malformed.json")
	require.NoError(t, os.WriteFile(malformed, []byte(`{"bomFormat": "CycloneDX",`), 0644))

	cases := []struct {
		name string
		args []string
		want int
	}{
		// Controls: real verdicts, so a "return 3 everywhere" bug fails.
		{"valid and trusted", []string{"verify-cbom", "--bom", signed, "--trusted-key", pub}, 0},
		{"valid, self-attest", []string{"verify-cbom", "--bom", signed}, 0},
		{"valid but signed by a different key", []string{"verify-cbom", "--bom", signed, "--trusted-key", other + ".pub"}, 1},
		{"unsigned BOM is invalid", []string{"verify-cbom", "--bom", bom}, 2},
		{"tampered BOM is invalid", []string{"verify-cbom", "--bom", tampered, "--trusted-key", pub}, 2},
		{"malformed JSON is invalid", []string{"verify-cbom", "--bom", malformed}, 2},

		{"without --bom", []string{"verify-cbom"}, 3},
		{"positional form the README used to document", []string{"verify-cbom", signed}, 3},
		{"positional form with a trusted key", []string{"verify-cbom", signed, "--trusted-key", pub}, 3},
		{"-h", []string{"verify-cbom", "-h"}, 3},
		{"--help", []string{"verify-cbom", "--help"}, 3},
		{"unknown flag", []string{"verify-cbom", "--trusted_key", pub, "--bom", signed}, 3},
		{"missing BOM file", []string{"verify-cbom", "--bom", missing}, 3},
		{"missing trusted key", []string{"verify-cbom", "--bom", signed, "--trusted-key", missing}, 3},
		{"private key as trusted key", []string{"verify-cbom", "--bom", signed, "--trusted-key", prefix + ".key"}, 3},
		// A stray argument means the invocation is not what the caller
		// thinks it is. It points at a real signed BOM with the right key,
		// so the only reason to exit 3 is the stray argument itself.
		{"extra argument", []string{"verify-cbom", "--bom", signed, "--trusted-key", pub, "stray"}, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code := runCipherflag(t, bin, cfg, tc.args...)
			if code != tc.want {
				t.Errorf("exit code = %d, want %d; output:\n%s", code, tc.want, out)
			}
			if tc.want == 3 && strings.Contains(out, "Signature valid") {
				t.Errorf("a could-not-verify run printed a verdict; output:\n%s", out)
			}
		})
	}
}
