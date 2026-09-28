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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// With [cbom.signing] enabled and a key the signer cannot load, serve used
// to get past startup and then panic in whichever CBOM constructor ran
// first (NewRuntime or one of the CBOM download handlers), so under
// `restart: unless-stopped` the container crash-looped. These tests run the
// real binary and require one clean fatal line, before the database is
// touched.

// buildCipherflag compiles this package's binary into a temp dir.
func buildCipherflag(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "cipherflag")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// writePreflightConfig writes a config whose database refuses connections,
// so any run that gets as far as connecting says so in its output.
// extra is appended verbatim.
func writePreflightConfig(t *testing.T, dir, extra string) string {
	t.Helper()
	cfg := `[server]
listen = "127.0.0.1:0"

[storage]
postgres_url = "postgres://x:y@127.0.0.1:1/none?sslmode=disable&connect_timeout=2"

` + extra
	path := filepath.Join(dir, "cipherflag.toml")
	require.NoError(t, os.WriteFile(path, []byte(cfg), 0600))
	return path
}

func fileSigningBlock(keyPath string) string {
	return fmt.Sprintf("[cbom.signing]\nenabled = true\nsigner = \"file\"\npath = %q\n", keyPath)
}

// runCipherflag runs bin with args against configPath and returns its
// combined output and exit code.
func runCipherflag(t *testing.T, bin, configPath string, args ...string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = filepath.Dir(configPath)
	cmd.Env = append(os.Environ(), "CIPHERFLAG_CONFIG="+configPath, "NO_COLOR=1")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("%v did not exit within 60s; output:\n%s", args, out)
	}
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run %v: %v", args, err)
	}
	return string(out), code
}

// requireSigningFatal asserts the run stopped on the signing preflight:
// exit 1 (a Go panic exits 2), one message naming the key and the way out,
// no panic, and no attempt to reach the database.
func requireSigningFatal(t *testing.T, out string, code int, keyRef string) {
	t.Helper()
	if code != 1 {
		t.Errorf("exit code = %d, want 1 (a panic exits 2); output:\n%s", code, out)
	}
	for _, want := range []string{"[cbom.signing]", keyRef, "enabled = false"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q; output:\n%s", want, out)
		}
	}
	for _, bad := range []string{"panic:", "connect to database"} {
		if strings.Contains(out, bad) {
			t.Errorf("output contains %q; output:\n%s", bad, out)
		}
	}
}

// requireReachedDatabase asserts the run got past the signing preflight to
// the database connect.
func requireReachedDatabase(t *testing.T, out string) {
	t.Helper()
	if strings.Contains(out, "[cbom.signing]") {
		t.Errorf("serve stopped on the signing preflight; output:\n%s", out)
	}
	if !strings.Contains(out, "connect to database") {
		t.Errorf("want serve to reach the database connect; output:\n%s", out)
	}
}

func TestSigningPreflight(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the cipherflag binary")
	}
	bin := buildCipherflag(t)

	// The API handlers load the key even when [cbom] enabled is false, so
	// the check must not depend on it; none of these configs set it.
	t.Run("serve stops before the database on an unloadable key file", func(t *testing.T) {
		dir := t.TempDir()
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		der, err := x509.MarshalPKCS8PrivateKey(ecKey)
		require.NoError(t, err)
		key := filepath.Join(dir, "signing.key")
		writeKeyPEM(t, key, "PRIVATE KEY", der)

		out, code := runCipherflag(t, bin, writePreflightConfig(t, dir, fileSigningBlock(key)), "serve")
		requireSigningFatal(t, out, code, key)
	})

	t.Run("serve stops before the database on an unset key variable", func(t *testing.T) {
		dir := t.TempDir()
		const envVar = "CF_TEST_PREFLIGHT_UNSET_KEY"
		t.Setenv(envVar, "") // restores any prior value after the test
		require.NoError(t, os.Unsetenv(envVar))
		block := fmt.Sprintf("[cbom.signing]\nenabled = true\nsigner = \"env\"\nenv_var = %q\n", envVar)

		out, code := runCipherflag(t, bin, writePreflightConfig(t, dir, block), "serve")
		requireSigningFatal(t, out, code, envVar)
	})

	// A preflight that refused every enabled config would pass the cases
	// above; these require a loadable key to get through to the database.
	t.Run("serve gets past the preflight with a raw key", func(t *testing.T) {
		dir := t.TempDir()
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		key := filepath.Join(dir, "signing.key")
		writeKeyPEM(t, key, "PRIVATE KEY", priv)

		out, _ := runCipherflag(t, bin, writePreflightConfig(t, dir, fileSigningBlock(key)), "serve")
		requireReachedDatabase(t, out)

		// The fingerprint operators compare against their out-of-band record
		// is logged whenever signing is enabled, not only when the [cbom]
		// runtime is (this config leaves [cbom] enabled off, and the API
		// download handlers still sign).
		sum := sha256.Sum256(pub)
		require.Contains(t, out, "public_key_sha256="+hex.EncodeToString(sum[:]))
	})

	t.Run("serve gets past the preflight with a standard PKCS#8 key", func(t *testing.T) {
		dir := t.TempDir()
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		require.NoError(t, err)
		key := filepath.Join(dir, "signing.key")
		writeKeyPEM(t, key, "PRIVATE KEY", der)

		out, _ := runCipherflag(t, bin, writePreflightConfig(t, dir, fileSigningBlock(key)), "serve")
		requireReachedDatabase(t, out)
	})

	t.Run("serve ignores an unusable key when signing is disabled", func(t *testing.T) {
		dir := t.TempDir()
		block := fmt.Sprintf("[cbom.signing]\nenabled = false\nsigner = \"file\"\npath = %q\n",
			filepath.Join(dir, "does-not-exist.key"))

		out, _ := runCipherflag(t, bin, writePreflightConfig(t, dir, block), "serve")
		requireReachedDatabase(t, out)
	})
}
