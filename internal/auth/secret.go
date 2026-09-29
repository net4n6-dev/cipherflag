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

package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
)

const (
	// DefaultJWTSecretPath is used when [server] jwt_secret_path is empty.
	DefaultJWTSecretPath = "/var/lib/cipherflag/jwt-secret.key"
	// DefaultSetupTokenPath is used when [server] setup_token_path is empty.
	DefaultSetupTokenPath = "/var/lib/cipherflag/setup-token"

	secretBytes = 32
	tokenChars  = 64 // hex of 32 random bytes
)

// LoadOrCreateSecret returns the per-install session signing key. If path
// exists it is read and must hold at least 32 bytes; otherwise 32 random
// bytes are created there with mode 0600. Creation is atomic and first
// writer wins, so replicas sharing one volume agree on a single key.
func LoadOrCreateSecret(path string) ([]byte, error) {
	return loadOrCreate(path,
		func() ([]byte, error) {
			b := make([]byte, secretBytes)
			_, err := rand.Read(b)
			return b, err
		},
		func(b []byte) ([]byte, error) {
			if len(b) < secretBytes {
				return nil, fmt.Errorf("session secret file %s holds %d bytes, need at least %d: delete it to generate a new one (this signs everyone out)", path, len(b), secretBytes)
			}
			return b, nil
		})
}

// LoadOrCreateToken returns the first-admin setup token: 64 hex characters,
// stored in a 0600 file. Whitespace around an existing value is trimmed.
// A file shorter than 64 characters is rejected so startup fails closed
// rather than running with an empty or guessable token.
func LoadOrCreateToken(path string) (string, error) {
	b, err := loadOrCreate(path,
		func() ([]byte, error) {
			raw := make([]byte, secretBytes)
			if _, err := rand.Read(raw); err != nil {
				return nil, err
			}
			return []byte(hex.EncodeToString(raw)), nil
		},
		func(b []byte) ([]byte, error) {
			t := strings.TrimSpace(string(b))
			if len(t) < tokenChars {
				return nil, fmt.Errorf("setup token file %s holds %d characters, need at least %d: delete the file and restart to generate a new token", path, len(t), tokenChars)
			}
			return []byte(t), nil
		})
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// loadOrCreate reads path if it exists, else writes gen() there atomically.
// validate is applied to whatever ends up on disk.
func loadOrCreate(path string, gen func() ([]byte, error), validate func([]byte) ([]byte, error)) ([]byte, error) {
	if b, err := readExisting(path); err == nil {
		return validate(b)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}
	val, err := gen()
	if err != nil {
		return nil, fmt.Errorf("generate value for %s: %w", path, err)
	}

	// Write the complete value to a temp file first, then link it into place.
	// link(2) fails with EEXIST if path exists, so the first writer wins and
	// path never appears half written. Do not use os.Rename here: it replaces
	// an existing file silently, and two starting processes would each keep a
	// different value in memory.
	tmp, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return nil, fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(val); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("write %s: %w", tmp.Name(), err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("sync %s: %w", tmp.Name(), err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("close %s: %w", tmp.Name(), err)
	}

	if err := os.Link(tmp.Name(), path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			b, rerr := readExisting(path)
			if rerr != nil {
				return nil, rerr
			}
			return validate(b)
		}
		return nil, linkError(path, err)
	}
	return validate(val)
}

// linkError explains a failed link(2) install. The directory must sit on a
// filesystem that supports hard links.
func linkError(path string, err error) error {
	return fmt.Errorf("install %s: %w (the directory must be on a filesystem that supports hard links, such as local disk or a Docker named volume)", path, err)
}

// readExisting reads path and warns when it is readable by group or others.
func readExisting(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		log.Warn().Str("path", path).Str("mode", fmt.Sprintf("%o", fi.Mode().Perm())).
			Msg("file is accessible by group or others; restrict it to mode 0600")
	}
	return b, nil
}
