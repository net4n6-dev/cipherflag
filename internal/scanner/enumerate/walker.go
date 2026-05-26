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

// Package enumerate walks a cloned git working tree and returns a list of
// Blob records — each carrying its content SHA-256, size, and path.
// Detectors in 6.1b-3 consume this list.
package enumerate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Blob struct {
	Path   string // repo-relative
	Size   int64
	SHA256 []byte // 32 bytes
}

func (b Blob) HexSHA() string { return hex.EncodeToString(b.SHA256) }

type Options struct {
	MaxBlobSizeBytes int64 // blobs larger than this are skipped
}

// Walk walks root recursively. Skips .git/ and entries > Options.MaxBlobSizeBytes.
// Symlinks are not followed. Directories are descended into but not recorded.
func Walk(root string, opts Options) ([]Blob, error) {
	var out []Blob
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			if rel == ".git" || strings.HasPrefix(rel, ".git"+string(filepath.Separator)) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if opts.MaxBlobSizeBytes > 0 && info.Size() > opts.MaxBlobSizeBytes {
			return nil
		}
		sum, err := hashFile(path)
		if err != nil {
			return fmt.Errorf("hash %s: %w", rel, err)
		}
		out = append(out, Blob{
			Path:   filepath.ToSlash(rel),
			Size:   info.Size(),
			SHA256: sum,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func hashFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
