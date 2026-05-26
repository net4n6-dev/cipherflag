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

package sshkeys

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/normalize"
	"github.com/net4n6-dev/cipherflag/internal/scanner/executil"
	"github.com/rs/zerolog/log"
)

// Scanner discovers SSH keys on the host.
type Scanner struct {
	runner executil.CommandRunner

	// testFiles overrides file stat lookups for testing. When non-nil, only
	// keys listed here are "discovered" by ScanDirectory.
	testFiles map[string]testFileInfo
}

// testFileInfo provides file metadata for testing without filesystem access.
type testFileInfo struct {
	uid      int
	username string
	mode     uint32
}

// New creates a Scanner with the given command runner.
func New(runner executil.CommandRunner) *Scanner {
	return &Scanner{runner: runner}
}

// StandardDirectories returns the default SSH key scan locations.
func StandardDirectories() []string {
	dirs := []string{"/etc/ssh"}
	entries, err := os.ReadDir("/home")
	if err == nil {
		for _, e := range entries {
			if e.IsDir() {
				dirs = append(dirs, filepath.Join("/home", e.Name(), ".ssh"))
			}
		}
	}
	dirs = append(dirs, "/root/.ssh")
	return dirs
}

// ScanDirectories scans all standard SSH key locations.
func (s *Scanner) ScanDirectories(ctx context.Context) ([]SSHKeyFinding, error) {
	var all []SSHKeyFinding
	for _, dir := range StandardDirectories() {
		findings, err := s.ScanDirectory(ctx, dir)
		if err != nil {
			log.Warn().Err(err).Str("dir", dir).Msg("ssh key scan failed for directory, skipping")
			continue
		}
		all = append(all, findings...)
	}
	return all, nil
}

// ScanDirectory scans a single directory for SSH key files.
func (s *Scanner) ScanDirectory(ctx context.Context, root string) ([]SSHKeyFinding, error) {
	keyFiles := s.discoverKeyFiles(root)

	var findings []SSHKeyFinding
	for _, path := range keyFiles {
		f, err := s.scanKeyFile(ctx, path)
		if err != nil {
			log.Warn().Err(err).Str("path", path).Msg("ssh key scan failed for file, skipping")
			continue
		}
		findings = append(findings, *f)
	}
	return findings, nil
}

// discoverKeyFiles returns paths matching SSH key file patterns in a directory.
func (s *Scanner) discoverKeyFiles(root string) []string {
	if s.testFiles != nil {
		var paths []string
		for path := range s.testFiles {
			if strings.HasPrefix(path, root) {
				paths = append(paths, path)
			}
		}
		return paths
	}

	var paths []string
	patterns := []string{
		filepath.Join(root, "id_*"),
		filepath.Join(root, "ssh_host_*_key"),
	}
	for _, pat := range patterns {
		matches, err := filepath.Glob(pat)
		if err != nil {
			continue
		}
		paths = append(paths, matches...)
	}
	pubPattern := filepath.Join(root, "*.pub")
	pubMatches, _ := filepath.Glob(pubPattern)
	paths = append(paths, pubMatches...)

	seen := make(map[string]bool)
	var unique []string
	for _, p := range paths {
		if !seen[p] {
			seen[p] = true
			unique = append(unique, p)
		}
	}
	return unique
}

// scanKeyFile runs ssh-keygen on a single file and returns a finding.
func (s *Scanner) scanKeyFile(ctx context.Context, path string) (*SSHKeyFinding, error) {
	stdout, _, err := s.runner.Run(ctx, "ssh-keygen", "-l", "-f", path)
	if err != nil {
		return nil, fmt.Errorf("ssh-keygen -l -f %s: %w", path, err)
	}

	bits, fp, comment, keyType, err := parseSSHKeygenOutput(string(stdout))
	if err != nil {
		return nil, err
	}

	isPrivate := isPrivateKeyPath(path)
	isProtected := false
	if isPrivate {
		isProtected = s.checkPassphrase(ctx, path)
	}

	owner, mode := s.getFileInfo(path)
	modTime := s.getModTime(path)

	return &SSHKeyFinding{
		KeyType:           keyType,
		KeySizeBits:       bits,
		FingerprintSHA256: fp,
		FilePath:          path,
		OwnerUser:         owner,
		IsPrivateKey:      isPrivate,
		IsProtected:       isProtected,
		IsAuthorized:      false,
		GrantsRoot:        false,
		Comment:           comment,
		FileMode:          mode,
		ModifiedAt:        modTime,
	}, nil
}

// checkPassphrase tests whether a private key has a passphrase.
// Returns true if the key is passphrase-protected.
func (s *Scanner) checkPassphrase(ctx context.Context, path string) bool {
	_, _, err := s.runner.Run(ctx, "ssh-keygen", "-y", "-P", "", "-f", path)
	return err != nil
}

// parseSSHKeygenOutput parses the output of `ssh-keygen -l -f <file>`.
// Format: "4096 SHA256:abc123 comment with spaces (RSA)".
// The comment field may be absent (len=3) or multi-word (len≥4); we
// preserve whatever lives between the fingerprint and the trailing
// parenthesised type.
func parseSSHKeygenOutput(output string) (bits int, fingerprint string, comment string, keyType string, err error) {
	line := strings.TrimSpace(output)
	if line == "" {
		return 0, "", "", "", fmt.Errorf("empty ssh-keygen output")
	}

	fields := strings.Fields(line)
	if len(fields) < 3 {
		return 0, "", "", "", fmt.Errorf("unexpected ssh-keygen output format: %q", line)
	}

	bits, err = strconv.Atoi(fields[0])
	if err != nil {
		return 0, "", "", "", fmt.Errorf("parse bits %q: %w", fields[0], err)
	}

	fingerprint = fields[1]

	// Last field is (TYPE) — strip parens and normalize.
	rawType := fields[len(fields)-1]
	rawType = strings.TrimPrefix(rawType, "(")
	rawType = strings.TrimSuffix(rawType, ")")
	keyType = normalize.KeyType(rawType)

	// Comment is everything between fingerprint and (TYPE). Empty when
	// ssh-keygen omits the middle (len==3). Multi-word comments
	// (e.g. "deploy bot for payments") are preserved verbatim so
	// downstream inference sees the raw string.
	if len(fields) > 3 {
		comment = strings.Join(fields[2:len(fields)-1], " ")
	}

	return bits, fingerprint, comment, keyType, nil
}

// isPrivateKeyPath returns true for private key file paths.
func isPrivateKeyPath(path string) bool {
	base := filepath.Base(path)
	if strings.HasSuffix(base, ".pub") {
		return false
	}
	if strings.HasPrefix(base, "id_") {
		return true
	}
	if strings.HasPrefix(base, "ssh_host_") && strings.HasSuffix(base, "_key") {
		return true
	}
	return false
}

// getFileInfo returns the owner username and file mode.
func (s *Scanner) getFileInfo(path string) (string, uint32) {
	if s.testFiles != nil {
		if info, ok := s.testFiles[path]; ok {
			return info.username, info.mode
		}
		return "", 0
	}

	info, err := os.Stat(path)
	if err != nil {
		return "", 0
	}
	return "", uint32(info.Mode().Perm())
}

// getModTime returns the modification time, or zero on error or in test mode.
func (s *Scanner) getModTime(path string) time.Time {
	if s.testFiles != nil {
		return time.Time{}
	}
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}
