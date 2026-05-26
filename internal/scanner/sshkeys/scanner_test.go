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
	"os"
	"path/filepath"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/scanner/executil"
)

func TestScanDirectory_ParsesSSHKeygenOutput(t *testing.T) {
	runner := executil.NewTestRunner()
	// ssh-keygen -l -f outputs: bits fingerprint comment (type)
	runner.AddCommand("ssh-keygen -l -f /tmp/testdir/id_rsa", executil.CommandResult{
		Stdout: []byte("4096 SHA256:abcdef1234567890 admin@host (RSA)\n"),
	})
	// Note: double space between "-P" and "-f" is intentional — the empty
	// passphrase arg "" is joined as zero characters by commandKey, leaving
	// just the surrounding spaces.
	runner.AddCommand("ssh-keygen -y -P  -f /tmp/testdir/id_rsa", executil.CommandResult{
		Stderr:   []byte("load failed\n"),
		ExitCode: 255,
	})

	s := New(runner)
	s.testFiles = map[string]testFileInfo{
		"/tmp/testdir/id_rsa": {uid: 1000, username: "admin", mode: 0600},
	}

	findings, err := s.ScanDirectory(context.Background(), "/tmp/testdir")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.KeyType != "rsa" {
		t.Errorf("KeyType = %q, want rsa", f.KeyType)
	}
	if f.KeySizeBits != 4096 {
		t.Errorf("KeySizeBits = %d, want 4096", f.KeySizeBits)
	}
	if f.FingerprintSHA256 != "SHA256:abcdef1234567890" {
		t.Errorf("FingerprintSHA256 = %q", f.FingerprintSHA256)
	}
	if !f.IsProtected {
		t.Error("expected IsProtected = true")
	}
	if !f.IsPrivateKey {
		t.Error("expected IsPrivateKey = true")
	}
	if f.OwnerUser != "admin" {
		t.Errorf("OwnerUser = %q, want admin", f.OwnerUser)
	}
}

func TestScanDirectory_PublicKey(t *testing.T) {
	runner := executil.NewTestRunner()
	runner.AddCommand("ssh-keygen -l -f /tmp/testdir/id_ed25519.pub", executil.CommandResult{
		Stdout: []byte("256 SHA256:xyz789 user@host (ED25519)\n"),
	})

	s := New(runner)
	s.testFiles = map[string]testFileInfo{
		"/tmp/testdir/id_ed25519.pub": {uid: 1000, username: "user", mode: 0644},
	}

	findings, err := s.ScanDirectory(context.Background(), "/tmp/testdir")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.KeyType != "ed25519" {
		t.Errorf("KeyType = %q, want ed25519", f.KeyType)
	}
	if f.IsPrivateKey {
		t.Error("expected IsPrivateKey = false for .pub file")
	}
	if f.IsProtected {
		t.Error("expected IsProtected = false for public key")
	}
}

func TestScanDirectory_UnreadableFileSkipped(t *testing.T) {
	runner := executil.NewTestRunner()
	runner.AddCommand("ssh-keygen -l -f /tmp/testdir/id_rsa", executil.CommandResult{
		Stderr:   []byte("permission denied\n"),
		ExitCode: 1,
	})

	s := New(runner)
	s.testFiles = map[string]testFileInfo{
		"/tmp/testdir/id_rsa": {uid: 0, username: "root", mode: 0600},
	}

	findings, err := s.ScanDirectory(context.Background(), "/tmp/testdir")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (unreadable file should be skipped)", len(findings))
	}
}

func TestScanDirectory_UnprotectedPrivateKey(t *testing.T) {
	runner := executil.NewTestRunner()
	runner.AddCommand("ssh-keygen -l -f /tmp/testdir/id_ecdsa", executil.CommandResult{
		Stdout: []byte("256 SHA256:ecdsa123 user@host (ECDSA)\n"),
	})
	// Exit 0 means no passphrase
	runner.AddCommand("ssh-keygen -y -P  -f /tmp/testdir/id_ecdsa", executil.CommandResult{
		Stdout: []byte("ecdsa-sha2-nistp256 AAAA...\n"),
	})

	s := New(runner)
	s.testFiles = map[string]testFileInfo{
		"/tmp/testdir/id_ecdsa": {uid: 1000, username: "user", mode: 0600},
	}

	findings, err := s.ScanDirectory(context.Background(), "/tmp/testdir")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].IsProtected {
		t.Error("expected IsProtected = false for unprotected key")
	}
}

func TestParseSSHKeygenOutput(t *testing.T) {
	tests := []struct {
		line    string
		bits    int
		fp      string
		comment string
		keyType string
	}{
		{"4096 SHA256:abcdef admin@host (RSA)\n", 4096, "SHA256:abcdef", "admin@host", "rsa"},
		{"256 SHA256:xyz789 user@host (ED25519)\n", 256, "SHA256:xyz789", "user@host", "ed25519"},
		{"384 SHA256:ecdsa384 user@host (ECDSA)\n", 384, "SHA256:ecdsa384", "user@host", "ecdsa"},
		{"1024 SHA256:dsa1024 user@host (DSA)\n", 1024, "SHA256:dsa1024", "user@host", "dsa"},
		// Multi-word comments preserved verbatim so downstream ownership
		// inference sees the raw string.
		{"2048 SHA256:multi deploy bot for payments (RSA)\n", 2048, "SHA256:multi", "deploy bot for payments", "rsa"},
		// "no comment" is ssh-keygen's literal placeholder text; store as-is.
		{"4096 SHA256:nc no comment (RSA)\n", 4096, "SHA256:nc", "no comment", "rsa"},
		// Genuinely absent comment — len==3, no middle field.
		{"4096 SHA256:empty (RSA)\n", 4096, "SHA256:empty", "", "rsa"},
	}

	for _, tt := range tests {
		bits, fp, comment, kt, err := parseSSHKeygenOutput(tt.line)
		if err != nil {
			t.Errorf("parseSSHKeygenOutput(%q): %v", tt.line, err)
			continue
		}
		if bits != tt.bits {
			t.Errorf("bits = %d, want %d", bits, tt.bits)
		}
		if fp != tt.fp {
			t.Errorf("fp = %q, want %q", fp, tt.fp)
		}
		if comment != tt.comment {
			t.Errorf("comment = %q, want %q (line %q)", comment, tt.comment, tt.line)
		}
		if kt != tt.keyType {
			t.Errorf("keyType = %q, want %q", kt, tt.keyType)
		}
	}
}

func TestScanDirectory_ExtractsComment(t *testing.T) {
	runner := executil.NewTestRunner()
	runner.AddCommand("ssh-keygen -l -f /tmp/testdir/id_rsa", executil.CommandResult{
		Stdout: []byte("4096 SHA256:abc alice@ops-01.acme.com (RSA)\n"),
	})
	runner.AddCommand("ssh-keygen -y -P  -f /tmp/testdir/id_rsa", executil.CommandResult{
		Stderr:   []byte("load failed\n"),
		ExitCode: 255,
	})

	s := New(runner)
	s.testFiles = map[string]testFileInfo{
		"/tmp/testdir/id_rsa": {uid: 1000, username: "alice", mode: 0600},
	}

	findings, err := s.ScanDirectory(context.Background(), "/tmp/testdir")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Comment != "alice@ops-01.acme.com" {
		t.Errorf("Comment = %q, want %q", findings[0].Comment, "alice@ops-01.acme.com")
	}
}

func TestDiscoverKeyFiles_RealFilesystem(t *testing.T) {
	tmpDir := t.TempDir()

	// Create SSH key files and one non-key file.
	filesToCreate := []string{
		"id_rsa",
		"id_rsa.pub",
		"id_ed25519",
		"id_ed25519.pub",
		"ssh_host_rsa_key",
		"ssh_host_rsa_key.pub",
		"not_a_key.txt",
	}
	for _, name := range filesToCreate {
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte(""), 0600); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}

	// Use a real Scanner (no testFiles set) so discoverKeyFiles uses the real filesystem.
	s := New(executil.NewTestRunner())
	got := s.discoverKeyFiles(tmpDir)

	// Build a set of returned basenames for order-independent assertion.
	found := make(map[string]bool, len(got))
	for _, p := range got {
		found[filepath.Base(p)] = true
	}

	expectedPresent := []string{
		"id_rsa",
		"id_rsa.pub",
		"id_ed25519",
		"id_ed25519.pub",
		"ssh_host_rsa_key",
		"ssh_host_rsa_key.pub",
	}
	for _, name := range expectedPresent {
		if !found[name] {
			t.Errorf("expected %q in results, not found; got %v", name, got)
		}
	}

	if found["not_a_key.txt"] {
		t.Errorf("not_a_key.txt should not be in results, but was")
	}

	// Assert no duplicates (id_rsa.pub matches both id_* and *.pub patterns).
	seen := make(map[string]bool, len(got))
	for _, p := range got {
		if seen[p] {
			t.Errorf("duplicate path in results: %q", p)
		}
		seen[p] = true
	}
}
