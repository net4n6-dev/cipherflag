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

package fpreduce

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

func TestLoadAllowlist_EmptyPathReturnsEmpty(t *testing.T) {
	a, err := LoadAllowlist("")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(a.entries) != 0 {
		t.Errorf("expected empty; got %d", len(a.entries))
	}
}

func TestLoadAllowlist_MissingFileReturnsEmpty(t *testing.T) {
	a, err := LoadAllowlist("/definitely/does/not/exist.yaml")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(a.entries) != 0 {
		t.Errorf("expected empty; got %d", len(a.entries))
	}
}

func TestLoadAllowlist_MalformedFailsLoud(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "bad.yaml")
	_ = os.WriteFile(p, []byte("!!!not yaml:::"), 0644)
	_, err := LoadAllowlist(p)
	if err == nil {
		t.Error("expected parse error")
	}
}

func TestLoadAllowlist_LoadsEntries(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "ok.yaml")
	_ = os.WriteFile(p, []byte(`- image_digest: sha256:abc
  path: /etc/ssl/certs/snakeoil.pem
  sha256: sha256:def
  comment: Debian ssl-cert package snakeoil

- image_digest: xyz
  path: /usr/share/doc/libssl-doc/demos/bn/cert.pem
  sha256: 123
`), 0644)
	a, err := LoadAllowlist(p)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(a.entries) != 2 {
		t.Fatalf("len=%d", len(a.entries))
	}
}

func TestAllowed_DigestPrefixNormalized(t *testing.T) {
	a := &Allowlist{entries: []AllowlistEntry{
		{ImageDigest: "sha256:abc", Path: "/p", SHA256: "def"},
	}}
	if !a.Allowed("abc", "/p", "sha256:def") {
		t.Error("digest prefix normalisation failed")
	}
}

func TestAllowed_NoMatch(t *testing.T) {
	a := &Allowlist{entries: []AllowlistEntry{
		{ImageDigest: "abc", Path: "/p", SHA256: "def"},
	}}
	if a.Allowed("abc", "/q", "def") {
		t.Error("path mismatch should not match")
	}
	if a.Allowed("xyz", "/p", "def") {
		t.Error("digest mismatch should not match")
	}
}

func TestApply_SuppressesMatches(t *testing.T) {
	a := &Allowlist{entries: []AllowlistEntry{
		{ImageDigest: "abc", Path: "/p/benign.pem", SHA256: "def"},
	}}
	findings := []finding.FindingRecord{
		{Path: "/p/benign.pem", Fingerprint: "sha256:def"},
		{Path: "/p/suspect.pem", Fingerprint: "sha256:xyz"},
		{Path: "/p/no-hash.pem"}, // skipped because no fingerprint
	}
	out := a.Apply(findings, "sha256:abc")
	if len(out) != 2 {
		t.Errorf("len=%d want 2", len(out))
	}
	for _, f := range out {
		if f.Path == "/p/benign.pem" {
			t.Error("benign match should have been suppressed")
		}
	}
}

func TestApply_EmptyAllowlistPassesThrough(t *testing.T) {
	a := &Allowlist{}
	findings := []finding.FindingRecord{{Path: "/x", Fingerprint: "y"}}
	out := a.Apply(findings, "sha256:any")
	if len(out) != 1 {
		t.Errorf("empty allowlist must pass through; got %d", len(out))
	}
}

func TestAllowed_StripsPlatformSuffix(t *testing.T) {
	a := &Allowlist{entries: []AllowlistEntry{
		{ImageDigest: "sha256:abc", Path: "/p", SHA256: "def"},
	}}
	// AssetID in container mode: "sha256:abc@linux/amd64". Must match
	// the entry that only names the digest.
	if !a.Allowed("sha256:abc@linux/amd64", "/p", "sha256:def") {
		t.Error("@platform suffix should be stripped during normalization")
	}
}
