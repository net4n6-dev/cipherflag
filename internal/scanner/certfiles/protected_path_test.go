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

package certfiles

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsProtectedPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/etc/ssl/private/key.pem", true},
		{"/etc/pki/tls/private/leaf.pem", true},
		{"/etc/ipsec.d/private/key.pem", true},
		{"/etc/ssl/certs/ca.pem", false},
		{"/tmp/key.pem", false},
	}
	for _, tc := range cases {
		if got := IsProtectedPath(tc.path); got != tc.want {
			t.Errorf("IsProtectedPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestIsProtectedMode_RestrictedMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(p)
	if !IsProtectedMode(info.Mode()) {
		t.Error("mode 0600 should be protected")
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	info, _ = os.Stat(p)
	if IsProtectedMode(info.Mode()) {
		t.Error("mode 0644 should NOT be protected")
	}
}
