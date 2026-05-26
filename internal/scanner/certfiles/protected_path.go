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
	"io/fs"
	"strings"
)

// protectedPathPrefixes are Linux paths whose contents are conventionally
// readable only by privileged users; cert files under them are treated as
// strong inferential evidence of private-key holding even without an
// adjacent .key file.
var protectedPathPrefixes = []string{
	"/etc/ssl/private/",
	"/etc/pki/tls/private/",
	"/etc/ipsec.d/private/",
}

// IsProtectedPath returns true if the path is under one of the
// well-known privileged-only directories.
func IsProtectedPath(path string) bool {
	for _, prefix := range protectedPathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// IsProtectedMode returns true if the file's permission bits restrict
// read access to root or a single service user (0600 or 0640).
func IsProtectedMode(mode fs.FileMode) bool {
	perm := mode.Perm()
	return perm == 0o600 || perm == 0o640
}
