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

// Package sshkeys scans hosts for SSH keys and reports findings.
package sshkeys

import "time"

// SSHKeyFinding represents a single SSH key discovered on the host.
type SSHKeyFinding struct {
	// KeyType is the canonical key algorithm: rsa, ecdsa, ed25519, dsa.
	KeyType string

	// KeySizeBits is the key size in bits (e.g., 4096 for RSA, 256 for Ed25519).
	KeySizeBits int

	// FingerprintSHA256 is the SSH key fingerprint (e.g., "SHA256:abc123...").
	FingerprintSHA256 string

	// FilePath is the absolute path to the key file.
	FilePath string

	// OwnerUser is the username that owns the key file.
	//
	// Limitation: in the current production scanner, this field is always empty
	// because UID→username resolution is not yet implemented. Tests populate it
	// via the testFiles hook. To be addressed in a follow-up that calls
	// os/user.LookupId on syscall.Stat_t.Uid.
	OwnerUser string

	// IsPrivateKey is true for private keys (id_rsa), false for public keys (id_rsa.pub).
	IsPrivateKey bool

	// IsProtected is true when the private key has a passphrase. Only meaningful for private keys.
	IsProtected bool

	// IsAuthorized is true when the key was found in an authorized_keys file.
	IsAuthorized bool

	// GrantsRoot is true when an authorized_keys entry grants root access (UID 0).
	GrantsRoot bool

	// Comment is the free-text trailing field from ssh-keygen -l -f output
	// (or the authorized_keys line). Empty when the key has no comment.
	// Preserved verbatim — ssh-keygen sometimes emits literal "no comment"
	// which we store as-is rather than normalizing, so downstream inference
	// sees the raw string and can decide what to trust.
	Comment string

	// --- Scanner metadata (not mapped to discovery types) ---

	// FileMode is the file permission bits (e.g., 0600).
	FileMode uint32

	// ModifiedAt is the file modification time.
	ModifiedAt time.Time
}
