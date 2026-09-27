// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package static

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// maxCheckpointSize bounds the input to ParseAndVerifyCheckpoint.
// A real Static CT checkpoint is well under 1 KB; 64 KB gives generous
// headroom while preventing a malformed input from triggering unbounded
// scan work in-process. The HTTP fetcher in T11 also caps reads, so
// this is belt-and-suspenders.
const maxCheckpointSize = 64 << 10

// STH is the parsed signed-tree-head returned by GET <log_url>/checkpoint.
// All three body fields are required; signature verification is part
// of construction (ParseAndVerifyCheckpoint), so an STH value always
// represents an authenticated tree state.
type STH struct {
	Origin   string // first line of the body (log identity)
	TreeSize uint64 // second line of the body
	RootHash []byte // third line, base64-decoded (32 bytes for SHA-256)
}

// KeyHashEd25519 computes the 4-byte key hash that prefixes a
// signed-note Ed25519 signature. Per the c2sp.org/signed-note spec:
//
//	keyHash = SHA-256(name || 0x01 || publicKey)[:4]
//
// where 0x01 is the Ed25519 algorithm identifier.
func KeyHashEd25519(name string, pub ed25519.PublicKey) []byte {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{0x01})
	h.Write(pub)
	return h.Sum(nil)[:4]
}

// ParseAndVerifyCheckpoint parses a signed-note checkpoint body and
// verifies the Ed25519 signature for the matching key name. Returns
// the parsed STH on success; on any failure (parse, missing key line,
// signature mismatch) returns nil + an operator-readable error.
//
// Format (c2sp.org/signed-note + static-ct-api §1.1.1):
//
//	<origin>
//	<tree-size>
//	<base64-root-hash>
//	<BLANK LINE>
//	— <keyName> <base64( keyHash(4) || sig(64) )>
//	[— <keyName2> <base64(...)> ...]
func ParseAndVerifyCheckpoint(body []byte, pub ed25519.PublicKey, keyName string) (*STH, error) {
	if len(body) > maxCheckpointSize {
		return nil, fmt.Errorf("static: checkpoint: body too large (%d bytes > %d limit)", len(body), maxCheckpointSize)
	}
	// Split body | signatures at the first blank line.
	idx := bytes.Index(body, []byte("\n\n"))
	if idx < 0 {
		return nil, fmt.Errorf("static: checkpoint: no blank-line separator between body and signatures")
	}
	signedBody := body[:idx+1] // include the terminating \n; signers sign body+"\n"
	sigBlock := body[idx+2:]

	// Parse the three-line body.
	scanner := bufio.NewScanner(bytes.NewReader(signedBody))
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("static: checkpoint body: scan: %w", err)
	}
	if len(lines) != 3 {
		return nil, fmt.Errorf("static: checkpoint body: want 3 lines, got %d", len(lines))
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("static: checkpoint body: tree size parse: %w", err)
	}
	// No real CT log will ever reach math.MaxInt64 entries (exabytes of
	// storage) — but bounding it explicitly here, once, makes every
	// downstream int64(sth.TreeSize)/leafIndex conversion in provider.go
	// provably safe (gosec G115) instead of relying on an implicit
	// "logs don't get that big" assumption.
	if size > math.MaxInt64 {
		return nil, fmt.Errorf("static: checkpoint body: tree size %d exceeds int64 range", size)
	}
	rootHash, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return nil, fmt.Errorf("static: checkpoint body: root hash base64: %w", err)
	}
	if len(rootHash) != 32 {
		return nil, fmt.Errorf("static: checkpoint body: root hash len = %d, want 32", len(rootHash))
	}

	// Walk signature lines; find one matching our keyName + verify.
	wantKH := KeyHashEd25519(keyName, pub)
	sigScanner := bufio.NewScanner(bytes.NewReader(sigBlock))
	for sigScanner.Scan() {
		line := sigScanner.Text()
		// Expected: "— <keyName> <base64(keyHash||sig)>"
		// Note: signed-note uses the em-dash (U+2014).
		const prefix = "— "
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		rest := line[len(prefix):]
		spaceIdx := strings.IndexByte(rest, ' ')
		if spaceIdx < 0 {
			continue
		}
		name := rest[:spaceIdx]
		if name != keyName {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(rest[spaceIdx+1:])
		if err != nil {
			return nil, fmt.Errorf("static: checkpoint signature: base64: %w", err)
		}
		if len(raw) != 4+ed25519.SignatureSize {
			return nil, fmt.Errorf("static: checkpoint signature: raw len = %d, want 68", len(raw))
		}
		gotKH := raw[:4]
		sig := raw[4:]
		if !bytes.Equal(gotKH, wantKH) {
			// Wrong key hash — could be a co-signer line we don't care about.
			continue
		}
		if !ed25519.Verify(pub, signedBody, sig) {
			return nil, fmt.Errorf("static: checkpoint signature verification failed for key %q", keyName)
		}
		return &STH{Origin: lines[0], TreeSize: size, RootHash: rootHash}, nil
	}
	if err := sigScanner.Err(); err != nil {
		return nil, fmt.Errorf("static: checkpoint signature: scan: %w", err)
	}
	return nil, fmt.Errorf("static: checkpoint: no signature line for key %q", keyName)
}
