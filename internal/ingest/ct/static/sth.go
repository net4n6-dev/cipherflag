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
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/note"
)

// maxCheckpointSize bounds the input to ParseAndVerifyCheckpoint.
// Real Static CT checkpoints run from ~300 bytes (one ECDSA signature) to
// ~5 KB (ECDSA + an ML-DSA cosignature + GREASE lines); 64 KB gives
// generous headroom while preventing a malformed input from triggering
// unbounded scan work in-process. The HTTP fetcher (fetchCheckpoint) also
// caps reads, so this is belt-and-suspenders.
const maxCheckpointSize = 64 << 10

// STH is the parsed signed-tree-head returned by GET <log_url>checkpoint.
// All three body fields are required; signature verification is part
// of construction (ParseAndVerifyCheckpoint), so an STH value always
// represents an authenticated tree state.
type STH struct {
	Origin   string // first line of the body (log identity = submission prefix)
	TreeSize uint64 // second line of the body
	RootHash []byte // third line, base64-decoded (32 bytes for SHA-256)
}

// sigTypeRFC6962 is the c2sp.org/signed-note signature type identifier of
// RFC6962NoteSignature (static-ct-api checkpoints). (Ed25519 is type
// 0x01; that path is handled by golang.org/x/mod/sumdb/note itself.) The
// type byte is the first byte of the "encoded public key" that is hashed
// into a signature line's 4-byte key ID, so a key ID commits to its
// signature type as well as to the key name and key material.
const sigTypeRFC6962 = 0x05

// TLS 1.2 SignatureAndHashAlgorithm values (RFC 5246 §7.4.1.4.1) used in
// the DigitallySigned wrapper of an RFC6962NoteSignature.
const (
	tlsHashSHA256 = 0x04
	tlsSigECDSA   = 0x03
)

// NoteKeyHash computes the 32-bit key ID that prefixes every signed-note
// signature, per c2sp.org/signed-note and golang.org/x/mod/sumdb/note's
// keyHash:
//
//	keyID = SHA-256(name || "\n" || encodedKey)[:4]   (big-endian uint32)
//
// where encodedKey = sigType || typeSpecificKeyBytes. For Ed25519 the key
// bytes are the 32-byte public key; for RFC6962NoteSignature they are
// SHA-256(DER SubjectPublicKeyInfo). The "\n" separator is load-bearing:
// omitting it (as an earlier version of this file did) yields a key ID
// that matches no real log.
func NoteKeyHash(name string, encodedKey []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write(encodedKey)
	return binary.BigEndian.Uint32(h.Sum(nil))
}

// rfc6962Verifier is a note.Verifier for the RFC6962NoteSignature type
// (0x05) that every production Static CT log (Sunlight, Tessera/Google,
// IPng, TrustAsia, Microsec, …) signs its checkpoint with. The signature
// is not over the note text itself but over the RFC 6962 §3.5
// TreeHeadSignature built from the checkpoint's tree size and root hash,
// so the log's existing RFC 6962 ECDSA P-256 key signs both.
//
// Signature bytes (after note.Open strips the 4-byte key ID):
//
//	uint64 timestamp (ms since epoch)
//	TLS DigitallySigned {
//	    uint8  hash      = 4 (sha256)
//	    uint8  signature = 3 (ecdsa)
//	    opaque signature<0..2^16-1>  (ASN.1 ECDSA-Sig-Value)
//	}
type rfc6962Verifier struct {
	name string
	hash uint32
	pub  *ecdsa.PublicKey
}

func (v *rfc6962Verifier) Name() string    { return v.name }
func (v *rfc6962Verifier) KeyHash() uint32 { return v.hash }

func (v *rfc6962Verifier) Verify(msg, sig []byte) bool {
	cp, err := parseCheckpointBody(msg)
	if err != nil {
		return false
	}
	s := cryptobyte.String(sig)
	var (
		timestamp       uint64
		hashAlg, sigAlg uint8
		der             cryptobyte.String
	)
	if !s.ReadUint64(&timestamp) ||
		!s.ReadUint8(&hashAlg) ||
		!s.ReadUint8(&sigAlg) ||
		!s.ReadUint16LengthPrefixed(&der) ||
		!s.Empty() {
		return false
	}
	if hashAlg != tlsHashSHA256 || sigAlg != tlsSigECDSA {
		return false
	}
	digest := sha256.Sum256(treeHeadSignatureInput(timestamp, cp.TreeSize, cp.RootHash))
	return ecdsa.VerifyASN1(v.pub, digest[:], der)
}

// treeHeadSignatureInput builds the RFC 6962 §3.5 TreeHeadSignature
// structure a log signs for an STH:
//
//	uint8  version        = 0 (v1)
//	uint8  signature_type = 1 (tree_hash)
//	uint64 timestamp
//	uint64 tree_size
//	opaque sha256_root_hash[32]
func treeHeadSignatureInput(timestamp, treeSize uint64, rootHash []byte) []byte {
	b := make([]byte, 0, 2+8+8+len(rootHash))
	b = append(b, 0, 1)
	b = binary.BigEndian.AppendUint64(b, timestamp)
	b = binary.BigEndian.AppendUint64(b, treeSize)
	return append(b, rootHash...)
}

// NewCheckpointVerifier returns a note.Verifier that accepts checkpoint
// signatures by key under the key name origin. The signature type is
// selected by the key's algorithm:
//
//   - ECDSA P-256 → RFC6962NoteSignature (0x05). This is what every log in
//     Google's log_list.json tiled_logs uses.
//   - Ed25519     → plain signed-note Ed25519 (0x01), via
//     golang.org/x/mod/sumdb/note's reference verifier. Not used by any
//     production Static CT log today, but kept so a tlog-checkpoint style
//     log keyed with Ed25519 still verifies.
//
// Because the signature type byte is folded into the key ID, a note line
// of the "other" type can never be routed to this verifier: note.Open
// only hands a line to a verifier whose (name, key ID) pair matches.
func NewCheckpointVerifier(origin string, key *LogPublicKey) (note.Verifier, error) {
	if key == nil {
		return nil, errors.New("static: checkpoint verifier: nil key")
	}
	if !isValidNoteName(origin) {
		return nil, fmt.Errorf("static: checkpoint verifier: invalid origin %q", origin)
	}
	switch pub := key.Key.(type) {
	case *ecdsa.PublicKey:
		spkiHash := sha256.Sum256(key.SPKI)
		enc := append([]byte{sigTypeRFC6962}, spkiHash[:]...)
		return &rfc6962Verifier{name: origin, hash: NoteKeyHash(origin, enc), pub: pub}, nil
	case ed25519.PublicKey:
		vkey, err := note.NewEd25519VerifierKey(origin, pub)
		if err != nil {
			return nil, fmt.Errorf("static: checkpoint verifier: %w", err)
		}
		return note.NewVerifier(vkey)
	default:
		return nil, fmt.Errorf("static: checkpoint verifier: unsupported key type %T", key.Key)
	}
}

// isValidNoteName mirrors golang.org/x/mod/sumdb/note's (unexported)
// isValidName: non-empty valid UTF-8, no Unicode whitespace, no '+'.
func isValidNoteName(name string) bool {
	return name != "" && utf8.ValidString(name) && strings.IndexFunc(name, unicode.IsSpace) < 0 && !strings.Contains(name, "+")
}

// ParseAndVerifyCheckpoint parses a Static CT checkpoint (a
// c2sp.org/signed-note whose body is a c2sp.org/tlog-checkpoint) and
// verifies that it carries a valid signature from key under the key name
// origin. Returns the parsed STH on success; on any failure (parse,
// origin mismatch, no signature from the configured key, bad signature)
// returns nil + an operator-readable error.
//
// Format:
//
//	<origin>
//	<tree-size>
//	<base64-root-hash>
//	<BLANK LINE>
//	— <name> <base64( keyID(4) || signature )>
//	[— <name> <base64(...)> ...]
//
// Signature-line handling is delegated to note.Open, which matches real
// log behaviour: lines whose (name, key ID) is not the configured key —
// GREASE lines (grease.invalid, or the log's own name with a random key
// ID and random-length payload), ML-DSA cosignature/v1 lines, third-party
// witness cosignatures — are skipped regardless of length or order, and
// the note is accepted if the configured key's line verifies. A line that
// does carry the configured key's ID but fails verification is a hard
// error.
//
// The body's origin line must equal origin: for Static CT the note key
// name and the checkpoint origin are both the log's submission prefix
// (static-ct-api), and the RFC6962 signature itself does not cover the
// origin line, so this equality check is what binds it.
func ParseAndVerifyCheckpoint(body []byte, origin string, key *LogPublicKey) (*STH, error) {
	if len(body) > maxCheckpointSize {
		return nil, fmt.Errorf("static: checkpoint: body too large (%d bytes > %d limit)", len(body), maxCheckpointSize)
	}
	// Parse the body first (same split rule as note.Open: the LAST blank
	// line separates text from signatures) so a malformed body is reported
	// as such rather than as a signature failure.
	split := bytes.LastIndex(body, []byte("\n\n"))
	if split < 0 {
		return nil, fmt.Errorf("static: checkpoint: no blank-line separator between body and signatures")
	}
	sth, err := parseCheckpointBody(body[:split+1])
	if err != nil {
		return nil, err
	}
	if sth.Origin != origin {
		return nil, fmt.Errorf("static: checkpoint origin %q does not match configured origin %q", sth.Origin, origin)
	}

	v, err := NewCheckpointVerifier(origin, key)
	if err != nil {
		return nil, err
	}
	if _, err := note.Open(body, note.VerifierList(v)); err != nil {
		var unverified *note.UnverifiedNoteError
		var invalid *note.InvalidSignatureError
		switch {
		case errors.As(err, &unverified):
			return nil, fmt.Errorf("static: checkpoint: no signature line for key %q (key ID %08x) among %d signature line(s) %s; check origin and public_key_pem",
				origin, v.KeyHash(), len(unverified.Note.UnverifiedSigs), describeSigs(unverified.Note.UnverifiedSigs))
		case errors.As(err, &invalid):
			return nil, fmt.Errorf("static: checkpoint signature verification failed for key %q (key ID %08x)", origin, v.KeyHash())
		default:
			return nil, fmt.Errorf("static: checkpoint: %w", err)
		}
	}
	return sth, nil
}

// describeSigs renders the (name, key ID) pairs of unverified signature
// lines for an operator-facing error message.
func describeSigs(sigs []note.Signature) string {
	parts := make([]string, 0, len(sigs))
	for _, s := range sigs {
		parts = append(parts, fmt.Sprintf("%s+%08x", s.Name, s.Hash))
	}
	return "[" + strings.Join(parts, " ") + "]"
}

// parseCheckpointBody parses the three-line checkpoint body text
// (including its trailing newline). Extension lines are rejected: the
// RFC6962 signature covers only tree size and root hash, so any extra
// line would be unauthenticated.
func parseCheckpointBody(text []byte) (*STH, error) {
	if len(text) == 0 || text[len(text)-1] != '\n' {
		return nil, fmt.Errorf("static: checkpoint body: not newline-terminated")
	}
	lines := strings.Split(string(text[:len(text)-1]), "\n")
	if len(lines) != 3 {
		return nil, fmt.Errorf("static: checkpoint body: want 3 lines, got %d", len(lines))
	}
	if lines[0] == "" {
		return nil, fmt.Errorf("static: checkpoint body: empty origin line")
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
	if len(rootHash) != sha256.Size {
		return nil, fmt.Errorf("static: checkpoint body: root hash len = %d, want 32", len(rootHash))
	}
	return &STH{Origin: lines[0], TreeSize: size, RootHash: rootHash}, nil
}
