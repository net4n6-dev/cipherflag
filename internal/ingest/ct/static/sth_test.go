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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/note"
)

// ---------------------------------------------------------------------
// Ground truth: real checkpoints from every production Static CT log.
//
// testdata/real_checkpoints/ holds the /checkpoint body of every
// tiled_logs entry in Google's log_list.json (38 logs across Google,
// Let's Encrypt, Geomys, IPng, TrustAsia and Microsec), fetched
// 2026-09-27, plus logs.json carrying each log's origin (from
// submission_url) and public key (verbatim from log_list.json). These are
// what keep this verifier honest: an earlier version passed its own
// self-signed fixtures while rejecting 38/38 real checkpoints, because
// the fixture signer shared the verifier's wrong assumptions.
// ---------------------------------------------------------------------

type realLogFixture struct {
	Operator      string `json:"operator"`
	Origin        string `json:"origin"`
	MonitoringURL string `json:"monitoring_url"`
	SubmissionURL string `json:"submission_url"`
	Key           string `json:"key"` // base64 DER SPKI, verbatim from log_list.json
	File          string `json:"file"`
}

func loadRealLogFixtures(t *testing.T) []realLogFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "real_checkpoints", "logs.json"))
	if err != nil {
		t.Fatalf("read logs.json: %v", err)
	}
	var doc struct {
		Logs []realLogFixture `json:"logs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse logs.json: %v", err)
	}
	if len(doc.Logs) < 30 {
		t.Fatalf("logs.json has %d logs, want the full tiled_logs set (38)", len(doc.Logs))
	}
	return doc.Logs
}

func (f realLogFixture) checkpoint(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "real_checkpoints", f.File))
	if err != nil {
		t.Fatalf("read %s: %v", f.File, err)
	}
	return b
}

func (f realLogFixture) spki(t *testing.T) []byte {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(f.Key)
	if err != nil {
		t.Fatalf("%s: key base64: %v", f.Origin, err)
	}
	return der
}

func (f realLogFixture) pem(t *testing.T) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: f.spki(t)}))
}

func (f realLogFixture) key(t *testing.T) *LogPublicKey {
	t.Helper()
	k, err := ParseLogPublicKeyPEM(f.pem(t))
	if err != nil {
		t.Fatalf("%s: ParseLogPublicKeyPEM: %v", f.Origin, err)
	}
	return k
}

// Every real production checkpoint verifies against its log-list key and
// origin. This is the regression test for all four checkpoint findings at
// once (ECDSA/RFC6962 signature type, GREASE early exit, key-ID newline,
// origin vs monitoring host).
func TestParseAndVerifyCheckpoint_RealProductionLogs(t *testing.T) {
	for _, f := range loadRealLogFixtures(t) {
		t.Run(f.Origin, func(t *testing.T) {
			// Also exercise the operator-facing validator with the exact
			// values an operator copies out of log_list.json.
			if err := ValidateDomainConfig("example.com", f.MonitoringURL, f.Origin, f.pem(t)); err != nil {
				t.Fatalf("ValidateDomainConfig: %v", err)
			}
			sth, err := ParseAndVerifyCheckpoint(f.checkpoint(t), f.Origin, f.key(t))
			if err != nil {
				t.Fatalf("ParseAndVerifyCheckpoint: %v", err)
			}
			if sth.Origin != f.Origin || sth.TreeSize == 0 || len(sth.RootHash) != 32 {
				t.Errorf("STH = {%q, %d, %d-byte root}", sth.Origin, sth.TreeSize, len(sth.RootHash))
			}
		})
	}
}

// rfc6962LineFor returns the decoded payload of the checkpoint signature
// line that is the log's RFC6962NoteSignature, identified purely
// structurally (independent of the production code): name == origin and
// payload = keyID(4) || ts(8) || 0x04 0x03 || uint16 len || DER of that
// exact length. Also returns how many same-name lines precede it that do
// NOT have this shape (GREASE / ML-DSA cosignatures).
func rfc6962LineFor(t *testing.T, cp []byte, origin string) (payload []byte, sameNameBefore int) {
	t.Helper()
	_, sigs, ok := bytes.Cut(cp, []byte("\n\n"))
	if !ok {
		t.Fatalf("%s: no signature block", origin)
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(sigs), "\n"), "\n") {
		name, b64, _ := strings.Cut(strings.TrimPrefix(line, "— "), " ")
		if name != origin {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err == nil && len(raw) >= 16 && raw[12] == 0x04 && raw[13] == 0x03 &&
			int(binary.BigEndian.Uint16(raw[14:16])) == len(raw)-16 {
			return raw, sameNameBefore
		}
		sameNameBefore++
	}
	t.Fatalf("%s: no RFC6962NoteSignature-shaped line", origin)
	return nil, 0
}

// Finding #3 against real data: the key ID on each log's real signature
// line is SHA-256(origin || "\n" || 0x05 || SHA-256(SPKI))[:4] — computed
// here inline, independently of NoteKeyHash — and NOT the newline-less
// variant an earlier version of this file used.
func TestRealCheckpoints_KeyIDFormula(t *testing.T) {
	for _, f := range loadRealLogFixtures(t) {
		t.Run(f.Origin, func(t *testing.T) {
			payload, _ := rfc6962LineFor(t, f.checkpoint(t), f.Origin)
			spkiHash := sha256.Sum256(f.spki(t))

			withNL := sha256.Sum256(append(append([]byte(f.Origin+"\n"), 0x05), spkiHash[:]...))
			noNL := sha256.Sum256(append(append([]byte(f.Origin), 0x05), spkiHash[:]...))
			if !bytes.Equal(payload[:4], withNL[:4]) {
				t.Errorf("key ID %x != SHA-256(origin||\\n||0x05||SHA-256(SPKI))[:4] = %x", payload[:4], withNL[:4])
			}
			if bytes.Equal(payload[:4], noNL[:4]) {
				t.Errorf("key ID unexpectedly matches the newline-less formula")
			}
			enc := append([]byte{0x05}, spkiHash[:]...)
			if got := NoteKeyHash(f.Origin, enc); got != binary.BigEndian.Uint32(payload[:4]) {
				t.Errorf("NoteKeyHash = %08x, real line key ID = %x", got, payload[:4])
			}
		})
	}
}

// Finding #2 against real data: several production logs put a same-name
// line whose payload is NOT a 68-byte Ed25519 blob nor an RFC6962
// signature (GREASE with a random key ID and random length, or an ML-DSA
// cosignature) BEFORE the real signature line. The old parser errored out
// on the first such line. Pin that the fixture set really contains this
// shape (so the RealProductionLogs test above genuinely covers it) —
// including Geomys Tuscolo2026h2, the canonical example.
func TestRealCheckpoints_GreaseBeforeRealLineStillVerifies(t *testing.T) {
	var withLeadingGrease []string
	for _, f := range loadRealLogFixtures(t) {
		cp := f.checkpoint(t)
		if _, before := rfc6962LineFor(t, cp, f.Origin); before > 0 {
			withLeadingGrease = append(withLeadingGrease, f.Origin)
			if _, err := ParseAndVerifyCheckpoint(cp, f.Origin, f.key(t)); err != nil {
				t.Errorf("%s: %v", f.Origin, err)
			}
		}
	}
	if !contains(withLeadingGrease, "tuscolo2026h2.sunlight.geomys.org") {
		t.Errorf("expected tuscolo2026h2 fixture to lead with a same-name GREASE line; logs with leading same-name lines: %v", withLeadingGrease)
	}
	t.Logf("%d real checkpoints lead with same-name non-RFC6962 lines: %v", len(withLeadingGrease), withLeadingGrease)
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// Finding #4 against real data: naming the key after the monitoring
// host (the old deriveKeyName behaviour) fails, because the origin is the
// submission identity.
func TestRealCheckpoints_MonitoringHostIsNotTheOrigin(t *testing.T) {
	f := findFixture(t, "log.sycamore.ct.letsencrypt.org/2026h2")
	u, _ := url.Parse(f.MonitoringURL)
	if u.Host == f.Origin {
		t.Fatalf("fixture no longer distinguishes monitoring host from origin")
	}
	if _, err := ParseAndVerifyCheckpoint(f.checkpoint(t), u.Host, f.key(t)); err == nil {
		t.Fatalf("verification with monitoring host %q as key name succeeded; want failure", u.Host)
	}
}

// Tampering with a real checkpoint's root hash must break the RFC6962
// signature (the signature really covers tree size + root).
func TestRealCheckpoints_TamperedBodyRejected(t *testing.T) {
	f := findFixture(t, "tuscolo2026h2.sunlight.geomys.org")
	cp := f.checkpoint(t)
	lines := strings.SplitN(string(cp), "\n", 4)

	t.Run("root hash", func(t *testing.T) {
		root, _ := base64.StdEncoding.DecodeString(lines[2])
		root[0] ^= 0x01
		bad := lines[0] + "\n" + lines[1] + "\n" + base64.StdEncoding.EncodeToString(root) + "\n" + lines[3]
		_, err := ParseAndVerifyCheckpoint([]byte(bad), f.Origin, f.key(t))
		if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
			t.Fatalf("err = %v, want signature verification failure", err)
		}
	})
	t.Run("tree size", func(t *testing.T) {
		n, _ := strconv.ParseUint(lines[1], 10, 64)
		bad := lines[0] + "\n" + strconv.FormatUint(n+1, 10) + "\n" + lines[2] + "\n" + lines[3]
		_, err := ParseAndVerifyCheckpoint([]byte(bad), f.Origin, f.key(t))
		if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
			t.Fatalf("err = %v, want signature verification failure", err)
		}
	})
}

// A real checkpoint verified against a DIFFERENT log's real key finds no
// matching signature line.
func TestRealCheckpoints_WrongKeyRejected(t *testing.T) {
	a := findFixture(t, "tuscolo2026h2.sunlight.geomys.org")
	b := findFixture(t, "log.sycamore.ct.letsencrypt.org/2026h2")
	_, err := ParseAndVerifyCheckpoint(a.checkpoint(t), a.Origin, b.key(t))
	if err == nil || !strings.Contains(err.Error(), "no signature line") {
		t.Fatalf("err = %v, want no-signature-line failure", err)
	}
}

func findFixture(t *testing.T, origin string) realLogFixture {
	t.Helper()
	for _, f := range loadRealLogFixtures(t) {
		if f.Origin == origin {
			return f
		}
	}
	t.Fatalf("no fixture for %s", origin)
	return realLogFixture{}
}

// ---------------------------------------------------------------------
// Synthetic checkpoints. The RFC6962 test signer below is written
// independently of the production verifier (its key ID and
// TreeHeadSignature are derived inline, and encoding goes through
// golang.org/x/mod/sumdb/note.Sign); the real-log tests above are what
// anchor it to the true wire format.
// ---------------------------------------------------------------------

// rfc6962TestSigner is a note.Signer producing RFC6962NoteSignature
// checkpoint signatures with an ECDSA P-256 key, as a real Static CT log
// does.
type rfc6962TestSigner struct {
	origin    string
	priv      *ecdsa.PrivateKey
	spki      []byte
	timestamp uint64
}

func newRFC6962TestSigner(t *testing.T, origin string) *rfc6962TestSigner {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return &rfc6962TestSigner{origin: origin, priv: priv, spki: spki, timestamp: 1790000000000}
}

func (s *rfc6962TestSigner) Name() string { return s.origin }

func (s *rfc6962TestSigner) KeyHash() uint32 {
	spkiHash := sha256.Sum256(s.spki)
	h := sha256.Sum256(append(append([]byte(s.origin+"\n"), 0x05), spkiHash[:]...))
	return binary.BigEndian.Uint32(h[:4])
}

func (s *rfc6962TestSigner) Sign(msg []byte) ([]byte, error) {
	lines := strings.Split(strings.TrimSuffix(string(msg), "\n"), "\n")
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return nil, err
	}
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return nil, err
	}
	th := cryptobyte.NewBuilder(nil)
	th.AddUint8(0) // v1
	th.AddUint8(1) // tree_hash
	th.AddUint64(s.timestamp)
	th.AddUint64(size)
	th.AddBytes(root)
	digest := sha256.Sum256(th.BytesOrPanic())
	der, err := ecdsa.SignASN1(rand.Reader, s.priv, digest[:])
	if err != nil {
		return nil, err
	}
	out := cryptobyte.NewBuilder(nil)
	out.AddUint64(s.timestamp)
	out.AddUint8(4) // sha256
	out.AddUint8(3) // ecdsa
	out.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(der) })
	return out.Bytes()
}

func (s *rfc6962TestSigner) pubPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: s.spki}))
}

func (s *rfc6962TestSigner) key(t *testing.T) *LogPublicKey {
	t.Helper()
	k, err := ParseLogPublicKeyPEM(s.pubPEM())
	if err != nil {
		t.Fatalf("ParseLogPublicKeyPEM: %v", err)
	}
	return k
}

// checkpointBody is the three-line tlog-checkpoint body.
func checkpointBody(origin string, size uint64, root []byte) string {
	return origin + "\n" + strconv.FormatUint(size, 10) + "\n" + base64.StdEncoding.EncodeToString(root) + "\n"
}

// greaseSigs returns signature lines shaped like real production GREASE:
// one "grease.invalid" line and one under the log's own name with a
// random key ID and a random-length payload that is neither 68 bytes nor
// RFC6962-shaped. note.Sign emits these BEFORE the real signature, the
// ordering that tripped the old parser.
func greaseSigs(t *testing.T, origin string, avoid uint32) []note.Signature {
	t.Helper()
	mk := func(name string, n int) note.Signature {
		raw := make([]byte, n)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		if binary.BigEndian.Uint32(raw) == avoid {
			raw[0] ^= 0xff
		}
		return note.Signature{Name: name, Hash: binary.BigEndian.Uint32(raw), Base64: base64.StdEncoding.EncodeToString(raw)}
	}
	return []note.Signature{mk("grease.invalid", 45), mk(origin, 11)}
}

// signTestCheckpoint returns a checkpoint signed by s, optionally led by
// GREASE lines.
func signTestCheckpoint(t *testing.T, s note.Signer, origin string, size uint64, root []byte, grease bool) string {
	t.Helper()
	n := &note.Note{Text: checkpointBody(origin, size, root)}
	if grease {
		n.UnverifiedSigs = greaseSigs(t, origin, s.KeyHash())
	}
	out, err := note.Sign(n, s)
	if err != nil {
		t.Fatalf("note.Sign: %v", err)
	}
	return string(out)
}

var testRoot = bytes.Repeat([]byte{0xAB}, 32)

const testOrigin = "log.example.test/2026h2"

func TestParseAndVerifyCheckpoint_RFC6962_HappyPath(t *testing.T) {
	s := newRFC6962TestSigner(t, testOrigin)
	cp := signTestCheckpoint(t, s, testOrigin, 12345, testRoot, false)

	got, err := ParseAndVerifyCheckpoint([]byte(cp), testOrigin, s.key(t))
	if err != nil {
		t.Fatalf("ParseAndVerifyCheckpoint: %v", err)
	}
	if got.TreeSize != 12345 || got.Origin != testOrigin || !bytes.Equal(got.RootHash, testRoot) {
		t.Errorf("STH = %+v", got)
	}
}

// Finding #2, synthetic: GREASE lines — including one under the log's
// own name with an 11-byte payload — precede the real line.
func TestParseAndVerifyCheckpoint_GreaseLinesBeforeRealSignature(t *testing.T) {
	s := newRFC6962TestSigner(t, testOrigin)
	cp := signTestCheckpoint(t, s, testOrigin, 7, testRoot, true)

	sigBlock := cp[strings.LastIndex(cp, "\n\n")+2:]
	if lines := strings.Split(strings.TrimSuffix(sigBlock, "\n"), "\n"); len(lines) != 3 ||
		!strings.HasPrefix(lines[0], "— grease.invalid ") || !strings.HasPrefix(lines[1], "— "+testOrigin+" ") {
		t.Fatalf("fixture does not lead with GREASE lines:\n%s", sigBlock)
	}
	if _, err := ParseAndVerifyCheckpoint([]byte(cp), testOrigin, s.key(t)); err != nil {
		t.Fatalf("ParseAndVerifyCheckpoint: %v", err)
	}
}

func TestParseAndVerifyCheckpoint_RejectsBadSignature(t *testing.T) {
	good := newRFC6962TestSigner(t, testOrigin)
	bad := newRFC6962TestSigner(t, testOrigin)
	bad.spki = good.spki // claim good's key ID, sign with bad's private key
	cp := signTestCheckpoint(t, bad, testOrigin, 1, testRoot, false)

	_, err := ParseAndVerifyCheckpoint([]byte(cp), testOrigin, good.key(t))
	if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("err = %v, want signature failure", err)
	}
}

func TestParseAndVerifyCheckpoint_RejectsMissingMatchingKeyLine(t *testing.T) {
	signed := newRFC6962TestSigner(t, testOrigin)
	other := newRFC6962TestSigner(t, testOrigin)
	cp := signTestCheckpoint(t, signed, testOrigin, 1, testRoot, true)

	_, err := ParseAndVerifyCheckpoint([]byte(cp), testOrigin, other.key(t))
	if err == nil || !strings.Contains(err.Error(), "no signature line for key") {
		t.Errorf("err = %v, want missing-key failure", err)
	}
}

func TestParseAndVerifyCheckpoint_RejectsOriginMismatch(t *testing.T) {
	s := newRFC6962TestSigner(t, testOrigin)
	cp := signTestCheckpoint(t, s, testOrigin, 1, testRoot, false)

	_, err := ParseAndVerifyCheckpoint([]byte(cp), "other.example.test/2026h2", s.key(t))
	if err == nil || !strings.Contains(err.Error(), "does not match configured origin") {
		t.Errorf("err = %v, want origin mismatch", err)
	}
}

// The DigitallySigned wrapper must be SHA-256/ECDSA and fully consumed.
func TestRFC6962Verifier_RejectsMalformedDigitallySigned(t *testing.T) {
	s := newRFC6962TestSigner(t, testOrigin)
	msg := []byte(checkpointBody(testOrigin, 9, testRoot))
	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewCheckpointVerifier(testOrigin, s.key(t))
	if err != nil {
		t.Fatal(err)
	}
	if !v.Verify(msg, sig) {
		t.Fatal("control: valid signature rejected")
	}
	mutate := func(fn func(b []byte) []byte) []byte { return fn(append([]byte(nil), sig...)) }
	for name, bad := range map[string][]byte{
		"hash alg sha384": mutate(func(b []byte) []byte { b[8] = 0x05; return b }),
		"sig alg rsa":     mutate(func(b []byte) []byte { b[9] = 0x01; return b }),
		"trailing byte":   mutate(func(b []byte) []byte { return append(b, 0) }),
		"truncated":       mutate(func(b []byte) []byte { return b[:len(b)-1] }),
		"timestamp":       mutate(func(b []byte) []byte { b[7] ^= 1; return b }),
	} {
		if v.Verify(msg, bad) {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Ed25519 keys are verified with golang.org/x/mod/sumdb/note's own
// reference verifier; the checkpoint here is produced by note's own
// reference signer, so this path shares no code with the production side.
func TestParseAndVerifyCheckpoint_Ed25519_ReferenceSigner(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vkey, err := note.NewEd25519VerifierKey(testOrigin, pub)
	if err != nil {
		t.Fatal(err)
	}
	hash16 := strings.Split(vkey, "+")[1]
	skey := "PRIVATE+KEY+" + testOrigin + "+" + hash16 + "+" + base64.StdEncoding.EncodeToString(append([]byte{0x01}, priv.Seed()...))
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	cp := signTestCheckpoint(t, signer, testOrigin, 42, testRoot, true)

	der, _ := x509.MarshalPKIXPublicKey(pub)
	key, err := ParseLogPublicKeyPEM(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseAndVerifyCheckpoint([]byte(cp), testOrigin, key)
	if err != nil {
		t.Fatalf("ParseAndVerifyCheckpoint: %v", err)
	}
	if got.TreeSize != 42 {
		t.Errorf("TreeSize = %d", got.TreeSize)
	}
	// Signed-note Ed25519 key ID = SHA-256(name || "\n" || 0x01 || pub)[:4].
	if want := NoteKeyHash(testOrigin, append([]byte{0x01}, pub...)); signer.KeyHash() != want {
		t.Errorf("NoteKeyHash = %08x, reference signer key ID = %08x", want, signer.KeyHash())
	}
}

func TestParseAndVerifyCheckpoint_RejectsMalformedBody(t *testing.T) {
	s := newRFC6962TestSigner(t, testOrigin)
	good := signTestCheckpoint(t, s, testOrigin, 1, testRoot, false)
	sigs := good[strings.LastIndex(good, "\n\n")+1:]
	for name, body := range map[string]string{
		"extension line": testOrigin + "\n1\n" + base64.StdEncoding.EncodeToString(testRoot) + "\nextra\n",
		"short root":     testOrigin + "\n1\nAAAA\n",
		"bad size":       testOrigin + "\nx\n" + base64.StdEncoding.EncodeToString(testRoot) + "\n",
	} {
		if _, err := ParseAndVerifyCheckpoint([]byte(body+sigs), testOrigin, s.key(t)); err == nil || !strings.Contains(err.Error(), "checkpoint body") {
			t.Errorf("%s: err = %v, want body parse error", name, err)
		}
	}
	if _, err := ParseAndVerifyCheckpoint([]byte("no separator\n"), testOrigin, s.key(t)); err == nil {
		t.Error("no separator: accepted")
	}
}
