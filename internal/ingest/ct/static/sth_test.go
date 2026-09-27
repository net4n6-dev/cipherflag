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
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseAndVerifyCheckpoint_HappyPath(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Body the log signs: origin / size / hash, terminated by a newline,
	// followed by a blank line that separates body from signature lines.
	body := "sunlight.example/2024h2/\n12345\nB10vRWCDc4hZkDIRb7tEXmAACIb6N7uKp7XCG8oP4Y4=\n"
	sig := ed25519.Sign(priv, []byte(body))

	// keyHash = first 4 bytes of SHA-256(name || 0x01 || pub).
	keyName := "sunlight.example"
	keyHash := KeyHashEd25519(keyName, pub)

	checkpoint := body + "\n— " + keyName + " " + base64.StdEncoding.EncodeToString(append(keyHash, sig...)) + "\n"

	got, err := ParseAndVerifyCheckpoint([]byte(checkpoint), pub, keyName)
	if err != nil {
		t.Fatalf("ParseAndVerifyCheckpoint: %v", err)
	}
	if got.TreeSize != 12345 {
		t.Errorf("TreeSize = %d, want 12345", got.TreeSize)
	}
	if got.Origin != "sunlight.example/2024h2/" {
		t.Errorf("Origin = %q", got.Origin)
	}
	if len(got.RootHash) != 32 {
		t.Errorf("RootHash len = %d, want 32", len(got.RootHash))
	}
}

func TestParseAndVerifyCheckpoint_RejectsBadSignature(t *testing.T) {
	pubGood, _, _ := ed25519.GenerateKey(nil)
	_, privBad, _ := ed25519.GenerateKey(nil)

	body := "sunlight.example/2024h2/\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
	badSig := ed25519.Sign(privBad, []byte(body))
	keyName := "sunlight.example"
	keyHash := KeyHashEd25519(keyName, pubGood)
	checkpoint := body + "\n— " + keyName + " " + base64.StdEncoding.EncodeToString(append(keyHash, badSig...)) + "\n"

	_, err := ParseAndVerifyCheckpoint([]byte(checkpoint), pubGood, keyName)
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Errorf("err = %v, want signature failure", err)
	}
}

func TestParseAndVerifyCheckpoint_RejectsMissingMatchingKeyLine(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	body := "sunlight.example/2024h2/\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
	sig := ed25519.Sign(priv, []byte(body))
	wrongKeyName := "other.example"
	keyHash := KeyHashEd25519(wrongKeyName, pub)
	checkpoint := body + "\n— " + wrongKeyName + " " + base64.StdEncoding.EncodeToString(append(keyHash, sig...)) + "\n"

	_, err := ParseAndVerifyCheckpoint([]byte(checkpoint), pub, "sunlight.example")
	if err == nil || !strings.Contains(err.Error(), "key") {
		t.Errorf("err = %v, want missing-key failure", err)
	}
}
