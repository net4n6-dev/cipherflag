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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// FakeSPKILookup is an in-memory SPKILookup for tests.
type FakeSPKILookup map[string]string // spkiFP → certFP

func (f FakeSPKILookup) CertFingerprintBySPKI(_ context.Context, spkiFP string) (string, bool) {
	fp, ok := f[spkiFP]
	return fp, ok
}

func TestDetectPEMPrivateKey_MatchesCertBySPKI(t *testing.T) {
	dir := t.TempDir()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyPath := filepath.Join(dir, "leaf.key")
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	f := mustCreate(t, keyPath)
	pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	f.Close()

	spki, _ := model.PrivateKeySPKIFingerprint(key)
	lookup := FakeSPKILookup{spki: "matching-cert-fp"}

	obs, err := DetectPEMPrivateKey(context.Background(), keyPath, lookup)
	if err != nil {
		t.Fatalf("DetectPEMPrivateKey: %v", err)
	}
	if len(obs) != 1 || obs[0].CertFingerprint != "matching-cert-fp" || obs[0].Evidence != "colocated_pem" {
		t.Errorf("obs = %+v, want one row {cert=matching-cert-fp, evidence=colocated_pem}", obs)
	}
}

func TestDetectPEMPrivateKey_NoMatchEmitsNothing(t *testing.T) {
	dir := t.TempDir()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyPath := filepath.Join(dir, "orphan.key")
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	f := mustCreate(t, keyPath)
	pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	f.Close()

	obs, _ := DetectPEMPrivateKey(context.Background(), keyPath, FakeSPKILookup{})
	if len(obs) != 0 {
		t.Errorf("orphan key produced %d obs, want 0", len(obs))
	}
}

func mustCreate(t *testing.T, p string) *os.File {
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
