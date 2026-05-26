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

package model

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"testing"
)

func TestPrivateKeySPKIFingerprint(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	cases := []struct {
		name string
		key  any
		pub  any
	}{
		{"rsa", rsaKey, &rsaKey.PublicKey},
		{"ec", ecKey, &ecKey.PublicKey},
		{"ed", edKey, edKey.Public()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PrivateKeySPKIFingerprint(tc.key)
			if err != nil {
				t.Fatalf("PrivateKeySPKIFingerprint: %v", err)
			}
			spki, _ := x509.MarshalPKIXPublicKey(tc.pub)
			sum := sha256.Sum256(spki)
			want := hex.EncodeToString(sum[:])
			if got != want {
				t.Errorf("%s: got %s want %s", tc.name, got, want)
			}
		})
	}
}
