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

package certparse

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestSPKIFingerprintHex(t *testing.T) {
	cases := []struct {
		name string
		spki []byte
	}{
		{"empty", []byte{}},
		{"short", []byte{0x30, 0x82, 0x01}},
		{"long", make([]byte, 4096)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SPKIFingerprintHex(tc.spki)
			sum := sha256.Sum256(tc.spki)
			want := hex.EncodeToString(sum[:])
			if got != want {
				t.Errorf("got %s want %s", got, want)
			}
		})
	}
}
