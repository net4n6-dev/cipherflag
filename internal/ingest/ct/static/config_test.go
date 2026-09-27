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

import "testing"

const testEd25519PubPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----`

func TestValidateDomainConfig(t *testing.T) {
	cases := []struct {
		name, domain, logURL, pubKey string
		wantErr                      bool
	}{
		{"valid", "example.com", "https://sunlight.example.com/log/", testEd25519PubPEM, false},
		{"missing domain", "", "https://sunlight.example.com/log/", testEd25519PubPEM, true},
		{"missing log_url", "example.com", "", testEd25519PubPEM, true},
		{"http rejected", "example.com", "http://sunlight.example.com/log/", testEd25519PubPEM, true},
		{"no trailing slash", "example.com", "https://sunlight.example.com/log", testEd25519PubPEM, true},
		{"missing public key", "example.com", "https://sunlight.example.com/log/", "", true},
		{"malformed public key", "example.com", "https://sunlight.example.com/log/", "not a pem", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDomainConfig(tc.domain, tc.logURL, tc.pubKey)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateDomainConfig() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
