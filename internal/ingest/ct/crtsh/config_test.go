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

package crtsh

import "testing"

func TestValidateDomain(t *testing.T) {
	cases := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		{"valid", "example.com", false},
		{"valid subdomain-capable", "sub.example.co.uk", false},
		{"empty", "", true},
		{"uppercase rejected", "Example.com", true},
		{"no dot", "localhost", true},
		{"whitespace only", "   ", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDomain(tc.domain)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateDomain(%q) error = %v, wantErr %v", tc.domain, err, tc.wantErr)
			}
		})
	}
}
