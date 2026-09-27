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

package certspotter

import "testing"

func TestValidateDomain(t *testing.T) {
	cases := []struct {
		name            string
		domain          string
		requestsPerHour int
		wantErr         bool
	}{
		{"valid default rate", "example.com", 0, false},
		{"valid explicit rate", "example.com", 100, false},
		{"empty domain", "", 0, true},
		{"negative rate", "example.com", -1, true},
		{"rate too high", "example.com", 100001, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDomain(tc.domain, tc.requestsPerHour)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateDomain() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
