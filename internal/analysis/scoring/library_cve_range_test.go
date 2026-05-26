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

package scoring

import "testing"

func TestMatchesVersionRange(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		rangeStr string
		want     bool
	}{
		// Basic lower+upper bound
		{"inside range", "1.0.1c", ">=1.0.1 <1.0.1g", true},
		{"at lower bound", "1.0.1", ">=1.0.1 <1.0.1g", true},
		{"at upper bound exclusive", "1.0.1g", ">=1.0.1 <1.0.1g", false},
		{"below lower bound", "1.0.0", ">=1.0.1 <1.0.1g", false},
		{"above upper bound", "1.0.1h", ">=1.0.1 <1.0.1g", false},
		// Numeric-only bounds
		{"numeric inside", "3.0.5", ">=3.0.0 <3.0.7", true},
		{"numeric at upper exclusive", "3.0.7", ">=3.0.0 <3.0.7", false},
		{"numeric above upper", "3.0.8", ">=3.0.0 <3.0.7", false},
		// Alpha suffix ordering
		{"alpha suffix j < k", "1.0.2j", ">=1.0.2 <1.0.2k", true},
		{"alpha suffix k not < k", "1.0.2k", ">=1.0.2 <1.0.2k", false},
		{"alpha suffix zd < ze", "1.0.2zd", ">=1.0.2 <1.0.2ze", true},
		{"alpha suffix zf above zd upper bound", "1.0.2zf", ">=1.0.2 <1.0.2zd", false},
		// Upper bound only
		{"upper only inside", "1.9.9", "<2.0.0", true},
		{"upper only at bound exclusive", "2.0.0", "<2.0.0", false},
		{"upper only above", "2.0.1", "<2.0.0", false},
		// Lower bound only
		{"lower only at bound", "3.0.0", ">=3.0.0", true},
		{"lower only above", "3.1.0", ">=3.0.0", true},
		{"lower only below", "2.9.9", ">=3.0.0", false},
		// -fips and -beta suffix stripped before comparison
		{"fips stripped inside range", "3.0.8-fips", ">=3.0.0 <3.0.9", true},
		{"fips stripped at upper exclusive", "3.0.9-fips", ">=3.0.0 <3.0.9", false},
		{"beta stripped inside", "1.0.2-beta", ">=1.0.2 <1.0.3", true},
		// Empty and unrecognised
		{"empty range string", "1.0.0", "", false},
		{"whitespace only range", "1.0.0", "   ", false},
		{"unrecognised operator", "1.0.0", "^1.0.0", false},
		{"tilde operator", "1.0.0", "~1.0.0", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesVersionRange(tt.version, tt.rangeStr)
			if got != tt.want {
				t.Errorf("matchesVersionRange(%q, %q) = %v, want %v",
					tt.version, tt.rangeStr, got, tt.want)
			}
		})
	}
}
