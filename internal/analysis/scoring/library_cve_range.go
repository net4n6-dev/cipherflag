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

import (
	"strconv"
	"strings"
)

// matchesVersionRange reports whether version falls within the range described
// by rangeStr. Returns false for empty or unrecognised range strings.
//
// Range format: space-separated >=X and <Y clauses (both optional).
//
//	">=1.0.1 <1.0.1g"  lower-inclusive, upper-exclusive
//	"<2.0.0"           upper bound only
//	">=3.0.0"          lower bound only
//
// Version strings with a "-" suffix (e.g. "3.0.8-fips") have the suffix
// stripped before comparison.
func matchesVersionRange(version, rangeStr string) bool {
	if rangeStr == "" {
		return false
	}
	version = stripVariantSuffix(version)
	if version == "" {
		return false
	}

	var hasLower, hasUpper bool
	var lower, upper string

	for _, clause := range strings.Fields(rangeStr) {
		switch {
		case strings.HasPrefix(clause, ">="):
			lower = stripVariantSuffix(clause[2:])
			hasLower = true
		case strings.HasPrefix(clause, "<"):
			upper = stripVariantSuffix(clause[1:])
			hasUpper = true
		default:
			return false // unrecognised operator
		}
	}
	if !hasLower && !hasUpper {
		return false
	}
	if hasLower && compareVersions(version, lower) < 0 {
		return false
	}
	if hasUpper && compareVersions(version, upper) >= 0 {
		return false
	}
	return true
}

// stripVariantSuffix removes everything from the first "-" in a version string.
// "3.0.8-fips" → "3.0.8", "1.0.2" → "1.0.2".
func stripVariantSuffix(v string) string {
	if i := strings.IndexByte(v, '-'); i >= 0 {
		return v[:i]
	}
	return v
}

// compareVersions returns negative if a < b, 0 if a == b, positive if a > b.
// Segments are split on ".". Each segment is compared as a numeric prefix
// (integer) then an alphabetic suffix (lexicographic). Missing segments are
// treated as zero with no suffix.
func compareVersions(a, b string) int {
	segA := strings.Split(a, ".")
	segB := strings.Split(b, ".")

	n := len(segA)
	if len(segB) > n {
		n = len(segB)
	}
	for i := 0; i < n; i++ {
		sa, sb := "", ""
		if i < len(segA) {
			sa = segA[i]
		}
		if i < len(segB) {
			sb = segB[i]
		}
		if c := compareSegment(sa, sb); c != 0 {
			return c
		}
	}
	return 0
}

// compareSegment compares two dot-separated version segments such as "2zd" vs "2ze".
// Splits each into a numeric prefix and alphabetic suffix.
func compareSegment(a, b string) int {
	numA, suffA := splitSegment(a)
	numB, suffB := splitSegment(b)
	if numA < numB {
		return -1
	}
	if numA > numB {
		return 1
	}
	if suffA < suffB {
		return -1
	}
	if suffA > suffB {
		return 1
	}
	return 0
}

// splitSegment splits a segment like "2zd" into numeric 2 and suffix "zd".
// A purely numeric segment returns an empty suffix.
func splitSegment(s string) (int, string) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	num, _ := strconv.Atoi(s[:i])
	return num, s[i:]
}
