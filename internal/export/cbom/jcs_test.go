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

package cbom

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJCS_CanonicalizesSimpleObject(t *testing.T) {
	input := []byte(`{"b": 1, "a": 2}`)
	canonical, err := Canonicalize(input)
	require.NoError(t, err)
	require.Equal(t, `{"a":2,"b":1}`, string(canonical),
		"JCS sorts object keys lexicographically and removes whitespace")
}

func TestJCS_NestedObjectSorting(t *testing.T) {
	input := []byte(`{"outer": {"b": 1, "a": {"d": 3, "c": 4}}}`)
	canonical, err := Canonicalize(input)
	require.NoError(t, err)
	require.Equal(t, `{"outer":{"a":{"c":4,"d":3},"b":1}}`, string(canonical))
}

func TestJCS_NumberCanonicalization(t *testing.T) {
	// RFC 8785 §3.2.2: numbers formatted per ECMA-262 / IEEE-754
	cases := []struct{ in, want string }{
		{`{"x": 1.0}`, `{"x":1}`},           // trailing zero stripped
		{`{"x": 1e2}`, `{"x":100}`},          // scientific → integer form when possible
		{`{"x": 0.000001}`, `{"x":0.000001}`}, // small numbers preserved
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			canonical, err := Canonicalize([]byte(tc.in))
			require.NoError(t, err)
			require.Equal(t, tc.want, string(canonical))
		})
	}
}

func TestJCS_StringEscaping(t *testing.T) {
	// RFC 8259 §7 + RFC 8785 §3.2.4
	input := []byte(`{"x": "héllo\twörld"}`)
	canonical, err := Canonicalize(input)
	require.NoError(t, err)
	// Non-ASCII passes through (UTF-8); only the 7 mandatory escapes apply.
	require.Equal(t, `{"x":"héllo\twörld"}`, string(canonical))
}

// TestJCS_OfficialVectors runs the canonicalizer against the upstream
// RFC 8785 test vectors. Skip if the testdata directory is empty
// (vendoring step not yet completed).
func TestJCS_OfficialVectors(t *testing.T) {
	inputDir := filepath.Join("testdata", "jcs-vectors", "input")
	outputDir := filepath.Join("testdata", "jcs-vectors", "output")
	entries, err := os.ReadDir(inputDir)
	if err != nil {
		t.Skipf("testdata/jcs-vectors not populated yet: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			in, err := os.ReadFile(filepath.Join(inputDir, e.Name()))
			require.NoError(t, err)
			want, err := os.ReadFile(filepath.Join(outputDir, e.Name()))
			require.NoError(t, err)
			got, err := Canonicalize(in)
			require.NoError(t, err)
			require.Equal(t, string(want), string(got))
		})
	}
}

func TestJCS_RejectsInvalidJSON(t *testing.T) {
	_, err := Canonicalize([]byte(`{not json`))
	require.Error(t, err)
}
