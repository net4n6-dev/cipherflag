//go:build integration

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
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScrub_ReplacesTopLevelSerial(t *testing.T) {
	in := []byte(`{"serialNumber":"urn:uuid:abc","metadata":{"timestamp":"2026-01-01T00:00:00Z"}}`)
	out, err := scrubVolatileFields(in)
	require.NoError(t, err)
	require.Contains(t, string(out), `"<SERIAL>"`)
	require.Contains(t, string(out), `"<TIME>"`)
	require.NotContains(t, string(out), `"urn:uuid:abc"`)
	require.NotContains(t, string(out), `"2026-01-01T00:00:00Z"`)
}

func TestScrub_PreservesNonVolatileValues(t *testing.T) {
	in := []byte(`{"components":[{"name":"openssl","version":"3.0.10","properties":[{"name":"cipherflag:fingerprint_sha256","value":"abc123"}]}]}`)
	out, err := scrubVolatileFields(in)
	require.NoError(t, err)
	require.Contains(t, string(out), `"openssl"`)
	require.Contains(t, string(out), `"3.0.10"`)
	require.Contains(t, string(out), `"abc123"`)
}

func TestScrub_ReplacesNamedVolatileProperty(t *testing.T) {
	in := []byte(`{"components":[{"properties":[{"name":"cipherflag:first_seen","value":"2026-05-16T10:00:00Z"},{"name":"cipherflag:fingerprint_sha256","value":"abc"}]}]}`)
	out, err := scrubVolatileFields(in)
	require.NoError(t, err)
	require.Contains(t, string(out), `"cipherflag:first_seen"`)
	require.Contains(t, string(out), `"<TIME>"`)
	require.Contains(t, string(out), `"abc"`)
	require.NotContains(t, string(out), `"2026-05-16T10:00:00Z"`)
}

func TestScrub_ReplacesToolsVersion(t *testing.T) {
	in := []byte(`{"metadata":{"tools":{"components":[{"name":"cipherflag","version":"v1.16.0-rc.3"}]}}}`)
	out, err := scrubVolatileFields(in)
	require.NoError(t, err)
	require.Contains(t, string(out), `"<VERSION>"`)
	require.NotContains(t, string(out), `"v1.16.0-rc.3"`)
}

func TestScrub_IsCanonicalised(t *testing.T) {
	// Differently-ordered input maps must produce byte-identical scrubbed output.
	in1 := []byte(`{"b":2,"a":1,"serialNumber":"x","metadata":{"timestamp":"y"}}`)
	in2 := []byte(`{"a":1,"metadata":{"timestamp":"y"},"serialNumber":"x","b":2}`)
	out1, err := scrubVolatileFields(in1)
	require.NoError(t, err)
	out2, err := scrubVolatileFields(in2)
	require.NoError(t, err)
	require.Equal(t, string(out1), string(out2))
}

func TestScrub_ReplacesSignatureValue(t *testing.T) {
	in := []byte(`{"signature":{"algorithm":"Ed25519","value":"AAABBBCCC","publicKey":{"crv":"Ed25519","x":"abc"}}}`)
	out, err := scrubVolatileFields(in)
	require.NoError(t, err)
	require.Contains(t, string(out), `"<SIGNATURE>"`)
	require.NotContains(t, string(out), `"AAABBBCCC"`)
	require.Contains(t, string(out), `"Ed25519"`) // algorithm preserved
	require.Contains(t, string(out), `"abc"`)     // publicKey.x preserved
}

// scrubRule describes one scrub operation against the parsed JSON tree.
//
// path is a dot-delimited walk where "[]" means "every element of this
// array", "*" means "every key at this level". Two dialect rules:
//
//   - If the rule's `name` is empty, the value at `path` is overwritten
//     with `value`. Use this for absolute paths like `serialNumber`.
//
//   - If the rule's `name` is non-empty, `path` must end at an array of
//     objects each shaped {name: ..., value: ...}, and only objects with
//     a matching `name` field are scrubbed. Use this for filtered
//     property scrubs.
//
// Spec source: docs/superpowers/specs/2026-05-16-l4-e-cbom-golden-suite-design.md §3.
type scrubRule struct {
	path  string
	name  string
	value string
}

var volatileScrubs = []scrubRule{
	{path: "serialNumber", value: "<SERIAL>"},
	{path: "metadata.timestamp", value: "<TIME>"},
	{path: "metadata.tools.components[].version", value: "<VERSION>"},
	{path: "components[].properties[]", name: "cipherflag:first_seen", value: "<TIME>"},
	{path: "components[].properties[]", name: "cipherflag:last_seen", value: "<TIME>"},
	{path: "components[].properties[]", name: "cipherflag:scored_at", value: "<TIME>"},
	// signature.value is a function of every byte the signer covered, which
	// includes the volatile serialNumber (random UUIDv4) and metadata.timestamp
	// (time.Now()). Ed25519 itself is deterministic, but the payload isn't —
	// so the signature value drifts per run. Scrub it to <SIGNATURE> so the
	// golden locks signature *shape* without depending on the per-run payload.
	// The spec's alternative considered (Section 3) preferred not scrubbing
	// this field; the design proved untenable once the serialNumber/timestamp
	// pre-sign drift was visible.
	{path: "signature.value", value: "<SIGNATURE>"},
}

// scrubVolatileFields parses canonicalJSON, applies volatileScrubs, then
// re-canonicalises so the output bytes are JCS-stable.
func scrubVolatileFields(canonicalJSON []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(canonicalJSON))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, fmt.Errorf("scrubVolatileFields: parse: %w", err)
	}
	for _, rule := range volatileScrubs {
		walkScrub(tree, splitPath(rule.path), rule.name, rule.value)
	}
	raw, err := json.Marshal(tree)
	if err != nil {
		return nil, fmt.Errorf("scrubVolatileFields: marshal: %w", err)
	}
	return Canonicalize(raw)
}

func splitPath(p string) []string {
	return strings.Split(p, ".")
}

// walkScrub descends `node` following `segments`. At the terminal
// segment, if `name` is empty it overwrites with value; otherwise it
// scrubs only objects in the terminal array whose `name` field matches.
func walkScrub(node any, segments []string, name, value string) {
	if len(segments) == 0 {
		return
	}
	head := segments[0]
	rest := segments[1:]

	isArrayStep := false
	if len(head) >= 2 && head[len(head)-2:] == "[]" {
		head = head[:len(head)-2]
		isArrayStep = true
	}

	obj, ok := node.(map[string]any)
	if !ok {
		return
	}
	child, ok := obj[head]
	if !ok {
		return
	}

	if !isArrayStep {
		if len(rest) == 0 {
			obj[head] = value
			return
		}
		walkScrub(child, rest, name, value)
		return
	}

	arr, ok := child.([]any)
	if !ok {
		return
	}

	if len(rest) == 0 {
		if name == "" {
			// arr[i] = value: assumes elements are scalars or objects, not nested arrays.
			for i := range arr {
				arr[i] = value
			}
			return
		}
		for _, el := range arr {
			elObj, ok := el.(map[string]any)
			if !ok {
				continue
			}
			if elObj["name"] == name {
				elObj["value"] = value
			}
		}
		return
	}

	for _, el := range arr {
		walkScrub(el, rest, name, value)
	}
}
