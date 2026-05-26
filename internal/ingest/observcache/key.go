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

package observcache

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// Key returns a deterministic SHA-256 hex digest of the canonical-JSON
// representation of the identifying fields of a single observation.
//
// The digest mutates whenever ANY field of the observation changes, so
// the cache can never mask a real content update.
func Key(source, resolvedHostID, assetType string, assetFields any) string {
	payload := map[string]any{
		"source":           source,
		"resolved_host_id": resolvedHostID,
		"asset_type":       assetType,
		"asset_fields":     assetFields,
	}
	buf, err := canonicalJSON(payload)
	if err != nil {
		// A marshal error should be impossible on our input types (they
		// are all JSON-marshalable). Fall back to a synthetic key that
		// won't collide with normal hashes — prefix with "ERR-" so
		// operators can grep for it if it ever appears.
		return fmt.Sprintf("ERR-%x", sha256.Sum256([]byte(fmt.Sprintf("%v", payload))))
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

// canonicalJSON marshals v into a canonical byte representation. The
// encoding is stable across calls for equal inputs: map keys sorted
// alphabetically at every nesting level, numeric types rendered
// consistently by encoding/json, timestamps (time.Time) rendered via
// their built-in MarshalJSON (RFC3339Nano).
func canonicalJSON(v any) ([]byte, error) {
	// First pass: marshal normally to get a generic any.
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, err
	}
	// Second pass: re-serialise with canonically-sorted map keys.
	var buf bytes.Buffer
	if err := writeCanonical(&buf, decoded); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeCanonical emits a canonical JSON encoding — maps are rendered with
// keys in lexicographic order; all other values use the standard encoding.
func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case map[string]any:
		buf.WriteByte('{')
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	default:
		enc, err := json.Marshal(v)
		if err != nil {
			return err
		}
		buf.Write(enc)
		return nil
	}
}
