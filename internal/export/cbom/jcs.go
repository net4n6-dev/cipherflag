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
	"sort"
	"strconv"
	"strings"
)

// Canonicalize implements RFC 8785 (JSON Canonicalization Scheme):
//   - Object members sorted lexicographically by UTF-16 code units.
//   - Numbers formatted per ECMA-262 (integers as integers; floats
//     in shortest unambiguous form).
//   - No insignificant whitespace.
//   - Strings escaped per RFC 8259 §7 (7 mandatory escapes only).
//
// The output is bytes ready for signing or hashing.
//
// Note on UTF-16 sort order: for ASCII-only keys (which CBOM uses throughout),
// Go's string comparison is equivalent to UTF-16 code-unit comparison. If
// non-ASCII keys ever appear, this implementation would need to upgrade to a
// true UTF-16 sort. The TestJCS_OfficialVectors test validates this assumption
// once the test vectors are vendored.
func Canonicalize(input []byte) ([]byte, error) {
	var v interface{}
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.UseNumber() // preserve number precision through unmarshal
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("jcs: parse: %w", err)
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(w *bytes.Buffer, v interface{}) error {
	switch x := v.(type) {
	case nil:
		w.WriteString("null")
	case bool:
		if x {
			w.WriteString("true")
		} else {
			w.WriteString("false")
		}
	case json.Number:
		return writeNumber(w, string(x))
	case string:
		return writeString(w, x)
	case []interface{}:
		w.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				w.WriteByte(',')
			}
			if err := writeCanonical(w, e); err != nil {
				return err
			}
		}
		w.WriteByte(']')
	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		w.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				w.WriteByte(',')
			}
			if err := writeString(w, k); err != nil {
				return err
			}
			w.WriteByte(':')
			if err := writeCanonical(w, x[k]); err != nil {
				return err
			}
		}
		w.WriteByte('}')
	default:
		return fmt.Errorf("jcs: unsupported type %T", v)
	}
	return nil
}

func writeNumber(w *bytes.Buffer, n string) error {
	// json.Number stores the original string; reformat per ECMA-262 §7.1.12.1.
	f, err := strconv.ParseFloat(n, 64)
	if err != nil {
		return fmt.Errorf("jcs: invalid number %q", n)
	}
	// If the original token is a plain integer literal, write it directly.
	if i, errI := strconv.ParseInt(n, 10, 64); errI == nil {
		w.WriteString(strconv.FormatInt(i, 10))
		return nil
	}
	// If the float is integer-valued and within safe integer range, write as integer.
	if f == float64(int64(f)) && f < 1e15 && f > -1e15 {
		w.WriteString(strconv.FormatInt(int64(f), 10))
		return nil
	}
	// Shortest round-trip float via Go's 'g' format, then apply ECMA-262 exponent
	// threshold: use positional decimal when -6 <= exponent < 21, exponential
	// notation only for exponent >= 21 or exponent < -6.
	s := strconv.FormatFloat(f, 'g', -1, 64)
	if idx := strings.Index(s, "e"); idx >= 0 {
		exp, errE := strconv.Atoi(s[idx+1:])
		if errE == nil && exp >= -6 && exp < 0 {
			// Go chose exponential; ECMA-262 requires positional for this range.
			s = strconv.FormatFloat(f, 'f', -1, 64)
		}
	}
	w.WriteString(s)
	return nil
}

func writeString(w *bytes.Buffer, s string) error {
	w.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			w.WriteString(`\"`)
		case '\\':
			w.WriteString(`\\`)
		case '\b':
			w.WriteString(`\b`)
		case '\f':
			w.WriteString(`\f`)
		case '\n':
			w.WriteString(`\n`)
		case '\r':
			w.WriteString(`\r`)
		case '\t':
			w.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(w, `\u%04x`, r)
			} else {
				w.WriteRune(r)
			}
		}
	}
	w.WriteByte('"')
	return nil
}
