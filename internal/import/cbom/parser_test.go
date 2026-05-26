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

package cbomimport

import (
	"bytes"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// encodeBOM is a test helper — encodes a BOM to JSON for parser input.
func encodeBOM(t *testing.T, bom *cdx.BOM) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	enc.SetPretty(false)
	if err := enc.Encode(bom); err != nil {
		t.Fatalf("encode: %v", err)
	}
	return buf.Bytes()
}

func TestParse_ValidBOM_1_6(t *testing.T) {
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_6
	bom.SerialNumber = "urn:uuid:test-1"
	components := []cdx.Component{
		{Type: cdx.ComponentTypeLibrary, Name: "openssl", Version: "3.0.14"},
	}
	bom.Components = &components

	parsed, err := Parse(bytes.NewReader(encodeBOM(t, bom)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.SerialNumber != "urn:uuid:test-1" {
		t.Errorf("SerialNumber = %q, want urn:uuid:test-1", parsed.SerialNumber)
	}
	if parsed.Components == nil || len(*parsed.Components) != 1 {
		t.Fatalf("Components length = %d, want 1", len(*parsed.Components))
	}
	if (*parsed.Components)[0].Name != "openssl" {
		t.Errorf("Component name = %q, want openssl", (*parsed.Components)[0].Name)
	}
}

func TestParse_ValidBOM_1_4(t *testing.T) {
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_4
	bom.SerialNumber = "urn:uuid:test-14"

	parsed, err := Parse(bytes.NewReader(encodeBOM(t, bom)))
	if err != nil {
		t.Fatalf("Parse 1.4: %v", err)
	}
	if parsed.SerialNumber != "urn:uuid:test-14" {
		t.Errorf("SerialNumber = %q", parsed.SerialNumber)
	}
}

func TestParse_EmptyBOM(t *testing.T) {
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_6

	parsed, err := Parse(bytes.NewReader(encodeBOM(t, bom)))
	if err != nil {
		t.Fatalf("Parse empty BOM: %v", err)
	}
	if parsed.Components != nil && len(*parsed.Components) != 0 {
		t.Errorf("empty BOM should have no components, got %d", len(*parsed.Components))
	}
}

func TestParse_MalformedJSON(t *testing.T) {
	_, err := Parse(strings.NewReader("not valid json {{{"))
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Errorf("error message = %v, want 'decode' keyword", err)
	}
}
