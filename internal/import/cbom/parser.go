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
	"fmt"
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Parse decodes a CycloneDX BOM from the reader as JSON. Accepts spec
// versions 1.4, 1.5, and 1.6 (the library auto-detects). Returns an
// error wrapped with "decode" on malformed input.
func Parse(r io.Reader) (*cdx.BOM, error) {
	var bom cdx.BOM
	decoder := cdx.NewBOMDecoder(r, cdx.BOMFileFormatJSON)
	if err := decoder.Decode(&bom); err != nil {
		return nil, fmt.Errorf("cbom import: decode: %w", err)
	}
	return &bom, nil
}
