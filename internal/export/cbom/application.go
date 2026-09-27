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
	"context"
	"errors"
	"fmt"
	"strconv"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// ErrNoApplicationAssets is returned by GenerateForApplication when no scored
// asset carries the tag, so callers can tell a typo'd or unused tag from a real
// (possibly all-omitted) application.
var ErrNoApplicationAssets = errors.New("cbom: no scored assets for application")

// GenerateForApplication produces a CycloneDX 1.6 BOM scoped to a single
// application-tag. Reuses Generator.mapRow so crypto-asset component
// semantics match the host-scoped CBOM path byte-for-byte — operators
// importing both into the same BOM-consumer see consistent shapes.
//
// Implements AQ-CE-02 at application grain. See
// docs/analyst-question-catalog.md §Domain 9.
func (g *Generator) GenerateForApplication(ctx context.Context, st store.CryptoStore, tag string) (*cdx.BOM, error) {
	rows, err := st.ListApplicationScopeAssets(ctx, tag)
	if err != nil {
		return nil, fmt.Errorf("cbom: list assets for application %q: %w", tag, err)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("%w: %q", ErrNoApplicationAssets, tag)
	}

	// The root application component identifies the application tag. Treat the
	// tag as the FISMA system identifier for OMB M-23-02 cross-reference
	// purposes (see OMB §II.A field 1).
	root := &cdx.Component{
		Type:   cdx.ComponentTypeApplication,
		BOMRef: "application:" + tag,
		Name:   tag,
		Properties: &[]cdx.Property{
			{Name: "cipherflag:application.tag", Value: tag},
			{Name: "cipherflag:application.asset_count", Value: strconv.Itoa(len(rows))},
			{Name: "cipherflag:application.fisma_id_alias", Value: tag},
		},
	}
	return g.buildBOMFromRows(ctx, st, rows, bomParams{
		root:          root,
		label:         "application:" + tag,
		depsInBOMOnly: true,
	})
}
