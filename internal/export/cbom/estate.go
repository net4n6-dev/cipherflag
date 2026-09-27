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
	"fmt"
	"strconv"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// GenerateWholeEstate produces a CycloneDX 1.6 CBOM over every scored asset in
// the database, independent of host provenance or application tag. Signed when
// a signer is configured.
//
// The BOM is assembled in memory with one store lookup per asset (a signed BOM
// must be, because JCS canonicalisation cannot stream), so very large
// inventories cost memory and time proportional to their size.
func (g *Generator) GenerateWholeEstate(ctx context.Context, st store.CryptoStore) (*cdx.BOM, error) {
	rows, err := st.ListAllAssetHealthReports(ctx)
	if err != nil {
		return nil, fmt.Errorf("cbom: list all assets: %w", err)
	}
	root := &cdx.Component{
		Type:   cdx.ComponentTypeApplication,
		BOMRef: "estate",
		Name:   "estate",
		Properties: &[]cdx.Property{
			{Name: "cipherflag:estate.asset_count", Value: strconv.Itoa(len(rows))},
		},
	}
	return g.buildBOMFromRows(ctx, st, rows, bomParams{root: root, label: "estate"})
}
