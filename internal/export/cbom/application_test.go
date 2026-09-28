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
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/store"
	"github.com/stretchr/testify/require"
)

func TestGenerateForApplication_NoRowsIsErrNoApplicationAssets(t *testing.T) {
	_, err := NewGenerator().GenerateForApplication(context.Background(), &appRowsStore{}, "typo-tag")
	require.True(t, errors.Is(err, ErrNoApplicationAssets), "got %v", err)
}

func TestGenerateForApplication_AllRowsOrphanedStillReturnsBOMWithDisclosure(t *testing.T) {
	st := &appRowsStore{rows: []store.ScopeAssetRow{
		{AssetType: "certificate", AssetID: "gone", Report: healthReport("certificate", "gone")},
	}}

	bom, err := NewGenerator().GenerateForApplication(context.Background(), st, "app-1")
	require.NoError(t, err, "orphaned rows are disclosed, not an error")

	props := rootProps(t, bom)
	require.Equal(t, "0", props["cipherflag:application.asset_count"])
	require.Equal(t, "1", props["cipherflag:application.assets_omitted"])
	require.Equal(t, "certificate", props["cipherflag:application.assets_omitted_types"])
}
