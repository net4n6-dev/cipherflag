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
	"testing"

	"github.com/stretchr/testify/require"
)

// Every BOM names the CipherFlag version that produced it in
// metadata.tools. The value was meant to be set with -ldflags -X in release
// builds, but no build did, so every released BOM said "dev". serve now sets
// it from its own Version at startup.
func TestSetToolVersion_StampsGeneratedBOMs(t *testing.T) {
	old := cbomVersion
	t.Cleanup(func() { cbomVersion = old })

	SetToolVersion("9.9.9")
	bom, err := NewGenerator().GenerateForRepo(context.Background(), &fakeRepoStore{}, "repo-1")
	require.NoError(t, err)
	require.NotNil(t, bom.Metadata)
	require.NotNil(t, bom.Metadata.Tools)
	tools := *bom.Metadata.Tools.Components
	require.Len(t, tools, 1)
	require.Equal(t, "cipherflag", tools[0].Name)
	require.Equal(t, "9.9.9", tools[0].Version)
}

func TestSetToolVersion_IgnoresEmpty(t *testing.T) {
	old := cbomVersion
	t.Cleanup(func() { cbomVersion = old })

	SetToolVersion("1.2.3")
	SetToolVersion("")
	require.Equal(t, "1.2.3", cbomVersion)
}
