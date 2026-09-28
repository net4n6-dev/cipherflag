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
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
	"github.com/stretchr/testify/require"
)

// estateStore serves a fixed whole-estate row set; the embedded fakeGenStore
// supplies the per-asset lookups.
type estateStore struct {
	fakeGenStore
	all []store.ScopeAssetRow
	err error
}

func (s *estateStore) ListAllAssetHealthReports(context.Context) ([]store.ScopeAssetRow, error) {
	return s.all, s.err
}

func TestGenerateWholeEstate_IncludesEveryScoredAsset(t *testing.T) {
	st := &estateStore{
		fakeGenStore: fakeGenStore{
			certs: map[string]*model.Certificate{"fp1": validCert("fp1")},
			sshKeys: map[string]*model.SSHKey{
				"key-1": {ID: "key-1", FingerprintSHA256: "fp-key-1", KeyType: "ssh-ed25519",
					KeySizeBits: 256, FirstSeen: time.Now(), DiscoveryStatus: "active"},
			},
		},
		all: []store.ScopeAssetRow{
			{AssetType: "certificate", AssetID: "fp1", Report: healthReport("certificate", "fp1")},
			{AssetType: "ssh_key", AssetID: "key-1", Report: healthReport("ssh_key", "key-1")},
		},
	}

	bom, err := NewGenerator().GenerateWholeEstate(context.Background(), st)
	require.NoError(t, err)

	require.Equal(t, "estate", bom.Metadata.Component.BOMRef)
	require.Equal(t, "estate", bom.Metadata.Component.Name)
	require.Equal(t, "2", rootProps(t, bom)["cipherflag:estate.asset_count"])

	refs := map[string]bool{}
	for _, c := range *bom.Components {
		refs[c.BOMRef] = true
	}
	require.True(t, refs["cert:fp1"], "certificate component missing")
	require.True(t, refs["sshkey:fp-key-1"], "ssh key component missing")
}

func TestGenerateWholeEstate_EmptyInventoryIsAValidBOM(t *testing.T) {
	bom, err := NewGenerator().GenerateWholeEstate(context.Background(), &estateStore{})
	require.NoError(t, err)
	require.NotNil(t, bom)
	require.Equal(t, "0", rootProps(t, bom)["cipherflag:estate.asset_count"])
	require.Nil(t, bom.Components, "an empty estate has no components")
}

func TestGenerateWholeEstate_ListErrorIsReturned(t *testing.T) {
	_, err := NewGenerator().GenerateWholeEstate(context.Background(), &estateStore{err: errors.New("db down")})
	require.ErrorContains(t, err, "list all assets")
}
