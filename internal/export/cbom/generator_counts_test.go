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

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
	"github.com/stretchr/testify/require"
)

func rootProps(t *testing.T, bom *cdx.BOM) map[string]string {
	t.Helper()
	require.NotNil(t, bom.Metadata)
	require.NotNil(t, bom.Metadata.Component)
	require.NotNil(t, bom.Metadata.Component.Properties)
	m := map[string]string{}
	for _, p := range *bom.Metadata.Component.Properties {
		m[p.Name] = p.Value
	}
	return m
}

func validCert(fp string) *model.Certificate {
	return &model.Certificate{
		FingerprintSHA256:  fp,
		Subject:            model.DistinguishedName{CommonName: "test.example.com", Full: "CN=test.example.com"},
		Issuer:             model.DistinguishedName{Full: "CN=CA"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(365 * 24 * time.Hour),
		SignatureAlgorithm: model.SigSHA256WithRSA,
	}
}

// appRowsStore returns fixed application rows; embedded fakeGenStore supplies
// the per-asset lookups.
type appRowsStore struct {
	fakeGenStore
	rows []store.ScopeAssetRow
}

func (s *appRowsStore) ListApplicationScopeAssets(context.Context, string) ([]store.ScopeAssetRow, error) {
	return s.rows, nil
}

// certErrStore fails every certificate lookup.
type certErrStore struct{ fakeGenStore }

func (*certErrStore) GetCertificate(context.Context, string) (*model.Certificate, error) {
	return nil, errors.New("db down")
}

func TestGenerate_AssetCountReflectsEmittedComponents(t *testing.T) {
	fake := &fakeGenStore{
		hostIDs: []string{"h1"},
		assetRows: []store.ScopeAssetRow{
			{AssetType: "certificate", AssetID: "fp1", Report: healthReport("certificate", "fp1")},
			// A health report can outlive its asset: no component can be built.
			{AssetType: "certificate", AssetID: "gone", Report: healthReport("certificate", "gone")},
			{AssetType: "ssh_key", AssetID: "gone-key", Report: healthReport("ssh_key", "gone-key")},
		},
		certs: map[string]*model.Certificate{"fp1": validCert("fp1")},
	}

	bom, err := NewGenerator().Generate(context.Background(), fake, &Scope{Name: "s", HostIDs: []string{"h1"}})
	require.NoError(t, err)

	props := rootProps(t, bom)
	require.Equal(t, "1", props["cipherflag:scope.asset_count"], "asset_count must equal emitted components")
	require.Equal(t, "2", props["cipherflag:scope.assets_omitted"])
	require.Equal(t, "certificate,ssh_key", props["cipherflag:scope.assets_omitted_types"])
	require.Equal(t, "1", props["cipherflag:scope.host_count"], "host_count is unaffected")
}

func TestGenerate_NoOmissionPropertiesWhenEverythingMapped(t *testing.T) {
	fake := &fakeGenStore{
		hostIDs:   []string{"h1"},
		assetRows: []store.ScopeAssetRow{{AssetType: "certificate", AssetID: "fp1", Report: healthReport("certificate", "fp1")}},
		certs:     map[string]*model.Certificate{"fp1": validCert("fp1")},
	}

	bom, err := NewGenerator().Generate(context.Background(), fake, &Scope{Name: "s", HostIDs: []string{"h1"}})
	require.NoError(t, err)

	props := rootProps(t, bom)
	require.Equal(t, "1", props["cipherflag:scope.asset_count"])
	require.NotContains(t, props, "cipherflag:scope.assets_omitted")
	require.NotContains(t, props, "cipherflag:scope.assets_omitted_types")
}

func TestGenerate_MappingErrorFailsExport(t *testing.T) {
	fake := &certErrStore{fakeGenStore{
		hostIDs:   []string{"h1"},
		assetRows: []store.ScopeAssetRow{{AssetType: "certificate", AssetID: "fp1", Report: healthReport("certificate", "fp1")}},
	}}

	_, err := NewGenerator().Generate(context.Background(), fake, &Scope{Name: "s", HostIDs: []string{"h1"}})
	require.Error(t, err, "a partial signed BOM must never be returned")
}

// appErrStore serves application rows but fails every certificate lookup.
type appErrStore struct {
	fakeGenStore
	rows []store.ScopeAssetRow
}

func (s *appErrStore) ListApplicationScopeAssets(context.Context, string) ([]store.ScopeAssetRow, error) {
	return s.rows, nil
}
func (*appErrStore) GetCertificate(context.Context, string) (*model.Certificate, error) {
	return nil, errors.New("db down")
}

func TestGenerateForApplication_MappingErrorFailsExport(t *testing.T) {
	st := &appErrStore{rows: []store.ScopeAssetRow{
		{AssetType: "certificate", AssetID: "fp1", Report: healthReport("certificate", "fp1")},
	}}

	_, err := NewGenerator().GenerateForApplication(context.Background(), st, "app-1")
	require.Error(t, err, "application export must fail on a mapping error like the scope export")
}
