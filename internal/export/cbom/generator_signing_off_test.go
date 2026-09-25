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
	"time"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// Regression: NewGeneratorWithSigning with signing disabled (the default)
// returned a Generator with a nil libraryFIPSLevel, so any scope containing
// both a crypto library and an algorithm component panicked in Generate.
func TestGenerate_SigningDisabled_LibraryAndAlgorithm(t *testing.T) {
	fake := &fakeGenStore{
		hostIDs: []string{"h1"},
		assetRows: []store.ScopeAssetRow{
			{AssetType: "certificate", AssetID: "fp1", Report: healthReport("certificate", "fp1")},
			{
				AssetType: "crypto_library", AssetID: "lib-1",
				Report:      healthReport("crypto_library", "lib-1"),
				LibraryName: "openssl", LibraryVersion: "3.0.8",
			},
		},
		certs: map[string]*model.Certificate{
			"fp1": {
				FingerprintSHA256:  "fp1",
				Subject:            model.DistinguishedName{CommonName: "test.example.com", Full: "CN=test.example.com"},
				Issuer:             model.DistinguishedName{Full: "CN=CA"},
				NotBefore:          time.Now().Add(-time.Hour),
				NotAfter:           time.Now().Add(365 * 24 * time.Hour),
				SignatureAlgorithm: model.SigSHA256WithRSA,
			},
		},
		libs: map[string]*model.CryptoLibrary{
			"lib-1": {ID: "lib-1", LibraryName: "openssl", Version: "3.0.8"},
		},
	}

	gen, err := NewGeneratorWithSigning(config.CBOMSigningConfig{Enabled: false})
	if err != nil {
		t.Fatalf("NewGeneratorWithSigning: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Generate panicked with signing disabled: %v", r)
		}
	}()
	bom, err := gen.Generate(context.Background(), fake, &Scope{Name: "s", HostIDs: []string{"h1"}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if bom == nil || bom.Components == nil || len(*bom.Components) == 0 {
		t.Fatal("expected a non-empty BOM")
	}
}
