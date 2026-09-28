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

package handler

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom/cbomtest"
)

// signingGenerator is a Generator signing with a fresh test key, as serve
// builds one at startup.
func signingGenerator(t *testing.T) *cbom.Generator {
	t.Helper()
	signer, err := cbom.LoadSigner(cbomtest.SigningConfig(t))
	require.NoError(t, err)
	return cbom.NewGeneratorFromSigner(signer)
}

// Each CBOM download handler used to load the signing key itself (and panic
// if that failed), separately from serve's startup check. serve now loads
// the key once; both handlers sign with the generator they are given, so
// every download is signed with the key serve logged.
func TestCBOMHandlersUseTheGeneratorTheyAreGiven(t *testing.T) {
	signing := cbomtest.SigningConfig(t)
	signer, err := cbom.LoadSigner(signing)
	require.NoError(t, err)
	gen := cbom.NewGeneratorFromSigner(signer)

	h := NewCBOMHandler(nil, &config.CBOMConfig{Signing: signing}, gen, nil)
	require.Same(t, gen, h.gen)

	r := NewRepoCBOMHandler(&fakeRepoCBOMStore{}, gen)
	require.Same(t, gen, r.gen)
}
