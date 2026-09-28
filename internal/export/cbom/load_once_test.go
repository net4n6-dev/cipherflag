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
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/net4n6-dev/cipherflag/internal/config"
)

// serve used to load the signing key up to four times: the startup check,
// then NewRuntime and each CBOM download handler on its own. A key file
// that changed during startup could make them sign with different keys, or
// make a constructor panic after the check had passed. The key is now loaded
// once and the one Generator is handed to every consumer.

func TestNewGeneratorFromSigner(t *testing.T) {
	path, pub := makeEd25519PEM(t)
	signer, err := LoadSigner(config.CBOMSigningConfig{Enabled: true, Signer: "file", Path: path})
	require.NoError(t, err)

	g := NewGeneratorFromSigner(signer)
	require.Equal(t, pub, signerPub(t, g.signer))
	require.NotNil(t, g.libraryFIPSLevel, "the FIPS lookup is wired in as NewGenerator does")

	require.Nil(t, NewGeneratorFromSigner(nil).signer, "a nil signer is an unsigned generator")
}

// The runtime signs with the generator it is given and never reads the key
// again: replacing the key file afterwards changes nothing.
func TestNewRuntime_UsesTheGeneratorItIsGiven(t *testing.T) {
	path, pub := makeEd25519PEM(t)
	signing := config.CBOMSigningConfig{Enabled: true, Signer: "file", Path: path}
	signer, err := LoadSigner(signing)
	require.NoError(t, err)
	gen := NewGeneratorFromSigner(signer)

	// The file now holds a different key (or nothing usable at all).
	require.NoError(t, os.WriteFile(path, []byte("rotated mid-startup"), 0600))

	rt := NewRuntime(&fakeSchedStore{}, &config.CBOMConfig{Signing: signing}, gen)
	require.Same(t, gen, rt.generator, "the runtime must use the generator serve loaded")
	require.Equal(t, pub, signerPub(t, rt.generator.(*Generator).signer))
}
