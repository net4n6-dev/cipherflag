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
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestCertificationLevel_MonomorphicFIPSValidated(t *testing.T) {
	// All observations agree on fips140-3-l1 → certificationLevel = fips140-3-l1
	obs := []AlgorithmObservation{
		{Algorithm: "aes-128", Library: "openssl-fips-3.0", FIPSLevel: "fips140-3-l1"},
		{Algorithm: "aes-128", Library: "rhel-openssl-fips", FIPSLevel: "fips140-3-l1"},
	}
	lvl := certificationLevelForAlgo("aes-128", obs)
	require.Equal(t, cdx.CryptoCertificationLevelFIPS140_3_L1, lvl)
}

func TestCertificationLevel_MixedObservationsOmits(t *testing.T) {
	obs := []AlgorithmObservation{
		{Algorithm: "aes-128", Library: "openssl-fips-3.0", FIPSLevel: "fips140-3-l1"},
		{Algorithm: "aes-128", Library: "openssl-3.0", FIPSLevel: ""}, // not validated
	}
	lvl := certificationLevelForAlgo("aes-128", obs)
	require.Equal(t, cdx.CryptoCertificationLevelNone, lvl,
		"mixed observations (some FIPS, some not) → omit certification level")
}

func TestCertificationLevel_NoObservationsOmits(t *testing.T) {
	lvl := certificationLevelForAlgo("aes-128", nil)
	require.Equal(t, cdx.CryptoCertificationLevelNone, lvl)
}

func TestCertificationLevel_MixedFIPSLevelsOmits(t *testing.T) {
	// Different FIPS levels disagree → None (don't pick one arbitrarily)
	obs := []AlgorithmObservation{
		{Algorithm: "aes-128", Library: "lib-a", FIPSLevel: "fips140-3-l1"},
		{Algorithm: "aes-128", Library: "lib-b", FIPSLevel: "fips140-2-l1"},
	}
	lvl := certificationLevelForAlgo("aes-128", obs)
	require.Equal(t, cdx.CryptoCertificationLevelNone, lvl,
		"disagreeing FIPS levels → None")
}

func TestCertificationLevel_SingleObservation(t *testing.T) {
	obs := []AlgorithmObservation{
		{Algorithm: "sha256", Library: "openssl-fips-3.0", FIPSLevel: "fips140-2-l3"},
	}
	lvl := certificationLevelForAlgo("sha256", obs)
	require.Equal(t, cdx.CryptoCertificationLevelFIPS140_2_L3, lvl)
}

func TestCertificationLevel_ObservationsForDifferentAlgosIgnored(t *testing.T) {
	// Observations for a different algorithm should not count toward the query algo.
	obs := []AlgorithmObservation{
		{Algorithm: "sha256", Library: "openssl-fips-3.0", FIPSLevel: "fips140-3-l1"},
		{Algorithm: "rsa", Library: "openssl-fips-3.0", FIPSLevel: "fips140-3-l1"},
	}
	// Querying for "aes-128" — no matching observations
	lvl := certificationLevelForAlgo("aes-128", obs)
	require.Equal(t, cdx.CryptoCertificationLevelNone, lvl)
}

func TestCertificationLevel_OnlyNonValidatedObservations(t *testing.T) {
	// All FIPSLevel are empty → monomorphic empty → None
	obs := []AlgorithmObservation{
		{Algorithm: "aes-128", Library: "openssl-3.0", FIPSLevel: ""},
		{Algorithm: "aes-128", Library: "libc", FIPSLevel: ""},
	}
	lvl := certificationLevelForAlgo("aes-128", obs)
	require.Equal(t, cdx.CryptoCertificationLevelNone, lvl)
}

func TestMapFIPSStringToCDX(t *testing.T) {
	cases := []struct {
		input string
		want  cdx.CryptoCertificationLevel
	}{
		{"fips140-3-l1", cdx.CryptoCertificationLevelFIPS140_3_L1},
		{"fips140-3-l2", cdx.CryptoCertificationLevelFIPS140_3_L2},
		{"fips140-3-l3", cdx.CryptoCertificationLevelFIPS140_3_L3},
		{"fips140-3-l4", cdx.CryptoCertificationLevelFIPS140_3_L4},
		{"fips140-2-l1", cdx.CryptoCertificationLevelFIPS140_2_L1},
		{"fips140-2-l2", cdx.CryptoCertificationLevelFIPS140_2_L2},
		{"fips140-2-l3", cdx.CryptoCertificationLevelFIPS140_2_L3},
		{"fips140-2-l4", cdx.CryptoCertificationLevelFIPS140_2_L4},
		{"fips140-1-l1", cdx.CryptoCertificationLevelFIPS140_1_L1},
		{"fips140-1-l2", cdx.CryptoCertificationLevelFIPS140_1_L2},
		{"fips140-1-l3", cdx.CryptoCertificationLevelFIPS140_1_L3},
		{"fips140-1-l4", cdx.CryptoCertificationLevelFIPS140_1_L4},
		{"", cdx.CryptoCertificationLevelNone},
		{"unknown-string", cdx.CryptoCertificationLevelNone},
		{"FIPS140-3-L1", cdx.CryptoCertificationLevelNone}, // wrong case → None
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := mapFIPSStringToCDX(tc.input)
			require.Equal(t, tc.want, got)
		})
	}
}
