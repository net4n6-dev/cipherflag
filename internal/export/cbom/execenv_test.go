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

func TestExecutionEnvFromProvenance(t *testing.T) {
	cases := []struct {
		source string
		want   cdx.CryptoExecutionEnvironment
	}{
		{"file_scanner", cdx.CryptoExecutionEnvironmentSoftwarePlainRAM},
		{"zeek_passive", cdx.CryptoExecutionEnvironmentSoftwarePlainRAM},
		{"ct_log", cdx.CryptoExecutionEnvironmentSoftwarePlainRAM},
		{"ciphertrust_manager", cdx.CryptoExecutionEnvironmentHardware},
		{"tpm_scanner", cdx.CryptoExecutionEnvironmentSoftwareTEE},
		// Unknown → default to software-plain-ram (conservative).
		{"weird_source", cdx.CryptoExecutionEnvironmentSoftwarePlainRAM},
		{"", cdx.CryptoExecutionEnvironmentSoftwarePlainRAM},
	}
	for _, tc := range cases {
		t.Run(tc.source, func(t *testing.T) {
			require.Equal(t, tc.want, executionEnvFromProvenance(tc.source))
		})
	}
}

func TestReduceExecEnv(t *testing.T) {
	t.Run("empty sources → software-plain-ram", func(t *testing.T) {
		got := reduceExecEnv(nil)
		require.Equal(t, cdx.CryptoExecutionEnvironmentSoftwarePlainRAM, got)
	})

	t.Run("single software source → software-plain-ram", func(t *testing.T) {
		got := reduceExecEnv([]string{"file_scanner"})
		require.Equal(t, cdx.CryptoExecutionEnvironmentSoftwarePlainRAM, got)
	})

	t.Run("all hardware sources → hardware", func(t *testing.T) {
		got := reduceExecEnv([]string{"aws_kms", "aws_kms"})
		require.Equal(t, cdx.CryptoExecutionEnvironmentHardware, got)
	})

	t.Run("all TEE sources → software-tee", func(t *testing.T) {
		got := reduceExecEnv([]string{"tpm_scanner", "tpm_scanner"})
		require.Equal(t, cdx.CryptoExecutionEnvironmentSoftwareTEE, got)
	})

	t.Run("mixed hardware + software → software-plain-ram (conservative)", func(t *testing.T) {
		got := reduceExecEnv([]string{"aws_kms", "file_scanner"})
		require.Equal(t, cdx.CryptoExecutionEnvironmentSoftwarePlainRAM, got)
	})

	t.Run("mixed hardware + TEE → software-plain-ram (conservative)", func(t *testing.T) {
		got := reduceExecEnv([]string{"luna_hsm", "tpm_scanner"})
		require.Equal(t, cdx.CryptoExecutionEnvironmentSoftwarePlainRAM, got)
	})

	t.Run("mixed software + TEE → software-plain-ram (conservative)", func(t *testing.T) {
		got := reduceExecEnv([]string{"file_scanner", "tpm_scanner"})
		require.Equal(t, cdx.CryptoExecutionEnvironmentSoftwarePlainRAM, got)
	})

	t.Run("single hardware source → hardware", func(t *testing.T) {
		got := reduceExecEnv([]string{"ciphertrust_manager"})
		require.Equal(t, cdx.CryptoExecutionEnvironmentHardware, got)
	})
}
