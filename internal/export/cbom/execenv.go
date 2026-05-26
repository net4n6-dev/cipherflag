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

import cdx "github.com/CycloneDX/cyclonedx-go"

// executionEnvFromProvenance maps an asset_provenance.source value to
// the CycloneDX CryptoExecutionEnvironment enum. Conservative default:
// SoftwarePlainRAM when the source doesn't carry positive hardware
// evidence. Updates as new sources (TPM scanners, KMS connectors)
// land — keep the switch exhaustive over enumerated source values.
func executionEnvFromProvenance(source string) cdx.CryptoExecutionEnvironment {
	switch source {
	case "ciphertrust_manager", "venafi_machine_identity", "aws_kms",
		"azure_keyvault", "gcp_kms", "luna_hsm":
		return cdx.CryptoExecutionEnvironmentHardware
	case "tpm_scanner":
		return cdx.CryptoExecutionEnvironmentSoftwareTEE
	default:
		// file scanner, Zeek, CT logs, B1-B5 detectors, and unknown
		// sources all map to plain-RAM software execution.
		return cdx.CryptoExecutionEnvironmentSoftwarePlainRAM
	}
}

// reduceExecEnv applies the same monomorphic-only policy as
// certificationLevel: only set hardware/TEE when ALL sources agree.
// Mixed observations conservatively default to software-plain-ram.
func reduceExecEnv(sources []string) cdx.CryptoExecutionEnvironment {
	if len(sources) == 0 {
		return cdx.CryptoExecutionEnvironmentSoftwarePlainRAM
	}
	first := executionEnvFromProvenance(sources[0])
	for _, s := range sources[1:] {
		if executionEnvFromProvenance(s) != first {
			return cdx.CryptoExecutionEnvironmentSoftwarePlainRAM
		}
	}
	return first
}
