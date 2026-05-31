// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package sentinelone

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestMapRSOOutput_ParsesNDJSONIntoDiscoveryResult(t *testing.T) {
	data, err := os.ReadFile("testdata/rso_results_sample.ndjson")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	result, parseErrs, err := MapRSOOutput(bytes.NewReader(data), "sentinelone", "host-1")
	if err != nil {
		t.Fatalf("MapRSOOutput: %v", err)
	}
	if len(parseErrs) != 0 {
		t.Errorf("unexpected parse errors: %v", parseErrs)
	}
	if len(result.Libraries) != 1 || result.Libraries[0].LibraryName != "openssl" {
		t.Errorf("libraries = %+v", result.Libraries)
	}
	if len(result.SSHKeys) != 1 || result.SSHKeys[0].FilePath != "/home/alice/.ssh/id_ed25519" {
		t.Errorf("ssh_keys = %+v", result.SSHKeys)
	}
	if len(result.Certificates) != 1 || result.Certificates[0].FingerprintSHA256 != "def" {
		t.Errorf("certs = %+v", result.Certificates)
	}
	if result.Source != "sentinelone" || result.Hostname != "host-1" {
		t.Errorf("envelope = %+v", *result)
	}
}

func TestMapRSOOutput_ReportsMalformedLines(t *testing.T) {
	body := strings.NewReader(`{"type":"library","name":"openssl","version":"3"}` + "\n" + `{broken json` + "\n")
	result, parseErrs, err := MapRSOOutput(body, "sentinelone", "h")
	if err != nil {
		t.Fatalf("MapRSOOutput: %v", err)
	}
	if len(result.Libraries) != 1 {
		t.Errorf("libraries = %d", len(result.Libraries))
	}
	if len(parseErrs) != 1 {
		t.Errorf("parseErrs = %d", len(parseErrs))
	}
}
