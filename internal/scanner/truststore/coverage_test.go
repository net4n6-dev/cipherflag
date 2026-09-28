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

package truststore

import (
	"reflect"
	"testing"
)

// scan-truststore removes trust-store rows a scan no longer saw, but only
// for sources the scan actually covered: a source whose discoverer failed
// was not looked at, and pruning it would wipe the host's inventory.

func results(failed ...string) map[string]DiscovererOutcome {
	out := map[string]DiscovererOutcome{}
	for _, name := range []string{"linux_os_bundles", "macos_keychains", "jvm_keystores", "runtime_bundles"} {
		out[name] = DiscovererOutcome{}
	}
	for _, name := range failed {
		out[name] = DiscovererOutcome{Err: "boom"}
	}
	return out
}

// Every discoverer New registers must be mapped to the source it produces,
// or its rows could never be reconciled (and private keys never would be).
func TestEveryDiscovererIsMappedToASource(t *testing.T) {
	mapped := map[string]bool{}
	for _, ds := range trustSourceDiscoverers {
		for _, d := range ds {
			mapped[d] = true
		}
	}
	for _, d := range New(nil, nil, nil).discoverers {
		if !mapped[d.Name] {
			t.Errorf("discoverer %q is not in trustSourceDiscoverers", d.Name)
		}
	}
}

func TestCoveredSources(t *testing.T) {
	cases := []struct {
		name        string
		results     map[string]DiscovererOutcome
		wantTrust   []string
		wantPrivate bool
	}{
		{"every discoverer succeeded", results(), []string{"jvm_cacerts", "lang_runtime", "os_bundle"}, true},
		{"JVM failed", results("jvm_keystores"), []string{"lang_runtime", "os_bundle"}, false},
		{"either OS discoverer failed leaves os_bundle unscanned", results("macos_keychains"), []string{"jvm_cacerts", "lang_runtime"}, false},
		{"runtime failed", results("runtime_bundles"), []string{"jvm_cacerts", "os_bundle"}, false},
		{"no discoverer ran", nil, nil, false},
		{"a discoverer that did not report is not covered", map[string]DiscovererOutcome{"jvm_keystores": {}}, []string{"jvm_cacerts"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trust, private := ScanResult{DiscovererResults: tc.results}.CoveredSources()
			if !reflect.DeepEqual(trust, tc.wantTrust) {
				t.Errorf("trust sources = %v, want %v", trust, tc.wantTrust)
			}
			if private != tc.wantPrivate {
				t.Errorf("private keys covered = %v, want %v", private, tc.wantPrivate)
			}
		})
	}
}
