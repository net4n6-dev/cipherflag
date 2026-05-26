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
)

// TestBOMRefForSSHKeyType_MatchesAlgoToComponentBOMRef pins the
// consistency invariant that the algorithm BOMRef emitted for an SSH
// key (via bomRefForSSHKeyType) and the algorithm component's BOMRef
// (via algoToComponent) must match. If they differ, the SSH key's
// AlgorithmRef is a dangling reference in the CycloneDX BOM.
//
// v1.3.5 introduced a live regression: bomRefForSSHKeyType hardcoded
// synonym spellings like "algo:ecdsa-p256" while v1.3.5's
// algoToComponent canonicalises to "algo:ecdsa". The two sides no
// longer agreed, and every SSH-key component pointing at an ECDSA
// algorithm carried an unresolvable reference. Routing
// bomRefForSSHKeyType through pqc.Canonical restores the invariant.
func TestBOMRefForSSHKeyType_MatchesAlgoToComponentBOMRef(t *testing.T) {
	// Covers all five hardcoded cases from the pre-fix switch plus
	// one unknown (fallback) and one-that's-a-synonym-in-the-catalog
	// to make sure both sides agree after the fix.
	cases := []string{
		"ssh-ed25519",
		"ssh-rsa",
		"ecdsa-sha2-nistp256",
		"ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp521",
		"ssh-ed448",          // synonym in catalog — must also round-trip
		"sk-ssh-ed25519@openssh.com", // unknown — fallback must still round-trip
	}
	for _, kt := range cases {
		t.Run(kt, func(t *testing.T) {
			sshRef := bomRefForSSHKeyType(kt)
			// algoToComponent receives the raw (after algo: prefix is
			// stripped by generator.go). We re-derive that here.
			afterStrip := stripAlgoPrefix(sshRef)
			component := algoToComponent(afterStrip)
			if string(component.BOMRef) != sshRef {
				t.Errorf("dangling reference: key-type %q → SSH ref %q, but algoToComponent emits BOMRef %q",
					kt, sshRef, component.BOMRef)
			}
		})
	}
}

// stripAlgoPrefix mirrors generator.go's "algo:" prefix strip so the
// test exercises the same resolution path a real emit would take.
func stripAlgoPrefix(ref string) string {
	const prefix = "algo:"
	if len(ref) > len(prefix) && ref[:len(prefix)] == prefix {
		return ref[len(prefix):]
	}
	return ref
}
