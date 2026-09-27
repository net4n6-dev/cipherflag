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

package multi

import (
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/config"
)

func TestValidateGroup(t *testing.T) {
	valid := config.CtMultiGroupConfig{
		Domain: "example.com",
		Children: []config.CtMultiChildConfig{
			{Crtsh: &config.CtMultiChildCrtshConfig{}},
			{Static: &config.CtMultiChildStaticConfig{Domain: "example.com", LogURL: "https://log/", PublicKeyPEM: "pem"}},
		},
	}
	if err := ValidateGroup(valid); err != nil {
		t.Fatalf("expected valid group to pass, got %v", err)
	}

	tooFewChildren := config.CtMultiGroupConfig{
		Domain:   "example.com",
		Children: []config.CtMultiChildConfig{{Crtsh: &config.CtMultiChildCrtshConfig{}}},
	}
	if err := ValidateGroup(tooFewChildren); err == nil {
		t.Fatal("expected error for <2 children")
	}

	mismatchedDomain := config.CtMultiGroupConfig{
		Domain: "example.com",
		Children: []config.CtMultiChildConfig{
			{Crtsh: &config.CtMultiChildCrtshConfig{}},
			{Static: &config.CtMultiChildStaticConfig{Domain: "other.com", LogURL: "https://log/", PublicKeyPEM: "pem"}},
		},
	}
	if err := ValidateGroup(mismatchedDomain); err == nil {
		t.Fatal("expected error for mismatched child domain")
	}

	ambiguousChild := config.CtMultiGroupConfig{
		Domain: "example.com",
		Children: []config.CtMultiChildConfig{
			{Crtsh: &config.CtMultiChildCrtshConfig{}, Static: &config.CtMultiChildStaticConfig{}},
			{Certspotter: &config.CtMultiChildCertspotterConfig{}},
		},
	}
	if err := ValidateGroup(ambiguousChild); err == nil {
		t.Fatal("expected error for child with two non-nil kinds")
	}
}
