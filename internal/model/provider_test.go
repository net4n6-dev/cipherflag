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

package model

import (
	"encoding/json"
	"testing"
	"time"
)

func TestProvider_JSONRoundTrip(t *testing.T) {
	now := time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)
	orig := Provider{
		ID:            "11111111-1111-1111-1111-111111111111",
		Kind:          "github",
		BaseURL:       "https://github.com",
		AuthSecretRef: "vault:secret/data/cipherflag/github#pat",
		DisplayName:   "Acme GitHub Org",
		CreatedAt:     now,
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Provider
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Kind != "github" || got.BaseURL != "https://github.com" || got.DisplayName != "Acme GitHub Org" {
		t.Errorf("round-trip mismatch: got %+v", got)
	}
}

func TestValidProviderKinds_AllRecognised(t *testing.T) {
	for _, k := range []string{
		"github",
		"github_enterprise",
		"gitlab",
		"gitlab_self_managed",
		"bitbucket",
		"bitbucket_server",
		"container_registry",
		"network_target",
	} {
		if !IsValidProviderKind(k) {
			t.Errorf("expected %q to be valid provider kind", k)
		}
	}
	for _, k := range []string{"", "gitlabx", "github-enterprise", "GITHUB"} {
		if IsValidProviderKind(k) {
			t.Errorf("expected %q to be invalid provider kind", k)
		}
	}
}
