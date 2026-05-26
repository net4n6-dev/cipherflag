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
	"strings"
	"testing"
	"time"
)

func TestRepository_JSONRoundTrip(t *testing.T) {
	now := time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)
	orig := Repository{
		ID:              "11111111-1111-1111-1111-111111111111",
		ProviderID:      "22222222-2222-2222-2222-222222222222",
		URL:             "https://github.com/acme/widget",
		DefaultBranch:   "main",
		ScheduleCron:    "0 3 * * *",
		DefaultScanMode: "enrichment",
		Tags:            map[string]string{"env": "prod", "team": "platform"},
		AuthSecretRef:   "vault:secret/data/github#pat",
		LastScannedSHA:  "abc123",
		LastScanAt:      &now,
		FirstSeen:       now,
		LastSeen:        now,
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Repository
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.URL != orig.URL || got.Tags["env"] != "prod" || got.LastScannedSHA != "abc123" {
		t.Errorf("round-trip mismatch: got %+v", got)
	}
}

func TestRepository_ZeroValue_OmitsOptionalFields(t *testing.T) {
	r := Repository{
		ID:            "a",
		ProviderID:    "b",
		URL:           "u",
		DefaultBranch: "main",
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, unwanted := range []string{`"schedule_cron":""`, `"last_scanned_sha":""`, `"auth_secret_ref":""`} {
		if strings.Contains(s, unwanted) {
			t.Errorf("expected %q omitted from %s", unwanted, s)
		}
	}
}
