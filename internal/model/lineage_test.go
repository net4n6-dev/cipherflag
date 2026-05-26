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

func TestLineageLink_JSONRoundTrip(t *testing.T) {
	now := time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)
	orig := LineageLink{
		ID:            "L-1",
		FromAssetType: "repository",
		FromAssetID:   "repo-uuid",
		ToAssetType:   "certificate",
		ToAssetID:     "sha256:deadbeef",
		LinkType:      "cert_fingerprint_match",
		Confidence:    1.0,
		Evidence: map[string]any{
			"commit_sha": "abc123",
			"path":       "secrets/prod.pem",
			"scan_id":    "scan-uuid",
		},
		CreatedAt: now,
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got LineageLink
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.FromAssetType != "repository" || got.LinkType != "cert_fingerprint_match" || got.Confidence != 1.0 {
		t.Errorf("round-trip mismatch: got %+v", got)
	}
	if got.Evidence["commit_sha"] != "abc123" {
		t.Errorf("evidence commit_sha mismatch: got %v", got.Evidence["commit_sha"])
	}
}
