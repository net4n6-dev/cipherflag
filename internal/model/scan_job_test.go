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

func TestScanJob_JSONRoundTrip(t *testing.T) {
	started := time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)
	completed := started.Add(90 * time.Second)
	orig := ScanJob{
		ID:             "job-1",
		RepoID:         "repo-1",
		ScanMode:       ScanModeDeterministicOnly,
		Trigger:        TriggerManual,
		BranchRef:      "main",
		Status:         ScanStatusRunning,
		WorkerID:       "worker-a",
		StartedAt:      &started,
		CompletedAt:    &completed,
		SummaryJSON:    map[string]any{"blobs": 42},
		LLMTokensSpent: 0,
		LLMCostUSD:     0,
		FindingsCount:  0,
		ErrorText:      "",
		CreatedAt:      started,
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ScanJob
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.RepoID != "repo-1" || got.Status != ScanStatusRunning || got.SummaryJSON["blobs"].(float64) != 42 {
		t.Errorf("round-trip mismatch: got %+v", got)
	}
}

func TestScanJob_JSONRoundTrip_RetryFields(t *testing.T) {
	ts := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	orig := ScanJob{
		ID:           "j1",
		RetryCount:   3,
		NextRetryAt:  &ts,
		FailureClass: FailureClassTransient,
	}
	data, err := json.Marshal(&orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ScanJob
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.RetryCount != 3 {
		t.Errorf("RetryCount: got %d, want 3", got.RetryCount)
	}
	if got.NextRetryAt == nil || !got.NextRetryAt.Equal(ts) {
		t.Errorf("NextRetryAt: got %v, want %v", got.NextRetryAt, ts)
	}
	if got.FailureClass != FailureClassTransient {
		t.Errorf("FailureClass: got %q, want %q", got.FailureClass, FailureClassTransient)
	}
}

func TestScanMode_Validation(t *testing.T) {
	for _, m := range []string{"deterministic_only", "triage", "enrichment", "deep"} {
		if !IsValidScanMode(m) {
			t.Errorf("%q should be valid", m)
		}
	}
	for _, m := range []string{"", "foo", "DEEP", "deterministic"} {
		if IsValidScanMode(m) {
			t.Errorf("%q should be invalid", m)
		}
	}
}

func TestScanStatus_TerminalDetection(t *testing.T) {
	terminal := map[string]bool{
		"queued":    false,
		"running":   false,
		"completed": true,
		"failed":    true,
		"cancelled": true,
	}
	for st, want := range terminal {
		if got := IsTerminalScanStatus(st); got != want {
			t.Errorf("IsTerminalScanStatus(%q) = %v, want %v", st, got, want)
		}
	}
}
