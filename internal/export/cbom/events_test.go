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
	"context"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// eventsFakeStore is a minimal CryptoStore fake for event-generation tests.
// Uses interface embedding so unimplemented methods panic if called.
type eventsFakeStore struct {
	store.CryptoStore
	hostIDs []string
	rows    []store.ScopeAssetRow
	lib     *model.CryptoLibrary
}

func (f *eventsFakeStore) GetHostIDsByPatterns(_ context.Context, _ []string) ([]string, error) {
	return f.hostIDs, nil
}
func (f *eventsFakeStore) ListScopeAssets(_ context.Context, _ store.ScopeAssetQuery) ([]store.ScopeAssetRow, error) {
	return f.rows, nil
}
func (f *eventsFakeStore) GetCryptoLibrary(_ context.Context, id string) (*model.CryptoLibrary, error) {
	if f.lib != nil && f.lib.ID == id {
		return f.lib, nil
	}
	return nil, nil
}

func TestGenerateEvents_AssetGranularity(t *testing.T) {
	g := &Generator{}
	lib := &model.CryptoLibrary{ID: "lib1", LibraryName: "openssl", Version: "1.0.1c", PQCCapable: false}
	report := model.AssetHealthReport{
		AssetType: "crypto_library", AssetID: "lib1",
		Grade: "F", Score: 0, PQCStatus: "vulnerable",
		RiskScore: 95,
		Findings: []model.HealthFinding{
			{RuleID: "LIB-001", Title: "Critical CVE", Severity: model.SeverityCritical,
				Category: model.CategoryAgility, Deduction: 50, ImmediateFail: true},
		},
	}
	fs := &eventsFakeStore{
		hostIDs: []string{"h1"},
		rows:    []store.ScopeAssetRow{{AssetType: "crypto_library", AssetID: "lib1", Report: report}},
		lib:     lib,
	}
	scope := &Scope{Name: "test"}
	events, err := g.GenerateEvents(context.Background(), fs, scope, "asset")
	if err != nil {
		t.Fatalf("GenerateEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("event count = %d, want 1", len(events))
	}
	e := events[0]
	if e.EventType != "asset" {
		t.Errorf("EventType = %q, want asset", e.EventType)
	}
	if e.Severity != "Critical" {
		t.Errorf("Severity = %q, want Critical (worst)", e.Severity)
	}
	if e.Payload["library_name"] != "openssl" {
		t.Errorf("payload library_name = %v, want openssl", e.Payload["library_name"])
	}
	findings, ok := e.Payload["findings"].([]map[string]interface{})
	if !ok || len(findings) != 1 {
		t.Errorf("findings array malformed: %T len=%d", e.Payload["findings"], len(findings))
	}
}

func TestGenerateEvents_FindingGranularity(t *testing.T) {
	g := &Generator{}
	lib := &model.CryptoLibrary{ID: "lib1", LibraryName: "openssl", Version: "1.0.1c"}
	report := model.AssetHealthReport{
		AssetType: "crypto_library", AssetID: "lib1",
		Grade: "F", Score: 0, RiskScore: 95,
		Findings: []model.HealthFinding{
			{RuleID: "LIB-001", Severity: model.SeverityCritical},
			{RuleID: "LIB-003", Severity: model.SeverityHigh},
		},
	}
	fs := &eventsFakeStore{
		hostIDs: []string{"h1"},
		rows:    []store.ScopeAssetRow{{AssetType: "crypto_library", AssetID: "lib1", Report: report}},
		lib:     lib,
	}
	scope := &Scope{Name: "test"}
	events, err := g.GenerateEvents(context.Background(), fs, scope, "finding")
	if err != nil {
		t.Fatalf("GenerateEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("event count = %d, want 2", len(events))
	}
	for _, e := range events {
		if e.EventType != "finding" {
			t.Errorf("EventType = %q, want finding", e.EventType)
		}
		if e.Payload["asset_id"] != "lib1" {
			t.Errorf("asset_id = %v, want lib1", e.Payload["asset_id"])
		}
	}
	if events[0].Payload["rule_id"] != "LIB-001" {
		t.Errorf("events[0] rule_id = %v, want LIB-001", events[0].Payload["rule_id"])
	}
	if events[1].Payload["rule_id"] != "LIB-003" {
		t.Errorf("events[1] rule_id = %v, want LIB-003", events[1].Payload["rule_id"])
	}
}

func TestGenerateEvents_InvalidGranularity(t *testing.T) {
	g := &Generator{}
	_, err := g.GenerateEvents(context.Background(), &eventsFakeStore{}, &Scope{Name: "x"}, "bogus")
	if err == nil {
		t.Fatal("expected error for invalid granularity")
	}
}

func TestWorstSeverity(t *testing.T) {
	tests := []struct {
		name     string
		findings []model.HealthFinding
		want     string
	}{
		{"none", nil, "Info"},
		{"one medium", []model.HealthFinding{{Severity: model.SeverityMedium}}, "Medium"},
		{"critical wins", []model.HealthFinding{
			{Severity: model.SeverityLow}, {Severity: model.SeverityCritical}, {Severity: model.SeverityHigh},
		}, "Critical"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := worstSeverity(tt.findings); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
