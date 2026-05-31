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
package netwrix

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

func testdataDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "testdata")
}

func loadActivityRecord(t *testing.T, name string) ActivityRecord {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(testdataDir(), name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal fixture %s: %v", name, err)
	}
	rec := ActivityRecord{Raw: raw}
	if ts, ok := raw["EventTime"].(string); ok {
		rec.EventTime = parseRFC3339(ts)
	}
	return rec
}

func TestMapActivityRecord_Issued(t *testing.T) {
	rec := loadActivityRecord(t, "activity_record_issued.json")

	event, err := MapActivityRecord(rec)
	if err != nil {
		t.Fatalf("MapActivityRecord: %v", err)
	}
	if event.EventType != model.ADCSEventTypeIssued {
		t.Errorf("EventType = %q, want issued", event.EventType)
	}
	if event.CAName != "corp-CA01-CA" {
		t.Errorf("CAName = %q", event.CAName)
	}
	if event.TemplateName != "WebServer" {
		t.Errorf("TemplateName = %q", event.TemplateName)
	}
	if event.RequestedBy != "DOMAIN\\alice" {
		t.Errorf("RequestedBy = %q", event.RequestedBy)
	}
	if event.SerialNumber != "0a1b2c3d" {
		t.Errorf("SerialNumber = %q", event.SerialNumber)
	}
	if event.IssuerDN != "CN=corp-CA01-CA,DC=corp,DC=local" {
		t.Errorf("IssuerDN = %q", event.IssuerDN)
	}
	if event.SubjectDN != "CN=web-01.corp.local" {
		t.Errorf("SubjectDN = %q", event.SubjectDN)
	}
	if event.ID == "" {
		t.Error("expected non-empty ID")
	}
	if event.Source != "netwrix" {
		t.Errorf("Source = %q", event.Source)
	}
}

func TestMapActivityRecord_Renewed(t *testing.T) {
	rec := loadActivityRecord(t, "activity_record_renewed.json")
	event, err := MapActivityRecord(rec)
	if err != nil {
		t.Fatalf("MapActivityRecord: %v", err)
	}
	if event.EventType != model.ADCSEventTypeRenewed {
		t.Errorf("EventType = %q, want renewed", event.EventType)
	}
	if event.SerialNumber != "ff00ff00" {
		t.Errorf("SerialNumber = %q", event.SerialNumber)
	}
}

func TestMapActivityRecord_Revoked(t *testing.T) {
	rec := loadActivityRecord(t, "activity_record_revoked.json")
	event, err := MapActivityRecord(rec)
	if err != nil {
		t.Fatalf("MapActivityRecord: %v", err)
	}
	if event.EventType != model.ADCSEventTypeRevoked {
		t.Errorf("EventType = %q, want revoked", event.EventType)
	}
}

func TestMapActivityRecord_Deterministic(t *testing.T) {
	rec := loadActivityRecord(t, "activity_record_issued.json")
	a, _ := MapActivityRecord(rec)
	b, _ := MapActivityRecord(rec)
	if a.ID != b.ID {
		t.Errorf("expected deterministic ID, got %q vs %q", a.ID, b.ID)
	}
}

func TestMapActivityRecord_MissingSerial(t *testing.T) {
	rec := ActivityRecord{
		Raw: map[string]interface{}{
			"Action":     "Added",
			"ObjectType": "Certificate",
			"Where":      "ca",
		},
	}
	_, err := MapActivityRecord(rec)
	if err == nil {
		t.Fatal("expected error for record without SerialNumber")
	}
}

func TestMapActivityRecord_UnknownAction(t *testing.T) {
	rec := ActivityRecord{
		Raw: map[string]interface{}{
			"Action":     "SomethingElse",
			"ObjectType": "Certificate",
			"Where":      "ca",
			"Details":    map[string]interface{}{"SerialNumber": "abc", "Issuer": "CN=ca"},
		},
	}
	_, err := MapActivityRecord(rec)
	if err == nil {
		t.Fatal("expected error for unrecognized action")
	}
}
