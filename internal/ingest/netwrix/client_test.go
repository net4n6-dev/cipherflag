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
	"context"
	"errors"
	"testing"
	"time"
)

func TestMockClient_ReturnsConfiguredRecords(t *testing.T) {
	m := NewMockClient()
	m.Records = []ActivityRecord{
		{EventTime: time.Now().UTC(), Raw: map[string]interface{}{"foo": "bar"}},
		{EventTime: time.Now().UTC(), Raw: map[string]interface{}{"foo": "baz"}},
	}

	records, err := m.SearchActivity(context.Background(), SearchFilter{DataSource: "Active Directory"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 2 {
		t.Errorf("got %d records, want 2", len(records))
	}
	if m.CallCount != 1 {
		t.Errorf("CallCount = %d, want 1", m.CallCount)
	}
	if m.LastFilter.DataSource != "Active Directory" {
		t.Errorf("LastFilter.DataSource = %q", m.LastFilter.DataSource)
	}
}

func TestMockClient_ReturnsConfiguredError(t *testing.T) {
	m := NewMockClient()
	m.Err = errors.New("boom")

	_, err := m.SearchActivity(context.Background(), SearchFilter{})
	if err == nil {
		t.Fatal("expected error")
	}
}
