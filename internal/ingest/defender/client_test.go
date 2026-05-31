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
package defender

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMockClient_ReturnsConfiguredRows(t *testing.T) {
	m := NewMockClient()
	m.Rows = []QueryRow{
		{Columns: map[string]any{"DeviceId": "d1", "SoftwareName": "OpenSSL"}},
		{Columns: map[string]any{"DeviceId": "d2", "SoftwareName": "GnuTLS"}},
	}

	rows, err := m.RunAdvancedQuery(context.Background(), "DeviceTvmSoftwareInventory | take 10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("got %d rows, want 2", len(rows))
	}
	if m.CallCount != 1 {
		t.Errorf("CallCount = %d, want 1", m.CallCount)
	}
	if m.LastQuery == "" {
		t.Error("expected LastQuery to be captured")
	}
}

func TestMockClient_ReturnsConfiguredError(t *testing.T) {
	m := NewMockClient()
	m.Err = errors.New("boom")

	_, err := m.RunAdvancedQuery(context.Background(), "")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRateLimitError_String(t *testing.T) {
	e := &RateLimitError{RetryAfter: 5 * time.Second}
	if e.Error() == "" {
		t.Error("Error() should return non-empty string")
	}
	e2 := &RateLimitError{}
	if e2.Error() == "" {
		t.Error("Error() should return non-empty string when RetryAfter is zero")
	}
}
