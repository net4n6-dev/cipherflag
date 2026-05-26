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

package store

import (
	"context"
	"testing"
)

// fakePatternResolver is used to unit-test GetHostIDsByPatterns SQL conversion.
// The actual SQL execution is tested in integration tests.

func TestGetHostIDsByPatterns_EmptyPatterns(t *testing.T) {
	s := &PostgresStore{} // pool is nil — safe because empty patterns returns early
	ids, err := s.GetHostIDsByPatterns(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("expected empty result for nil patterns, got %v", ids)
	}
}

func TestScopeAssetQuery_ZeroHostIDs(t *testing.T) {
	s := &PostgresStore{}
	rows, err := s.ListScopeAssets(context.Background(), ScopeAssetQuery{HostIDs: nil})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rows != nil {
		t.Errorf("expected nil for empty host IDs, got %v", rows)
	}
}
