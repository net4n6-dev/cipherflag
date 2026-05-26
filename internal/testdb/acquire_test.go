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

package testdb

import (
	"fmt"
	"strings"
	"testing"
)

func TestSlugify(t *testing.T) {
	cases := []struct {
		pkgPath string
		want    string
	}{
		{"internal/store", "test_internal_store"},
		{"internal/ingest/tanium", "test_internal_ingest_tanium"},
		{"internal/api/handler", "test_internal_api_handler"},
		{"internal/scanner/detect/b1", "test_internal_scanner_detect_b1"},
		{"internal/snapshot", "test_internal_snapshot"},
	}
	for _, tc := range cases {
		t.Run(tc.pkgPath, func(t *testing.T) {
			got := slugify(tc.pkgPath)
			if got != tc.want {
				t.Errorf("slugify(%q) = %q, want %q", tc.pkgPath, got, tc.want)
			}
		})
	}
}

func TestSlugify_TruncatesLongPaths(t *testing.T) {
	// 60-char path → slug must be ≤50 chars (leaves room under NAMEDATALEN=64).
	long := "internal/very/deeply/nested/package/path/that/is/definitely/too/long"
	got := slugify(long)
	if len(got) > 50 {
		t.Errorf("slugify(%q) returned %d chars, want ≤50: %q", long, len(got), got)
	}
	if !strings.HasPrefix(got, "test_") {
		t.Errorf("slugify should always start with test_, got %q", got)
	}
}

func TestSlugify_RejectsInvalidChars(t *testing.T) {
	// Non-alphanumeric (other than underscore) should become underscore.
	got := slugify("internal/foo-bar.baz")
	if strings.ContainsAny(got, "-.") {
		t.Errorf("slugify should replace - and . with _: got %q", got)
	}
}

func TestAppendSearchPath(t *testing.T) {
	cases := []struct {
		name   string
		dsn    string
		schema string
		want   string
	}{
		{
			"no existing query string",
			"postgres://u:p@h/db",
			"test_foo",
			"postgres://u:p@h/db?options=-c+search_path%3Dtest_foo",
		},
		{
			"existing query string preserved",
			"postgres://u:p@h/db?sslmode=disable",
			"test_foo",
			// net/url's Encode() sorts query params alphabetically per RFC 3986
			"postgres://u:p@h/db?options=-c+search_path%3Dtest_foo&sslmode=disable",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := appendSearchPath(tc.dsn, tc.schema)
			if got != tc.want {
				t.Errorf("appendSearchPath(%q, %q) = %q, want %q", tc.dsn, tc.schema, got, tc.want)
			}
		})
	}
}

func TestAppendPoolMaxConns(t *testing.T) {
	dsn := "postgres://u:p@h/db?sslmode=disable"
	got := appendPoolMaxConns(dsn, 4)
	// net/url's Encode() sorts query params alphabetically per RFC 3986
	want := "postgres://u:p@h/db?pool_max_conns=4&sslmode=disable"
	if got != want {
		t.Errorf("appendPoolMaxConns: got %q, want %q", got, want)
	}
}

func TestAppendPoolMaxConns_NoExistingQuery(t *testing.T) {
	got := appendPoolMaxConns("postgres://u:p@h/db", 4)
	want := "postgres://u:p@h/db?pool_max_conns=4"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRegisterSchema_UniqueOK(t *testing.T) {
	resetRegistry(t)
	registerSchema("internal/foo", "test_internal_foo")
	registerSchema("internal/bar", "test_internal_bar")
	// No panic → pass.
}

func TestRegisterSchema_SamePathTwiceOK(t *testing.T) {
	resetRegistry(t)
	registerSchema("internal/foo", "test_internal_foo")
	registerSchema("internal/foo", "test_internal_foo") // idempotent re-register
	// No panic → pass.
}

func TestRegisterSchema_CollisionPanics(t *testing.T) {
	resetRegistry(t)
	registerSchema("internal/foo", "test_conflict")
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic, got none")
		}
		msg := fmt.Sprint(r)
		if !strings.Contains(msg, "internal/foo") || !strings.Contains(msg, "internal/bar") {
			t.Errorf("panic message should mention both paths: %q", msg)
		}
	}()
	registerSchema("internal/bar", "test_conflict")
}

func TestSlugify_TruncationCollision(t *testing.T) {
	resetRegistry(t)
	// Two pkgPaths that diverge only after char 50 of the slug.
	// slugify prefixes with "test_" (5 chars), so the divergent chars
	// must sit past position 45 of the raw pkgPath.
	a := "internal/very/deeply/nested/package/path/aaaaaa/alpha"
	b := "internal/very/deeply/nested/package/path/aaaaaa/beta"
	slugA := slugify(a)
	slugB := slugify(b)
	if slugA != slugB {
		t.Fatalf("test precondition failed: expected truncation collision, got %q vs %q", slugA, slugB)
	}
	registerSchema(a, slugA)
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic from truncation collision, got none")
		}
	}()
	registerSchema(b, slugB)
}

// resetRegistry is a test-only helper that clears the collision-guard
// registry between tests. Same-package access to unexported
// registry / registryMu keeps the production surface clean.
func resetRegistry(t testing.TB) {
	t.Helper()
	registryMu.Lock()
	defer registryMu.Unlock()
	registry = map[string]string{}
}
