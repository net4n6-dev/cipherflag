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
	"testing"
)

func TestRequire_UsesScopedDSNWhenSet(t *testing.T) {
	t.Setenv("CIPHERFLAG_TEST_DB", "postgres://raw/base")
	t.Setenv("CIPHERFLAG_TEST_DB_DSN", "")
	t.Setenv("CIPHERFLAG_TEST_DSN", "")

	scopedDSN.Store("postgres://scoped/with-search-path")
	t.Cleanup(func() { scopedDSN.Store("") })

	got := Require(t)
	want := "postgres://scoped/with-search-path"
	if got != want {
		t.Errorf("Require() = %q, want %q (scoped should win)", got, want)
	}
}

func TestRequire_FallsBackToRawDSNWhenScopedUnset(t *testing.T) {
	t.Setenv("CIPHERFLAG_TEST_DB", "postgres://raw/base")
	t.Setenv("CIPHERFLAG_TEST_DB_DSN", "")
	t.Setenv("CIPHERFLAG_TEST_DSN", "")

	scopedDSN.Store("")

	got := Require(t)
	want := "postgres://raw/base"
	if got != want {
		t.Errorf("Require() = %q, want %q (raw should be the fallback)", got, want)
	}
}
