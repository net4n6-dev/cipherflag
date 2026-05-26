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
	"os"
	"testing"
)

// DSN returns the Postgres test-database connection string from the
// canonical environment variable, or from a deprecated fallback.
//
// Resolution order:
//  1. CIPHERFLAG_TEST_DB (canonical — matches README, developer-workflow.md,
//     and the documented integration-test invocation).
//  2. CIPHERFLAG_TEST_DB_DSN (legacy, retained one release for
//     backwards compatibility with older per-layer plan docs).
//  3. CIPHERFLAG_TEST_DSN (legacy, same rationale).
//
// Returns "" when none are set. Use Require to skip the test in that case.
//
// The two legacy names are deprecated; prefer CIPHERFLAG_TEST_DB in all
// new code and in any invocation you document. The fallbacks are scheduled
// for removal one release after callers have been migrated.
func DSN() string {
	if v := os.Getenv("CIPHERFLAG_TEST_DB"); v != "" {
		return v
	}
	if v := os.Getenv("CIPHERFLAG_TEST_DB_DSN"); v != "" {
		return v
	}
	return os.Getenv("CIPHERFLAG_TEST_DSN")
}

// Require returns the DSN tests should connect with.
//
// Resolution order:
//  1. Package-level scoped DSN set by Acquire (search_path pinned to
//     the package's schema).
//  2. Raw env var via DSN().
//  3. tb.Skip when neither is set.
//
// testing.TB accepts *testing.T and *testing.B alike.
func Require(tb testing.TB) string {
	tb.Helper()
	// Acquire (via TestMain) stashes a schema-qualified DSN here. Tests
	// always land on the package's isolated schema when that's present.
	if v, ok := scopedDSN.Load().(string); ok && v != "" {
		return v
	}
	if dsn := DSN(); dsn != "" {
		return dsn
	}
	tb.Skip("CIPHERFLAG_TEST_DB not set, skipping integration test")
	return ""
}
