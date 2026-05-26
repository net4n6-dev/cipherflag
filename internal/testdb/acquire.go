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

// Package testdb provides per-package test-DB isolation. See the
// design doc at
// docs/superpowers/specs/2026-04-22-per-package-test-schema-isolation-design.md
// for the full rationale.
package testdb

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
)

// slugify converts a Go import path like "internal/store" to a
// Postgres-safe schema name like "test_internal_store". Non-alphanumeric
// characters (other than underscore) become underscore. Length is capped
// at 50 chars to stay well under Postgres' NAMEDATALEN=64 with headroom
// for future suffixes.
func slugify(pkgPath string) string {
	const prefix = "test_"
	const maxLen = 50

	var b strings.Builder
	b.WriteString(prefix)
	for _, r := range pkgPath {
		switch {
		case r == '_' || unicode.IsDigit(r):
			b.WriteRune(r)
		case unicode.IsLetter(r):
			b.WriteRune(unicode.ToLower(r))
		default:
			b.WriteRune('_')
		}
	}
	s := b.String()
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	return s
}

// appendSearchPath returns a new DSN string with `options=-c search_path=<schema>`
// merged into the query string. Postgres receives this as a startup
// packet runtime parameter; pgx honours it for every connection in the
// pool. Preserves any existing query parameters.
func appendSearchPath(dsn, schema string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		// URL parse failures should be impossible for a DSN we've already
		// used to connect. Return the input unchanged; pgx will error at
		// connection time with a clearer message.
		return dsn
	}
	q := u.Query()
	q.Set("options", "-c search_path="+schema)
	u.RawQuery = q.Encode()
	return u.String()
}

// appendPoolMaxConns sets the pgxpool MaxConns ceiling via the
// pool_max_conns query parameter. pgxpool.ParseConfig reads this during
// pool construction. Caps the per-package pool so 18 concurrent packages
// don't exhaust Postgres' default max_connections=100.
func appendPoolMaxConns(dsn string, n int) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return dsn
	}
	q := u.Query()
	q.Set("pool_max_conns", strconv.Itoa(n))
	u.RawQuery = q.Encode()
	return u.String()
}

var (
	registryMu sync.Mutex
	registry   = map[string]string{} // schema name → pkg path
)

// registerSchema asserts that `schemaName` maps to exactly one `pkgPath`.
// Idempotent when called with the same pair. Panics with both paths in
// the message when a different pkgPath is already registered against
// the same schemaName — catches slug-truncation collisions at
// TestMain-time rather than as mysterious cross-package test bleed.
func registerSchema(pkgPath, schemaName string) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if existing, ok := registry[schemaName]; ok {
		if existing == pkgPath {
			return // idempotent
		}
		panic(fmt.Sprintf(
			"testdb: schema name collision — both %q and %q slug to %q",
			existing, pkgPath, schemaName,
		))
	}
	registry[schemaName] = pkgPath
}

var scopedDSN atomic.Value // string

// Acquire creates a Postgres schema scoped to pkgPath, sets it as the
// active search_path on the scoped DSN that Require will hand back to
// tests, and returns a no-op cleanup. The schema is NOT dropped on
// teardown — next invocation's DROP SCHEMA IF EXISTS + CREATE SCHEMA
// pair gives each run a fresh start while preserving post-crash
// state for inspection.
//
// Expected shape at the call site (unchanged from the pre-schema
// model):
//
//	func TestMain(m *testing.M) {
//	    cleanup := testdb.Acquire(context.Background(), "internal/store")
//	    code := m.Run()
//	    cleanup()
//	    os.Exit(code)
//	}
//
// Behaviour:
//   - No DSN env var set → no-op cleanup; tests proceed (and skip if
//     they call Require, matching today).
//   - DSN set but admin connect / DDL fails → log.Fatalf. A misconfigured
//     schema would have tests silently race or run against the wrong
//     schema; fail fast is better.
func Acquire(ctx context.Context, pkgPath string) func() {
	base := DSN()
	if base == "" {
		return func() {}
	}

	schema := slugify(pkgPath)
	registerSchema(pkgPath, schema)

	connCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(connCtx, base)
	if err != nil {
		log.Fatalf("testdb.Acquire(%s): connect failed: %v", pkgPath, err)
	}
	defer conn.Close(context.Background())

	// Idempotent schema reset. CASCADE drops any objects left from a
	// prior run; CREATE makes the fresh schema. Use QuoteIdentifier to
	// defend against pkgPath-derived schema names that contain
	// Postgres-reserved words (unlikely, but cheap).
	stmts := []string{
		"DROP SCHEMA IF EXISTS " + pgQuoteIdent(schema) + " CASCADE",
		"CREATE SCHEMA " + pgQuoteIdent(schema),
	}
	for _, stmt := range stmts {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			log.Fatalf("testdb.Acquire(%s): %q: %v", pkgPath, stmt, err)
		}
	}

	dsn := appendSearchPath(base, schema)
	dsn = appendPoolMaxConns(dsn, 4)
	scopedDSN.Store(dsn)

	return func() {}
}

// pgQuoteIdent quotes a Postgres identifier with double quotes and
// doubles any embedded double quotes. Matches pg's quote_ident()
// semantics for the subset of characters slugify can produce (all
// ASCII; no embedded quotes expected).
func pgQuoteIdent(s string) string {
	return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
}
