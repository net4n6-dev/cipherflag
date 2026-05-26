//go:build integration

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
	"flag"
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-cmp/cmp"
	"github.com/net4n6-dev/cipherflag/internal/store"
	"github.com/stretchr/testify/require"
)

// -update regenerates golden files instead of comparing against them.
// Use with caution: every regenerated file is a deliberate, reviewer-
// visible byte-level diff. Always inspect `git diff testdata/golden/`
// after regen to confirm only expected changes are present.
var updateGoldens = flag.Bool("update", false, "regenerate L4-E CBOM goldens")

const goldenDir = "testdata/golden"

// runGoldenAssert compares scrubbed against the golden file at
// goldenName. With -update, it overwrites the golden file and returns.
// Without -update, it fails the test with a cmp.Diff if bytes differ.
func runGoldenAssert(t *testing.T, scrubbed []byte, goldenName string) {
	t.Helper()
	path := filepath.Join(goldenDir, goldenName)

	if *updateGoldens {
		require.NoError(t, os.WriteFile(path, scrubbed, 0o644),
			"runGoldenAssert: write golden")
		t.Logf("regenerated %s (%d bytes)", path, len(scrubbed))
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("runGoldenAssert: read %s (missing? run with -update first): %v", path, err)
	}

	if diff := cmp.Diff(string(want), string(scrubbed)); diff != "" {
		t.Fatalf("runGoldenAssert: %s mismatch (-want +got):\n%s\n\nTo regenerate: go test -tags integration -run %s ./internal/export/cbom/... -update",
			path, diff, t.Name())
	}
}

// emitSignedScrubbed runs the full pipeline for a given *cdx.BOM and
// returns the bytes that get compared to a golden file.
//
//	bom → SignBOM → MarshalSignedBOM → Canonicalize → scrubVolatileFields
//
// Returns the scrubbed, canonicalised, signed JSON.
func emitSignedScrubbed(t *testing.T, bom *cdx.BOM) []byte {
	t.Helper()

	signer, err := NewFileSigner(filepath.Join(goldenDir, "fixture-signing.key"))
	require.NoError(t, err, "emitSignedScrubbed: NewFileSigner")
	require.NoError(t, SignBOM(bom, signer), "emitSignedScrubbed: SignBOM")

	raw, err := MarshalSignedBOM(bom)
	require.NoError(t, err, "emitSignedScrubbed: MarshalSignedBOM")

	canonical, err := Canonicalize(raw)
	require.NoError(t, err, "emitSignedScrubbed: Canonicalize")

	scrubbed, err := scrubVolatileFields(canonical)
	require.NoError(t, err, "emitSignedScrubbed: scrubVolatileFields")

	return scrubbed
}

// withGoldenDB opens the integration test store using the same harness
// the rest of internal/export/cbom/*_integration_test.go uses. Returns
// a context and the store. Thin wrapper over newIntegrationStore (the
// canonical helper in cbom_integration_test.go) so Tasks 5/6/7 can
// fetch both values in one call.
//
// Return type is *store.PostgresStore so the same value can be passed
// to seedPKIScenarioForCBOMRich (which wants *store.PostgresStore) and
// to Generator.Generate (which accepts the store.CryptoStore interface
// that *store.PostgresStore satisfies — see internal/store/postgres.go
// line 43: `var _ CryptoStore = (*PostgresStore)(nil)`).
func withGoldenDB(t *testing.T) (context.Context, *store.PostgresStore) {
	t.Helper()
	return context.Background(), newIntegrationStore(t)
}

// TestGolden_GenerateFullScope is the first end-to-end golden in the L4-E
// suite. It runs Generator.Generate against the rich PKI seed scoped to
// the three seeded hosts (the "full universe" the rich fixture knows
// about — see seedPKIScenarioForCBOMRich's HostA/HostB/HostC), runs the
// full sign→marshal→canonicalize→scrub pipeline via emitSignedScrubbed,
// and diffs the bytes against scope_rich.json.
//
// Note: PostgresStore.ListScopeAssets short-circuits to nil on an empty
// HostIDs slice (internal/store/cbom_store.go:84-86), so the rich-seed
// hosts must be enumerated explicitly to surface every cert observed on
// any of them. The seed return value is the canonical source for that
// list — every observation in the seed lands on one of these three.
//
// Regenerate the golden with:
//
//	go test -tags integration -run TestGolden_GenerateFullScope \
//	    -count=1 ./internal/export/cbom/... -update
func TestGolden_GenerateFullScope(t *testing.T) {
	ctx, st := withGoldenDB(t)
	seed := seedPKIScenarioForCBOMRich(t, ctx, st)

	gen := &Generator{}
	bom, err := gen.Generate(ctx, st, &Scope{
		HostIDs: []string{seed.HostA.String(), seed.HostB.String(), seed.HostC.String()},
	})
	require.NoError(t, err, "TestGolden_GenerateFullScope: Generate")

	scrubbed := emitSignedScrubbed(t, bom)
	runGoldenAssert(t, scrubbed, "scope_rich.json")
}

// TestGolden_GenerateForApplication locks the application-scope CBOM
// output for app-1. Per the rich seed, app-1 claims leaf-1 + leaf-2
// (seedPKIScenarioForCBOMRich line ~302-309); app-2 owns weak-leaf-1.
// The negative-space invariant — weak-leaf-1 must NOT appear in this
// golden — is enforced byte-for-byte: any drift in the app-scope
// filter that pulls weak-leaf-1 in would fail the diff.
//
// Regenerate the golden with:
//
//	go test -tags integration -run TestGolden_GenerateForApplication \
//	    -count=1 ./internal/export/cbom/... -update
func TestGolden_GenerateForApplication(t *testing.T) {
	ctx, st := withGoldenDB(t)
	seed := seedPKIScenarioForCBOMRich(t, ctx, st)

	gen := &Generator{}
	bom, err := gen.GenerateForApplication(ctx, st, seed.App1Tag)
	require.NoError(t, err, "TestGolden_GenerateForApplication: GenerateForApplication")

	scrubbed := emitSignedScrubbed(t, bom)
	runGoldenAssert(t, scrubbed, "application_rich.json")
}

// TestGolden_GenerateForRepo locks the repo-scope CBOM output for repo-1.
// Per the rich seed (seedPKIScenarioForCBOMRich line ~316-320), repo-1
// claims leaf-1 via a B3 finding whose cbom.algorithm is "sha256"; repo-2
// owns the leaf-2 (ed25519) finding. The negative-space invariant —
// "ed25519" must NOT appear in this golden, and "cbom-rich-leaf-2"
// likewise — is enforced byte-for-byte: any drift in
// ListRepositoryFindings's repo-keying that pulls repo-2's row in would
// fail the diff.
//
// Note: GenerateForRepo's second arg is the repoFindingsLister interface
// (repo_generator.go:16-18); *store.PostgresStore satisfies it via
// ListRepositoryFindings (internal/store/repo_findings.go:15).
//
// Regenerate the golden with:
//
//	go test -tags integration -run TestGolden_GenerateForRepo \
//	    -count=1 ./internal/export/cbom/... -update
func TestGolden_GenerateForRepo(t *testing.T) {
	ctx, st := withGoldenDB(t)
	seed := seedPKIScenarioForCBOMRich(t, ctx, st)

	gen := &Generator{}
	bom, err := gen.GenerateForRepo(ctx, st, seed.Repo1ID)
	require.NoError(t, err, "TestGolden_GenerateForRepo: GenerateForRepo")

	scrubbed := emitSignedScrubbed(t, bom)
	runGoldenAssert(t, scrubbed, "repo_rich.json")
}
