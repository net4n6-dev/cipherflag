# CE L4 Catalog Hardening Port — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port EE v1.27.0's Layer 4 catalog hardening (reproducible EOL/FIPS/PQC catalog generators + per-entry `Source` + finding `Evidence` surface) into CE as `v2.1.0`.

**Architecture:** Guided surgical port. Clean pieces are vendored whole-file from EE (`scripts/catalogs/` generator module, generated catalog data, invariant tests) with Apache-2.0 headers applied; divergent pieces are hand-edited (`model.HealthFinding`, `pqc.Classification`, the two scorers, the rule-engine version, a CE-specific frontend). Lands as one squash commit on `main` pinning EE source `v1.27.0` (`aa991b1`).

**Tech Stack:** Go 1.25 (main module + a separate `scripts/catalogs` module depending only on `gopkg.in/yaml.v3`), SvelteKit 2 / Svelte 5 (runes) frontend, Vitest (new) for the frontend test.

**Source of truth:** EE repo at `/Users/Erik/projects/cipherflag-EE` (pinned `v1.27.0` / `aa991b1`). Every "vendor" step copies the exact EE file. **Apply the Apache-2.0 header (below) to every NEW file**; existing CE files already carry it.

**Apache-2.0 header (Go form — prepend to every new `.go`/`.svelte`-adjacent source file; year 2026):**
```go
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
```
For YAML/Makefile use `#`-prefixed lines; for `.svelte` use an HTML `<!-- -->` comment of the same text.

**Working location:** all paths are relative to the CE repo `/Users/Erik/projects/cipherflag`. Do the work on branch `ce-port-phase2-l4` (Task 0).

**Commit discipline:** the user has NOT authorized the final squash/tag/push. Make per-task WIP commits on the branch as the plan says; the squash-to-`main` and any tag/push happen only on explicit go-ahead (Phase 6 stops there).

---

## Phase 0 — Branch setup

### Task 0: Create the working branch

**Files:** none (git only)

- [ ] **Step 1: Confirm clean-ish tree + create branch**

Run:
```bash
cd /Users/Erik/projects/cipherflag
git status --short
git checkout -b ce-port-phase2-l4
```
Expected: branch `ce-port-phase2-l4` created off `main`. (Pre-existing untracked files — `.claude/`, `docs/…`, `research/` — are fine; leave them.)

- [ ] **Step 2: Record the EE source SHA for the eventual squash message**

Run:
```bash
git -C /Users/Erik/projects/cipherflag-EE rev-parse --short HEAD
git -C /Users/Erik/projects/cipherflag-EE describe --tags --exact-match HEAD 2>/dev/null || true
```
Expected: `aa991b1` and `v1.27.0`. Note these for Phase 6.

---

## Phase 1 — Backend wiring (model + scorers + version)

This phase adds the `Evidence` field, the `Source` field, the two finding-evidence wirings, the shared FIPS matcher, and the rule-engine bump. It is self-contained and compiles/tests on its own (the catalogs still have their old data; the new fields are additive).

### Task 1.1: Add `Evidence` to `HealthFinding` (TDD)

**Files:**
- Modify: `internal/model/health.go:56-72`
- Test: `internal/model/health_test.go` (create if absent)

- [ ] **Step 1: Write the failing test**

Append to `internal/model/health_test.go` (create the file with package `model` + Apache header if it doesn't exist):
```go
func TestHealthFinding_EvidenceOmitemptyAndRoundTrips(t *testing.T) {
	// Absent Evidence must not appear in JSON (backward compat).
	bare := HealthFinding{RuleID: "LIB-003", Title: "x", Severity: SeverityHigh}
	b, err := json.Marshal(bare)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "evidence") {
		t.Errorf("empty Evidence leaked into JSON: %s", b)
	}

	// Present Evidence round-trips under the "evidence" key.
	withEv := HealthFinding{RuleID: "LIB-003", Evidence: map[string]any{"source_url": "https://endoflife.date/openssl"}}
	b2, _ := json.Marshal(withEv)
	if !strings.Contains(string(b2), `"evidence"`) || !strings.Contains(string(b2), "endoflife.date/openssl") {
		t.Errorf("Evidence missing from JSON: %s", b2)
	}
	var back HealthFinding
	if err := json.Unmarshal(b2, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Evidence["source_url"] != "https://endoflife.date/openssl" {
		t.Errorf("round-trip lost source_url: %#v", back.Evidence)
	}
}
```
Ensure the test file imports `encoding/json`, `strings`, `testing`.

- [ ] **Step 2: Run it; verify compile failure**

Run: `go test ./internal/model/ -run TestHealthFinding_Evidence -v`
Expected: FAIL — `back.Evidence undefined (type HealthFinding has no field or method Evidence)`.

- [ ] **Step 3: Add the field**

In `internal/model/health.go`, inside `HealthFinding`, after the `ScopeDeadline` field (`:71`) and before the closing `}`, add:
```go

	// Evidence is a free-form map for finding-specific provenance data.
	// For catalog-derived findings (LIB-003, LIB-005), includes "source_url"
	// pointing at the upstream catalog record so operators can click through
	// to verify the deduction. Matches the pattern at internal/model/lineage.go.
	Evidence map[string]any `json:"evidence,omitempty"`
```

- [ ] **Step 4: Run test; verify pass**

Run: `go test ./internal/model/ -run TestHealthFinding_Evidence -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/model/health.go internal/model/health_test.go
git commit -m "feat(model): add HealthFinding.Evidence map for finding provenance"
```

### Task 1.2: Add `Source` to `pqc.Classification` (TDD)

**Files:**
- Modify: `internal/analysis/pqc/types.go:73-82`
- Test: `internal/analysis/pqc/classify_test.go` (existing — add a case)

- [ ] **Step 1: Write the failing test**

Append to `internal/analysis/pqc/classify_test.go`:
```go
func TestClassification_HasSourceField(t *testing.T) {
	// Compile-level guarantee that Source exists and Classify propagates it.
	c := Classify("rsa")
	_ = c.Source // field must exist
	// A recognised classical entry should carry a non-empty Source after regen;
	// at minimum the field is addressable and Classify returns the struct.
	if c.Status == QuantumUnknown {
		t.Fatalf("expected rsa to be classified, got unknown")
	}
}
```

- [ ] **Step 2: Run it; verify compile failure**

Run: `go test ./internal/analysis/pqc/ -run TestClassification_HasSourceField -v`
Expected: FAIL — `c.Source undefined`.

- [ ] **Step 3: Add the field**

In `internal/analysis/pqc/types.go`, inside `Classification`, after `SecurityLevel uint8` and before the closing `}`, add:
```go

	// Source is the upstream URL pointing at this entry's authoritative
	// record (NIST FIPS PDF, IETF draft) or the literal "manual" for
	// hand-curated entries. Populated by the catalog refresh generator
	// (scripts/catalogs/refresh-pqc.go); empty for QuantumUnknown.
	Source string
```
(No change to `classify.go` — `Classify` already returns the `canonical[key]` struct, so `Source` propagates automatically once the catalog data carries it. The catalog data is regenerated in Phase 4; until then `Source` is empty, which the test tolerates.)

- [ ] **Step 4: Run test; verify pass**

Run: `go test ./internal/analysis/pqc/ -run TestClassification_HasSourceField -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/analysis/pqc/types.go internal/analysis/pqc/classify_test.go
git commit -m "feat(pqc): add Classification.Source field (propagated by Classify)"
```

### Task 1.3: Wire `Evidence["source_url"]` on LIB-003 (EOL) (TDD)

**Files:**
- Modify: `internal/analysis/scoring/library.go:125-143` (`checkLibraryEOL`)
- Test: `internal/analysis/scoring/library_test.go` (existing)

> Note: CE's current `eolStarterMap` is a positional 3-tuple with **no `Source` field**. This task depends on the EOL data file gaining a `Source` field. To keep Phase 1 self-contained, FIRST add a `Source` field to the existing CE data struct with `Source: "manual"` on every current entry is NOT required — instead, this task is ordered AFTER the data files are regenerated. **Re-order:** do Task 1.3 and 1.4 only after Phase 2/3 regenerate the data files with `Source`. To avoid a cross-phase tangle, this plan instead has Phase 1 reference `entry.Source` and ships the data-struct `Source` field as part of Phase 2 (EOL) and Phase 3 (FIPS). If executing Phase 1 fully first, temporarily guard with the helper below.

- [ ] **Step 1: Write the failing test**

Append to `internal/analysis/scoring/library_test.go`:
```go
func TestCheckLibraryEOL_FindingIncludesSourceURL(t *testing.T) {
	// Pick any library/version that the EOL catalog flags. openssl 1.0.x is EOL.
	lib := &model.CryptoLibrary{LibraryName: "openssl", Version: "1.0.2k"}
	findings := checkLibraryEOL(lib)
	if len(findings) != 1 {
		t.Fatalf("expected 1 EOL finding, got %d", len(findings))
	}
	src, ok := findings[0].Evidence["source_url"]
	if !ok || src == "" {
		t.Errorf("LIB-003 finding missing Evidence[\"source_url\"]: %#v", findings[0].Evidence)
	}
}
```

- [ ] **Step 2: Run it; verify failure**

Run: `go test ./internal/analysis/scoring/ -run TestCheckLibraryEOL_FindingIncludesSourceURL -v`
Expected: FAIL — Evidence is nil (and/or `entry.Source` undefined until the data file carries it).

- [ ] **Step 3: Add the `Source` field to the EOL data struct + wire the finding**

In `internal/analysis/scoring/library_eol_data.go`, add a `Source string` field to the `eolStarterMap` struct definition and a `Source: "manual"` value to every existing positional entry. **(This interim change is replaced wholesale when Phase 2 regenerates the file; it exists so Phase 1 compiles and tests independently.)** Then in `internal/analysis/scoring/library.go`, in `checkLibraryEOL`'s returned finding (after `ScopeDeadline: &deadline,`), add:
```go
				Evidence:      map[string]any{"source_url": entry.Source},
```

- [ ] **Step 4: Run test; verify pass**

Run: `go test ./internal/analysis/scoring/ -run TestCheckLibraryEOL_FindingIncludesSourceURL -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/analysis/scoring/library.go internal/analysis/scoring/library_eol_data.go internal/analysis/scoring/library_test.go
git commit -m "feat(scoring): emit Evidence[source_url] on LIB-003 EOL findings"
```

### Task 1.4: Add `fipsVersionMatch` helper + wire LIB-005 (FIPS) (TDD)

**Files:**
- Modify: `internal/analysis/scoring/library.go:162-176` (`checkLibraryFIPS`)
- Modify: `internal/analysis/scoring/library_fips_data.go` (interim `Source` field, replaced in Phase 3)
- Create: `internal/analysis/scoring/library_fips_lookup.go` (the helper + relocated `LibraryFIPSLevel` arrive in Phase 3; the helper is introduced here)
- Test: `internal/analysis/scoring/library_test.go`

> The shared helper `fipsVersionMatch(prefix, version string) bool` folds in the approved hardening (EE duplicated the `"*"` check inline in two places). It is the load-bearing fix for the `"*"` sentinel the regenerated FIPS data uses (CE's current empty-prefix matcher is always-true; `strings.HasPrefix(v, "*")` is always-false — so the regenerated data WOULD break matching without this).

- [ ] **Step 1: Write the failing tests**

Append to `internal/analysis/scoring/library_test.go`:
```go
func TestFipsVersionMatch(t *testing.T) {
	cases := []struct {
		prefix, version string
		want            bool
	}{
		{"*", "anything", true},
		{"*", "", true},
		{"3.0.0", "3.0.0-fips", true},
		{"3.0.0", "1.1.1", false},
		{"", "x", true}, // empty prefix matches (legacy semantics preserved)
	}
	for _, c := range cases {
		if got := fipsVersionMatch(c.prefix, c.version); got != c.want {
			t.Errorf("fipsVersionMatch(%q,%q)=%v want %v", c.prefix, c.version, got, c.want)
		}
	}
}

func TestCheckLibraryFIPS_FindingIncludesSourceURL(t *testing.T) {
	// A "*" wildcard product entry must match any version and carry a source.
	lib := &model.CryptoLibrary{LibraryName: "boringcrypto", Version: "0.0.0"}
	findings := checkLibraryFIPS(lib)
	if len(findings) != 1 {
		t.Fatalf("expected 1 FIPS finding for boringcrypto, got %d", len(findings))
	}
	if _, ok := findings[0].Evidence["source_url"]; !ok {
		t.Errorf("LIB-005 finding missing Evidence[\"source_url\"]: %#v", findings[0].Evidence)
	}
}
```

- [ ] **Step 2: Run; verify failure**

Run: `go test ./internal/analysis/scoring/ -run 'TestFipsVersionMatch|TestCheckLibraryFIPS_FindingIncludesSourceURL' -v`
Expected: FAIL — `fipsVersionMatch` undefined; Evidence nil.

- [ ] **Step 3: Add the helper + interim Source field + wire the finding**

Create `internal/analysis/scoring/library_fips_lookup.go` (Apache header + package `scoring`):
```go
package scoring

import "strings"

// fipsVersionMatch reports whether a fipsStarterMap entry's version prefix
// matches the given version. "*" is the any-version sentinel used for
// product-level entries (HSMs, commercial closed-source) where no version
// prefix applies. Shared by checkLibraryFIPS and LibraryFIPSLevel.
func fipsVersionMatch(prefix, version string) bool {
	return prefix == "*" || strings.HasPrefix(version, prefix)
}
```
In `internal/analysis/scoring/library_fips_data.go`, add a `Source string` field to the `fipsStarterMap` struct and `Source: "manual"` to every current entry (interim; replaced in Phase 3). For any current empty-prefix product entries, leave them as-is for now (the empty prefix still matches via `fipsVersionMatch`). In `internal/analysis/scoring/library.go`'s `checkLibraryFIPS`, replace the match condition with the helper and add Evidence:
```go
func checkLibraryFIPS(lib *model.CryptoLibrary) []model.HealthFinding {
	name := strings.ToLower(lib.LibraryName)
	for _, entry := range fipsStarterMap {
		if entry.LibraryName == name && fipsVersionMatch(entry.VersionPrefix, lib.Version) {
			return []model.HealthFinding{{
				RuleID:   "LIB-005",
				Title:    "FIPS-validated library version",
				Severity: model.SeverityInfo,
				Category: model.CategoryGovernance,
				Detail:   entry.Note,
				Evidence: map[string]any{"source_url": entry.Source},
			}}
		}
	}
	return nil
}
```
> Verify CE's current LIB-005 field names before editing (CE may use `Note` or `Reason`, `Detail`); match the existing struct. The grep `RuleID:   "LIB-005"` at `library.go:167` anchors the block.

- [ ] **Step 4: Run tests; verify pass + full scoring package**

Run: `go test ./internal/analysis/scoring/ -run 'TestFipsVersionMatch|TestCheckLibraryFIPS' -v && go test ./internal/analysis/scoring/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/analysis/scoring/library.go internal/analysis/scoring/library_fips_data.go internal/analysis/scoring/library_fips_lookup.go internal/analysis/scoring/library_test.go
git commit -m "feat(scoring): fipsVersionMatch helper + Evidence[source_url] on LIB-005"
```

### Task 1.5: Move `LibraryFIPSLevel` into `library_fips_lookup.go` + use the helper (TDD)

**Files:**
- Modify: `internal/analysis/scoring/library_fips_data.go:150` (remove the function)
- Modify: `internal/analysis/scoring/library_fips_lookup.go` (add the function)

- [ ] **Step 1: Confirm existing coverage**

Run: `go test ./internal/export/cbom/ ./internal/analysis/scoring/ 2>&1 | tail`
Expected: PASS (LibraryFIPSLevel currently lives in `library_fips_data.go`; cbom consumes it).

- [ ] **Step 2: Move the function**

Cut `func LibraryFIPSLevel(...)` from `internal/analysis/scoring/library_fips_data.go` and paste it into `internal/analysis/scoring/library_fips_lookup.go`, rewriting its match to use the helper:
```go
// LibraryFIPSLevel returns the FIPS validation level string for the given
// library + version, or empty string if not found. Used by
// internal/export/cbom to emit cdx:fips_validation_level per CDX 1.6.
// The fipsStarterMap data is generated by scripts/catalogs/refresh-fips.go;
// this lookup is hand-maintained.
func LibraryFIPSLevel(libraryName, version string) string {
	name := strings.ToLower(libraryName)
	for _, entry := range fipsStarterMap {
		if entry.LibraryName != name {
			continue
		}
		if fipsVersionMatch(entry.VersionPrefix, version) {
			return entry.FIPSLevel
		}
	}
	return ""
}
```
> If CE's current `fipsStarterMap` struct has no `FIPSLevel` field name (CE used a positional 4-tuple — the 4th is the level), keep returning that 4th field; the field is named `FIPSLevel` after the Phase 3 regen. For Phase 1 interim, ensure the struct field is named `FIPSLevel`.

After the move, `library_fips_data.go` no longer references `strings`; either remove the import or it will be re-added by the Phase 3 generated file. For now, run `goimports`/`gofmt` and let `go build` guide you.

- [ ] **Step 3: Build + test**

Run: `go build ./... && go test ./internal/export/cbom/ ./internal/analysis/scoring/`
Expected: PASS (cbom's `scoring.LibraryFIPSLevel` call resolves; same package, same signature).

- [ ] **Step 4: Commit**

```bash
git add internal/analysis/scoring/library_fips_data.go internal/analysis/scoring/library_fips_lookup.go
git commit -m "refactor(scoring): relocate LibraryFIPSLevel to library_fips_lookup.go using fipsVersionMatch"
```

### Task 1.6: Bump `CurrentRuleEngineVersion` 4 → 5 (TDD)

**Files:**
- Modify: `internal/analysis/scoring/version.go:44`

- [ ] **Step 1: Write the failing test**

Append to `internal/analysis/scoring/version_test.go` (create if absent):
```go
func TestCurrentRuleEngineVersionIs5(t *testing.T) {
	if CurrentRuleEngineVersion != 5 {
		t.Errorf("CurrentRuleEngineVersion = %d, want 5 (L4 catalog hardening bump)", CurrentRuleEngineVersion)
	}
}
```

- [ ] **Step 2: Run; verify failure**

Run: `go test ./internal/analysis/scoring/ -run TestCurrentRuleEngineVersionIs5 -v`
Expected: FAIL — got 4.

- [ ] **Step 3: Bump + document**

In `internal/analysis/scoring/version.go`, change `const CurrentRuleEngineVersion = 4` to `= 5` and add to the version-history comment:
```go
//   - 5: Layer 4 Catalog Hardening — comprehensive EOL/FIPS/PQC catalogs
//        regenerated from upstream + per-finding evidence.source_url. Bumping
//        to 5 causes the cron sweeper to re-classify every stored row,
//        backfilling Evidence on existing findings.
```

- [ ] **Step 4: Run; verify pass + whole package builds**

Run: `go test ./internal/analysis/scoring/ -run TestCurrentRuleEngineVersionIs5 -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/analysis/scoring/version.go internal/analysis/scoring/version_test.go
git commit -m "feat(scoring): bump CurrentRuleEngineVersion 4->5 for catalog hardening rescore"
```

### Task 1.7: Phase-1 gate

- [ ] **Step 1: Build + vet + race-test the touched packages**

Run:
```bash
go build ./... && go vet ./internal/model/ ./internal/analysis/... ./internal/export/cbom/
go test -race -count=1 ./internal/model/ ./internal/analysis/... ./internal/export/cbom/ 2>&1 | grep -E '^(ok|FAIL|---)' | tail
```
Expected: builds clean; no FAIL lines.

---

## Phase 2 — `scripts/catalogs/` module + codegen Apache header + EOL catalog

### Task 2.1: Vendor the `scripts/catalogs` module skeleton (go.mod + codegen)

**Files:**
- Create: `scripts/catalogs/go.mod`, `scripts/catalogs/go.sum`
- Create: `scripts/catalogs/internal/codegen/codegen.go` (+ Apache adaptation), `scripts/catalogs/internal/codegen/codegen_test.go`
- Create: `scripts/catalogs/README.md`

- [ ] **Step 1: Vendor the files**

Copy from EE (then apply the Apache header to each new file):
```bash
mkdir -p scripts/catalogs/internal/codegen
cp /Users/Erik/projects/cipherflag-EE/scripts/catalogs/go.mod        scripts/catalogs/go.mod
cp /Users/Erik/projects/cipherflag-EE/scripts/catalogs/go.sum        scripts/catalogs/go.sum
cp /Users/Erik/projects/cipherflag-EE/scripts/catalogs/README.md     scripts/catalogs/README.md
cp /Users/Erik/projects/cipherflag-EE/scripts/catalogs/internal/codegen/codegen.go      scripts/catalogs/internal/codegen/codegen.go
cp /Users/Erik/projects/cipherflag-EE/scripts/catalogs/internal/codegen/codegen_test.go scripts/catalogs/internal/codegen/codegen_test.go
```
Apply the Apache header to `codegen.go`, `codegen_test.go` (Go form), and `README.md` (Markdown — add a short "Licensed under Apache-2.0" line; do not comment-wrap a README). The `go.mod`/`go.sum` need no header.

- [ ] **Step 2: Verify `go.mod` module path + go version match CE**

Confirm `scripts/catalogs/go.mod` reads `module github.com/net4n6-dev/cipherflag/scripts/catalogs`. Set its `go` directive to match CE's main `go.mod`:
```bash
grep '^go ' /Users/Erik/projects/cipherflag/go.mod
```
Edit `scripts/catalogs/go.mod` `go` line to that version if it differs from EE's `1.25.0`.

- [ ] **Step 3: Adapt `codegen.Emit` to emit the Apache header in generated files**

In `scripts/catalogs/internal/codegen/codegen.go`, in `Emit`, prepend the Apache header **before** the `// Code generated by …` line. Insert at the very top of the buffer build:
```go
	const apacheHeader = `// Copyright 2026 net4n6-dev
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
//
`
	buf.WriteString(apacheHeader)
	fmt.Fprintf(&buf, "// Code generated by scripts/catalogs/%s. DO NOT EDIT.\n", header.GeneratorName)
	// …rest unchanged…
```

- [ ] **Step 4: Update/extend the codegen test to assert the Apache header is emitted**

In `scripts/catalogs/internal/codegen/codegen_test.go`, add an assertion that `Emit` output contains `Licensed under the Apache License`. Run:
```bash
cd scripts/catalogs && go test ./internal/codegen/ -v && cd -
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/catalogs/go.mod scripts/catalogs/go.sum scripts/catalogs/README.md scripts/catalogs/internal/codegen/
git commit -m "feat(catalogs): vendor scripts/catalogs codegen module; emit Apache header in generated files"
```

### Task 2.2: Vendor the EOL generator + watchlist + testdata; preserve OpenSSL legacy entries

**Files:**
- Create: `scripts/catalogs/refresh-eol.go`, `scripts/catalogs/refresh-eol_test.go`
- Create: `scripts/catalogs/watchlists/eol.yaml`
- Create: `scripts/catalogs/testdata/endoflife_openssl.json`

- [ ] **Step 1: Vendor**

```bash
mkdir -p scripts/catalogs/watchlists scripts/catalogs/testdata
cp /Users/Erik/projects/cipherflag-EE/scripts/catalogs/refresh-eol.go        scripts/catalogs/refresh-eol.go
cp /Users/Erik/projects/cipherflag-EE/scripts/catalogs/refresh-eol_test.go   scripts/catalogs/refresh-eol_test.go
cp /Users/Erik/projects/cipherflag-EE/scripts/catalogs/watchlists/eol.yaml   scripts/catalogs/watchlists/eol.yaml
cp /Users/Erik/projects/cipherflag-EE/scripts/catalogs/testdata/endoflife_openssl.json scripts/catalogs/testdata/endoflife_openssl.json
```
Apply Apache header to `refresh-eol.go` and `refresh-eol_test.go` (Go form, AFTER any leading doc comment — keep it as a normal comment block at top; `refresh-eol.go` has no build tag). Apply `#`-form header to `eol.yaml`. JSON testdata gets no header.

- [ ] **Step 2: Preserve the two CE-unique OpenSSL EOL entries in the watchlist**

In `scripts/catalogs/watchlists/eol.yaml`, under the `manual:` section, add:
```yaml
  - library_name: openssl
    version_prefix: "0.9."
    reason: "OpenSSL 0.9.x EOL (pre-1.0 series; long unsupported)"
  - library_name: openssl
    version_prefix: "1.0."
    reason: "OpenSSL 1.0.x EOL 2019-12-31 (1.0.0/1.0.1/1.0.2 all end-of-life)"
```
(These cover the wide `0.9.`/`1.0.` prefixes that endoflife.date's narrower cycle prefixes miss — see spec §5.)

- [ ] **Step 3: Run the EOL generator unit test (network-free, fixture-based)**

Run:
```bash
cd scripts/catalogs && go test -run TestTransform -v ./... ; cd -
```
Expected: PASS — the transform test loads `testdata/endoflife_openssl.json` and asserts the `Source`/`VersionPrefix`/`Reason` shape.

- [ ] **Step 4: Produce the committed EOL data file**

The EOL generator fetches endoflife.date (network). Default (network-free, deterministic) path: vendor EE's generated snapshot, then apply the Apache header and insert the two preserved entries as keyed structs.
```bash
cp /Users/Erik/projects/cipherflag-EE/internal/analysis/scoring/library_eol_data.go internal/analysis/scoring/library_eol_data.go
```
This OVERWRITES the interim Phase-1 file. Prepend the Apache header block (must be byte-identical to what `codegen.Emit` now emits, so a future `make refresh-eol` yields a clean diff). Then add these two keyed entries to the `eolStarterMap` literal (alphabetical position among the `openssl` entries):
```go
	{LibraryName: "openssl", VersionPrefix: "0.9.", Reason: "OpenSSL 0.9.x EOL (pre-1.0 series; long unsupported)", Source: "manual"},
	{LibraryName: "openssl", VersionPrefix: "1.0.", Reason: "OpenSSL 1.0.x EOL 2019-12-31 (1.0.0/1.0.1/1.0.2 all end-of-life)", Source: "manual"},
```
> Refresh path for the future (documented in README, not run now): `make refresh-eol` fetches `https://endoflife.date/api/openssl.json` + `nodejs.json` and re-emits this file; the two `manual:` entries above are merged automatically.

- [ ] **Step 5: Build + test**

Run: `go build ./... && go test ./internal/analysis/scoring/ 2>&1 | tail`
Expected: PASS. (`library_eol_data.go` now has the keyed struct with `Source`; the interim Phase-1 struct is replaced.)

- [ ] **Step 6: Commit**

```bash
git add scripts/catalogs/refresh-eol.go scripts/catalogs/refresh-eol_test.go scripts/catalogs/watchlists/eol.yaml scripts/catalogs/testdata/endoflife_openssl.json internal/analysis/scoring/library_eol_data.go
git commit -m "feat(catalogs): vendor EOL generator + watchlist; regenerate EOL data preserving OpenSSL 0.9/1.0"
```

### Task 2.3: EOL invariant test

**Files:**
- Create: `internal/analysis/scoring/library_eol_data_test.go`

- [ ] **Step 1: Vendor the invariant test + header**

```bash
cp /Users/Erik/projects/cipherflag-EE/internal/analysis/scoring/library_eol_data_test.go internal/analysis/scoring/library_eol_data_test.go
```
Apply the Apache header. The test asserts: no duplicate (library,prefix) pairs; every `Source` is `https://…` or `"manual"`; allowed domains; version-prefix format.

- [ ] **Step 2: Run**

Run: `go test ./internal/analysis/scoring/ -run TestEOLData -v`
Expected: PASS (the two `manual` OpenSSL entries pass the `"manual"` Source branch).

- [ ] **Step 3: Commit**

```bash
git add internal/analysis/scoring/library_eol_data_test.go
git commit -m "test(scoring): EOL catalog invariant tests"
```

---

## Phase 3 — FIPS catalog (generated, network-free) + lookup finalization

### Task 3.1: Vendor the FIPS generator + watchlist + testdata; regenerate FIPS data

**Files:**
- Create: `scripts/catalogs/refresh-fips.go`, `scripts/catalogs/fips_gen.go`, `scripts/catalogs/refresh-fips_test.go`
- Create: `scripts/catalogs/watchlists/fips.yaml`, `scripts/catalogs/testdata/fips_sample.yaml`
- Modify (regenerate): `internal/analysis/scoring/library_fips_data.go`

- [ ] **Step 1: Vendor**

```bash
cp /Users/Erik/projects/cipherflag-EE/scripts/catalogs/refresh-fips.go      scripts/catalogs/refresh-fips.go
cp /Users/Erik/projects/cipherflag-EE/scripts/catalogs/fips_gen.go          scripts/catalogs/fips_gen.go
cp /Users/Erik/projects/cipherflag-EE/scripts/catalogs/refresh-fips_test.go scripts/catalogs/refresh-fips_test.go
cp /Users/Erik/projects/cipherflag-EE/scripts/catalogs/watchlists/fips.yaml scripts/catalogs/watchlists/fips.yaml
cp /Users/Erik/projects/cipherflag-EE/scripts/catalogs/testdata/fips_sample.yaml scripts/catalogs/testdata/fips_sample.yaml
```
Apply Apache headers: `refresh-fips.go` (Go — KEEP the `//go:build ignore` as the very first line, then a blank line, then the doc comment; the Apache block goes after the build tag + blank line per Go convention — build constraints must precede the package clause and be followed by a blank line, and a license comment is fine below them). `fips_gen.go` (Go, no build tag). YAML files get `#`-form header.

> Go build-tag rule: `//go:build ignore` MUST be near the top with a blank line separating it from the package doc. Place the Apache header AFTER the build tag's blank line. Verify with `go vet ./scripts/catalogs/...` is not applicable (ignored files); instead verify `go run` works in Step 3.

- [ ] **Step 2: Run the FIPS generator test**

```bash
cd scripts/catalogs && go test -run TestFIPS -v ./... ; cd -
```
Expected: PASS.

- [ ] **Step 3: Regenerate the FIPS data file (network-free) — ORDERING per spec §11/Phase-3**

The FIPS generator reads only the watchlist (no network). Regenerate FIRST (this overwrites the interim Phase-1 file with the keyed struct carrying `Note`/`FIPSLevel`/`Source` and `"*"` sentinels):
```bash
make refresh-fips    # = cd scripts/catalogs && go run ./refresh-fips.go ./fips_gen.go
```
Expected: `internal/analysis/scoring/library_fips_data.go` rewritten with the Apache header (from codegen) + 62 keyed entries.
> The generated file keeps a `var _ = strings.HasPrefix` guard so its `strings` import stays used. `LibraryFIPSLevel` already lives in `library_fips_lookup.go` (Phase 1.5), so no function clobber occurs.

- [ ] **Step 4: Build + test**

Run: `go build ./... && go test ./internal/analysis/scoring/ ./internal/export/cbom/ 2>&1 | tail`
Expected: PASS. If `library_fips_data.go` has an unused `strings` import, confirm the generated file includes the `var _ = strings.HasPrefix` guard (it should, vendored from EE's generator template).

- [ ] **Step 5: Commit**

```bash
git add scripts/catalogs/refresh-fips.go scripts/catalogs/fips_gen.go scripts/catalogs/refresh-fips_test.go scripts/catalogs/watchlists/fips.yaml scripts/catalogs/testdata/fips_sample.yaml internal/analysis/scoring/library_fips_data.go
git commit -m "feat(catalogs): vendor FIPS generator; regenerate FIPS data with Source + '*' sentinel"
```

### Task 3.2: FIPS invariant test

**Files:**
- Create: `internal/analysis/scoring/library_fips_data_test.go`

- [ ] **Step 1: Vendor + header**

```bash
cp /Users/Erik/projects/cipherflag-EE/internal/analysis/scoring/library_fips_data_test.go internal/analysis/scoring/library_fips_data_test.go
```
Apply Apache header.

- [ ] **Step 2: Run**

Run: `go test ./internal/analysis/scoring/ -run TestFIPSData -v`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/analysis/scoring/library_fips_data_test.go
git commit -m "test(scoring): FIPS catalog invariant tests"
```

---

## Phase 4 — PQC catalog (generated, network-free)

### Task 4.1: Vendor the PQC generator + watchlist; regenerate catalog.go + synonyms.go

**Files:**
- Create: `scripts/catalogs/refresh-pqc.go`, `scripts/catalogs/pqc_gen.go`, `scripts/catalogs/refresh-pqc_test.go`
- Create: `scripts/catalogs/watchlists/pqc.yaml`
- Modify (regenerate): `internal/analysis/pqc/catalog.go`, `internal/analysis/pqc/synonyms.go`

- [ ] **Step 1: Vendor**

```bash
cp /Users/Erik/projects/cipherflag-EE/scripts/catalogs/refresh-pqc.go      scripts/catalogs/refresh-pqc.go
cp /Users/Erik/projects/cipherflag-EE/scripts/catalogs/pqc_gen.go          scripts/catalogs/pqc_gen.go
cp /Users/Erik/projects/cipherflag-EE/scripts/catalogs/refresh-pqc_test.go scripts/catalogs/refresh-pqc_test.go
cp /Users/Erik/projects/cipherflag-EE/scripts/catalogs/watchlists/pqc.yaml scripts/catalogs/watchlists/pqc.yaml
```
Apply Apache headers (`refresh-pqc.go` keeps `//go:build ignore` first; `pqc_gen.go` no tag; `pqc.yaml` `#`-form).

- [ ] **Step 2: Run the PQC generator test**

```bash
cd scripts/catalogs && go test -run TestPQC -v ./... ; cd -
```
Expected: PASS.

- [ ] **Step 3: Regenerate (network-free — liboqs fetch is a documented TODO; NIST FIPS + IETF are hardcoded, classical from watchlist)**

```bash
make refresh-pqc    # = cd scripts/catalogs && go run ./refresh-pqc.go ./pqc_gen.go
```
Expected: `internal/analysis/pqc/catalog.go` (208 canonical, each with `Source`) + `synonyms.go` rewritten with Apache headers.

- [ ] **Step 4: Build + test the pqc package**

Run: `go build ./... && go test ./internal/analysis/pqc/ 2>&1 | tail`
Expected: PASS. `Classify("rsa").Source` is now non-empty for catalogued entries (Task 1.2's test still passes).

- [ ] **Step 5: Commit**

```bash
git add scripts/catalogs/refresh-pqc.go scripts/catalogs/pqc_gen.go scripts/catalogs/refresh-pqc_test.go scripts/catalogs/watchlists/pqc.yaml internal/analysis/pqc/catalog.go internal/analysis/pqc/synonyms.go
git commit -m "feat(catalogs): vendor PQC generator; regenerate catalog.go + synonyms.go with Source"
```

### Task 4.2: PQC invariant test

**Files:**
- Create: `internal/analysis/pqc/catalog_invariants_test.go`

- [ ] **Step 1: Vendor + header**

```bash
cp /Users/Erik/projects/cipherflag-EE/internal/analysis/pqc/catalog_invariants_test.go internal/analysis/pqc/catalog_invariants_test.go
```
Apply Apache header.

- [ ] **Step 2: Run**

Run: `go test ./internal/analysis/pqc/ -run 'TestCatalog|TestSynonyms' -v`
Expected: PASS (no-dup canonical keys; synonyms point to valid canonicals; Source URLs well-formed; Status/Category enumerated).

- [ ] **Step 3: Commit**

```bash
git add internal/analysis/pqc/catalog_invariants_test.go
git commit -m "test(pqc): catalog + synonyms invariant tests"
```

### Task 4.3: Catalog subset-safety verification gate

**Files:** none (verification)

- [ ] **Step 1: Prove no pre-port CE entry was dropped**

Compare the regenerated catalogs against the pre-port `main` versions. Run:
```bash
cd /Users/Erik/projects/cipherflag
# PQC canonical keys
git show main:internal/analysis/pqc/catalog.go | grep -oE '^[[:space:]]+"[^"]+":[[:space:]]*\{' | grep -oE '"[^"]+"' | sort -u > /tmp/pqc_before.txt
grep -oE '^[[:space:]]+"[^"]+":[[:space:]]*\{' internal/analysis/pqc/catalog.go | grep -oE '"[^"]+"' | sort -u > /tmp/pqc_after.txt
echo "PQC keys dropped (must be empty):"; comm -23 /tmp/pqc_before.txt /tmp/pqc_after.txt
# EOL pairs
git show main:internal/analysis/scoring/library_eol_data.go | awk -F'"' '/^[[:space:]]*\{/{print $2"|"$4}' | sort -u > /tmp/eol_before.txt
awk -F'"' '/^[[:space:]]*\{/{print $2"|"$4}' internal/analysis/scoring/library_eol_data.go | sort -u > /tmp/eol_after.txt
echo "EOL pairs dropped (must be empty):"; comm -23 /tmp/eol_before.txt /tmp/eol_after.txt
# FIPS pairs (account for ""→"*" sentinel: normalize "*" to "")
git show main:internal/analysis/scoring/library_fips_data.go | awk -F'"' '/^[[:space:]]*\{/{print $2"|"$4}' | sed 's/|\*$/|/' | sort -u > /tmp/fips_before.txt
awk -F'"' '/^[[:space:]]*\{/{print $2"|"$4}' internal/analysis/scoring/library_fips_data.go | sed 's/|\*$/|/' | sort -u > /tmp/fips_after.txt
echo "FIPS pairs dropped (must be empty):"; comm -23 /tmp/fips_before.txt /tmp/fips_after.txt
```
Expected: all three "dropped" lists EMPTY. If any non-empty, add the missing entries to the relevant watchlist `manual:`/`classical:` overlay and regenerate before proceeding.

- [ ] **Step 2: Phase 4 gate**

Run: `cd scripts/catalogs && go test ./... && cd - && go test ./internal/analysis/... ./internal/model/ ./internal/export/cbom/ 2>&1 | grep -E '^(ok|FAIL)' | tail`
Expected: generator module green; main packages green.

---

## Phase 5 — Frontend source-link + Vitest

> Design refinement (DRY, consistent with spec §4.3's "shared rendering rule"): extract a single `FindingSource.svelte` component and use it in BOTH renderers. Test that component in isolation.

### Task 5.1: Extend the `HealthFinding` TS type

**Files:**
- Modify: `frontend/src/lib/api.ts:82-91`

- [ ] **Step 1: Add the evidence field**

In the `HealthFinding` interface (after `immediate_fail?: boolean;`), add:
```ts
	evidence?: { source_url?: string };
```

- [ ] **Step 2: Type-check**

Run: `cd frontend && npm run check 2>&1 | tail; cd -`
Expected: no NEW errors (CE has pre-existing warnings; no new type errors).

- [ ] **Step 3: Commit**

```bash
git add frontend/src/lib/api.ts
git commit -m "feat(frontend): add evidence.source_url to HealthFinding type"
```

### Task 5.2: Stand up Vitest

**Files:**
- Modify: `frontend/package.json`
- Create: `frontend/vitest-setup.ts`
- Modify: `frontend/vite.config.ts` (add a `test` block)

- [ ] **Step 1: Add dev deps + test script**

In `frontend/package.json`, add to `devDependencies` (use versions compatible with Vite 7 / Svelte 5):
```json
    "vitest": "^3.0.0",
    "@testing-library/svelte": "^5.2.0",
    "@testing-library/jest-dom": "^6.4.0",
    "jsdom": "^25.0.0"
```
And add to `scripts`:
```json
    "test": "vitest run",
    "test:watch": "vitest"
```
Run: `cd frontend && npm install; cd -` (state the install: it pulls vitest + testing-library from the npm registry).

- [ ] **Step 2: Create the setup file**

`frontend/vitest-setup.ts`:
```ts
import '@testing-library/jest-dom/vitest';
```

- [ ] **Step 3: Add the test block to `vite.config.ts`**

Merge into the existing config's exported object:
```ts
	test: {
		environment: 'jsdom',
		globals: true,
		setupFiles: ['./vitest-setup.ts'],
		include: ['src/**/*.{test,spec}.{js,ts}']
	}
```
Ensure the Svelte plugin is already in `plugins` (it is, for SvelteKit). If `vite.config.ts` lacks a TS triple-slash for vitest types, add at top: `/// <reference types="vitest" />`.

- [ ] **Step 4: Smoke-test the runner**

Create `frontend/src/lib/sanity.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
describe('vitest', () => { it('runs', () => { expect(1 + 1).toBe(2); }); });
```
Run: `cd frontend && npm test 2>&1 | tail; cd -`
Expected: 1 passing test. Then delete `frontend/src/lib/sanity.test.ts`.

- [ ] **Step 5: Commit**

```bash
git add frontend/package.json frontend/package-lock.json frontend/vitest-setup.ts frontend/vite.config.ts
git commit -m "test(frontend): stand up Vitest (jsdom + testing-library/svelte)"
```

### Task 5.3: `FindingSource.svelte` component (TDD)

**Files:**
- Create: `frontend/src/lib/components/findings/FindingSource.svelte`
- Create: `frontend/src/lib/components/findings/FindingSource.test.ts`

- [ ] **Step 1: Write the failing test**

`frontend/src/lib/components/findings/FindingSource.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import FindingSource from './FindingSource.svelte';

describe('FindingSource', () => {
	it('renders a source link for an https url', () => {
		render(FindingSource, { sourceUrl: 'https://endoflife.date/openssl' });
		const link = screen.getByRole('link', { name: /source/i });
		expect(link).toHaveAttribute('href', 'https://endoflife.date/openssl');
		expect(link).toHaveAttribute('target', '_blank');
		expect(link).toHaveAttribute('rel', expect.stringContaining('noopener'));
	});

	it('renders a "manually curated" indicator for the literal "manual"', () => {
		render(FindingSource, { sourceUrl: 'manual' });
		expect(screen.getByText(/manually curated/i)).toBeInTheDocument();
		expect(screen.queryByRole('link')).toBeNull();
	});

	it('renders nothing when sourceUrl is absent', () => {
		const { container } = render(FindingSource, { sourceUrl: undefined });
		expect(container.textContent?.trim()).toBe('');
	});
});
```

- [ ] **Step 2: Run; verify failure**

Run: `cd frontend && npm test -- FindingSource 2>&1 | tail; cd -`
Expected: FAIL — component not found.

- [ ] **Step 3: Implement the component (Svelte 5 runes)**

`frontend/src/lib/components/findings/FindingSource.svelte`:
```svelte
<!-- Apache-2.0 header (HTML comment form) -->
<script lang="ts">
	let { sourceUrl }: { sourceUrl?: string } = $props();
</script>

{#if sourceUrl}
	{#if sourceUrl === 'manual'}
		<span class="finding-source-manual" title="Manually curated reference data">manually curated</span>
	{:else}
		<a class="finding-source-link" href={sourceUrl} target="_blank" rel="noopener noreferrer">source</a>
	{/if}
{/if}

<style>
	.finding-source-link,
	.finding-source-manual {
		font-size: 0.7rem;
		color: var(--cf-accent);
		opacity: 0.8;
		margin-top: 0.2rem;
		display: inline-block;
	}
	.finding-source-link { text-decoration: none; }
	.finding-source-link:hover { text-decoration: underline; opacity: 1; }
	.finding-source-manual { font-style: italic; cursor: default; }
</style>
```

- [ ] **Step 4: Run; verify pass**

Run: `cd frontend && npm test -- FindingSource 2>&1 | tail; cd -`
Expected: 3 passing.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/lib/components/findings/FindingSource.svelte frontend/src/lib/components/findings/FindingSource.test.ts
git commit -m "feat(frontend): FindingSource component (source link / manual indicator) + tests"
```

### Task 5.4: Use `FindingSource` in both renderers

**Files:**
- Modify: `frontend/src/lib/components/graph/GraphDetailPanel.svelte` (~:185, after `finding-rem`)
- Modify: `frontend/src/routes/certificates/[fingerprint]/+page.svelte` (~:257, after remediation)

- [ ] **Step 1: GraphDetailPanel**

Import at the top of the `<script>`: `import FindingSource from '$lib/components/findings/FindingSource.svelte';`
In the finding card, after the `{#if finding.remediation}…{/if}` block, add:
```svelte
				<FindingSource sourceUrl={finding.evidence?.source_url} />
```

- [ ] **Step 2: Cert detail page**

Same import. After the remediation paragraph in the finding card, add the same `<FindingSource sourceUrl={finding.evidence?.source_url} />` line.

- [ ] **Step 3: Type-check + build**

Run: `cd frontend && npm run check 2>&1 | tail && npm run build 2>&1 | tail; cd -`
Expected: no new errors; build succeeds.

- [ ] **Step 4: Commit**

```bash
git add frontend/src/lib/components/graph/GraphDetailPanel.svelte 'frontend/src/routes/certificates/[fingerprint]/+page.svelte'
git commit -m "feat(frontend): render FindingSource in graph panel + cert detail findings"
```

---

## Phase 6 — Makefile, gitignore, CHANGELOG, audit manifest, full gate

### Task 6.1: Makefile + .gitignore

**Files:**
- Create: `Makefile`
- Modify/create: `.gitignore`

- [ ] **Step 1: Create the Makefile**

`Makefile` (repo root):
```makefile
.PHONY: refresh-catalogs refresh-eol refresh-fips refresh-pqc

refresh-eol:
	cd scripts/catalogs && go run ./refresh-eol.go

refresh-fips:
	cd scripts/catalogs && go run ./refresh-fips.go ./fips_gen.go

refresh-pqc:
	cd scripts/catalogs && go run ./refresh-pqc.go ./pqc_gen.go

refresh-catalogs: refresh-eol refresh-fips refresh-pqc
	@echo "Catalogs refreshed. Review the diff and commit."
```

- [ ] **Step 2: gitignore the generator build artifact**

Append to `.gitignore`:
```
# scripts/catalogs build artifacts
scripts/catalogs/catalogs
```

- [ ] **Step 3: Verify network-free targets reproduce committed data (sanity)**

Run:
```bash
make refresh-fips refresh-pqc
git status --short internal/analysis/pqc/ internal/analysis/scoring/
```
Expected: only `Generated:` timestamp lines differ (if anything). Restore the committed files if only timestamps changed:
```bash
git checkout -- internal/analysis/pqc/catalog.go internal/analysis/pqc/synonyms.go internal/analysis/scoring/library_fips_data.go
```

- [ ] **Step 4: Commit**

```bash
git add Makefile .gitignore
git commit -m "build: add refresh-catalogs Make targets + gitignore generator artifact"
```

### Task 6.2: CHANGELOG

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Add the v2.1.0 section**

Prepend a `## [2.1.0]` section to `CHANGELOG.md` (match the existing CHANGELOG style) with:
```markdown
## [2.1.0] - 2026-05-29

### Added
- Reproducible Layer 4 catalog generators under `scripts/catalogs/` (`make refresh-catalogs`): EOL (endoflife.date), FIPS (manual NIST CMVP watchlist), PQC (NIST FIPS 203/204/205 + IETF hybrids + watchlist classical).
- Per-entry `Source` URL on the EOL, FIPS, and PQC catalogs.
- `HealthFinding.Evidence` map — `source_url` on EOL (LIB-003) and FIPS (LIB-005) findings; the frontend renders a "source" link / "manually curated" indicator. Vitest test infrastructure introduced.

### Changed
- `rule_engine_version` bumped 4 → 5: the cron sweeper re-classifies all stored assets on first deploy, backfilling `Evidence` and flagging libraries previously "unknown".

### Notes
- FIPS catalog is a manually-curated watchlist (NIST CMVP has no clean API). liboqs PQC fetch and CI auto-refresh are deferred.
```

- [ ] **Step 2: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs: CHANGELOG for v2.1.0 L4 catalog hardening port"
```

### Task 6.3: Port audit manifest

**Files:**
- Create: `docs/superpowers/ce-port/manifest-phase2-l4.yaml`

- [ ] **Step 1: Write the audit record**

`docs/superpowers/ce-port/manifest-phase2-l4.yaml`:
```yaml
# Audit record for CE Phase 2 (L4 catalog hardening) port.
# Documentation only — not executed by extract.sh (guided surgical port).
phase: "2-l4"
ee_source_repo: /Users/Erik/projects/cipherflag-EE
ee_source_tag: v1.27.0
ee_source_sha: aa991b1
ce_target_version: v2.1.0
vendored:
  - scripts/catalogs/go.mod
  - scripts/catalogs/go.sum
  - scripts/catalogs/README.md
  - scripts/catalogs/internal/codegen/codegen.go        # adapted: emits Apache header
  - scripts/catalogs/internal/codegen/codegen_test.go
  - scripts/catalogs/refresh-eol.go
  - scripts/catalogs/refresh-eol_test.go
  - scripts/catalogs/refresh-fips.go
  - scripts/catalogs/fips_gen.go
  - scripts/catalogs/refresh-fips_test.go
  - scripts/catalogs/refresh-pqc.go
  - scripts/catalogs/pqc_gen.go
  - scripts/catalogs/refresh-pqc_test.go
  - scripts/catalogs/watchlists/eol.yaml                # +2 OpenSSL manual entries (CE-preserve)
  - scripts/catalogs/watchlists/fips.yaml
  - scripts/catalogs/watchlists/pqc.yaml
  - scripts/catalogs/testdata/endoflife_openssl.json
  - scripts/catalogs/testdata/fips_sample.yaml
  - internal/analysis/pqc/catalog.go                    # regenerated
  - internal/analysis/pqc/synonyms.go                   # regenerated
  - internal/analysis/pqc/catalog_invariants_test.go
  - internal/analysis/scoring/library_eol_data.go       # snapshot + 2 preserves
  - internal/analysis/scoring/library_eol_data_test.go
  - internal/analysis/scoring/library_fips_data.go      # regenerated
  - internal/analysis/scoring/library_fips_data_test.go
  - internal/analysis/scoring/library_fips_lookup.go    # relocated LibraryFIPSLevel + fipsVersionMatch
surgical_edits:
  - internal/model/health.go                            # +Evidence field
  - internal/analysis/pqc/types.go                      # +Source field
  - internal/analysis/scoring/library.go                # LIB-003/005 Evidence + fipsVersionMatch
  - internal/analysis/scoring/version.go                # 4 -> 5
  - frontend/src/lib/api.ts                             # +evidence type
ce_specific:
  - frontend/src/lib/components/findings/FindingSource.svelte
  - frontend/src/lib/components/graph/GraphDetailPanel.svelte
  - frontend/src/routes/certificates/[fingerprint]/+page.svelte
  - frontend/vite.config.ts                             # Vitest block
  - Makefile
moat_excluded: "CT multi-provider arc; AI tier; scanners; non-osquery adapters; risk/blast-radius; PCI; Layer 8 UX; Thales"
```

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/ce-port/manifest-phase2-l4.yaml
git commit -m "docs: CE port phase-2-l4 audit manifest pinning EE v1.27.0"
```

### Task 6.4: Full verification gate sweep

**Files:** none

- [ ] **Step 1: Backend gates (G1/G2/G3 + generator module)**

Run:
```bash
cd /Users/Erik/projects/cipherflag
go build ./...
go vet ./...
go test -race -count=1 ./internal/... 2>&1 | grep -E '^(FAIL|--- FAIL)' | head      # expect empty
go test -count=1 ./... 2>&1 | grep -E '^FAIL' | head                                  # expect empty
cd scripts/catalogs && go test -count=1 ./... 2>&1 | tail -3 ; cd -                    # expect ok
```
Expected: clean build/vet; no FAIL lines; generator module green.

- [ ] **Step 2: Header sweep (G5)**

Run:
```bash
grep -rEl "All Rights Reserved|Proprietary|Confidential|EE-only|Enterprise Edition only" --include='*.go' --include='*.yaml' --include='*.svelte' scripts/catalogs internal frontend/src/lib/components/findings 2>/dev/null
```
Expected: NO output (no proprietary markers in new files).

- [ ] **Step 3: Apache-header presence on new Go files**

Run:
```bash
for f in scripts/catalogs/refresh-eol.go scripts/catalogs/refresh-fips.go scripts/catalogs/refresh-pqc.go scripts/catalogs/fips_gen.go scripts/catalogs/pqc_gen.go scripts/catalogs/internal/codegen/codegen.go internal/analysis/scoring/library_fips_lookup.go internal/analysis/pqc/catalog.go internal/analysis/scoring/library_eol_data.go internal/analysis/scoring/library_fips_data.go; do
  head -3 "$f" | grep -q "Licensed under the Apache License" || echo "MISSING HEADER: $f";
done
```
Expected: NO "MISSING HEADER" lines.

- [ ] **Step 4: Frontend gates**

Run:
```bash
cd frontend && npm run check 2>&1 | tail -3 && npm test 2>&1 | tail -5 && npm run build 2>&1 | tail -3 ; cd -
```
Expected: no new check errors; FindingSource tests pass; build succeeds.

- [ ] **Step 5: STOP — report to user**

Do NOT squash to `main`, tag, or push. Summarize: gates passed, files changed, the EE source SHA (`aa991b1`/`v1.27.0`) to pin in the squash message. Await explicit go-ahead for the squash-merge to `main` and (after the 2026-06-01 freeze lift) the push.

---

## Self-review notes (author)

- **Spec coverage:** every spec §4 file maps to a task; §5 reconciliation → Tasks 2.2-step2 (EOL preserve), 3.1 (FIPS sentinel via 1.4 helper), 4.3 (subset-diff gate); §6 testing → invariant tests (2.3/3.2/4.2), generator tests (vendored with each generator), frontend test (5.3); §7 rule-engine bump → Task 1.6; §8 gates → Task 6.4.
- **Phase-1 self-containment caveat:** Tasks 1.3/1.4 add an *interim* `Source` field to the existing CE data structs so Phase 1 compiles and tests independently; Phases 2-4 replace those data files wholesale via vendor/regenerate. This is called out in each task. The alternative (defer all scorer wiring to post-regen) would make Phase 1 non-self-contained; the interim approach keeps each phase green.
- **Network:** only `make refresh-eol` touches the network; the plan produces `library_eol_data.go` by vendoring EE's snapshot (network-free) and documents the refresh path. FIPS/PQC regenerate offline. No test hits the network.
- **`"*"` sentinel:** load-bearing; introduced in Task 1.4 (helper) BEFORE the FIPS data carrying `"*"` is regenerated (Task 3.1). Ordering correct.
- **Type consistency:** `fipsVersionMatch(prefix, version string) bool`, `FindingSource` prop `sourceUrl?: string`, `evidence?: { source_url?: string }` used consistently across tasks.
</content>
