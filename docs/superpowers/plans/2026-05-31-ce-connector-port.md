# CipherFlag CE Connector Port Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring 5 pure-REST endpoint ingest connectors (Defender, SentinelOne, Tanium, Absolute, Netwrix) into CipherFlag CE and re-add the Venafi TPP+Cloud export client, all under Apache-2.0.

**Architecture:** Each ingest connector is an isolated Go package under `internal/ingest/<name>/` following the EE `client → mapper → poller` pattern, wired into `cmd/cipherflag/main.go` behind an `Enabled`-gated poller goroutine. All required CE contracts already exist (ingester, dedup, scriptparse, normalize, `ingestion_state` cursor table, `*SourceConfig` structs), so there are no schema or contract changes. Venafi is restored from CE's own git history (`origin/main` @ `7b6010e`), not copied from EE.

**Tech Stack:** Go 1.25 (toolchain 1.26), `net/http`, chi, pgx, zerolog; new dep `github.com/Azure/go-ntlmssp` (Netwrix NTLM). EE source-of-truth on disk: `/Users/Erik/projects/cipherflag-EE` (v1.27.0).

**Spec:** `docs/superpowers/specs/2026-05-31-ce-connector-port-design.md`

---

## Pre-flight (read once before any task)

- **Two repos on disk:** CE (this repo) `/Users/Erik/projects/cipherflag`; EE source
  `/Users/Erik/projects/cipherflag-EE`. You COPY connector source from EE into CE and add the
  Apache-2.0 header. EE files have NO license header; every CE Go file does (100% convention).
- **The Apache-2.0 header to prepend to every ported `.go` file** (copy from any existing CE Go
  file, e.g. `internal/ingest/ingester.go` lines 1–13):
  ```
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
- **Do NOT port** `velociraptor` (gRPC vendor SDK), `internal/ai`, `internal/scanner/image`,
  `internal/ingest/aws`. These stay EE-only.
- **Module path is identical** in both repos (`github.com/net4n6-dev/cipherflag`), so the EE
  connector files' internal imports (`internal/ingest`, `internal/model`, etc.) resolve
  unchanged in CE — no import rewriting needed.
- **The EE per-connector wiring template** (from `EE/cmd/cipherflag/main.go`, the Defender
  block) that you mirror in CE main.go:
  ```go
  if cfg.Sources.Defender.Enabled {
      dfCtx, dfCancel := context.WithCancel(ctx)
      defer dfCancel()
      dfClient, err := defender.NewClient(defender.Config{
          TenantID:     cfg.Sources.Defender.TenantID,
          ClientID:     cfg.Sources.Defender.ClientID,
          ClientSecret: cfg.Sources.Defender.ClientSecret,
          APIBaseURL:   cfg.Sources.Defender.APIBaseURL,
          HTTPTimeout:  time.Duration(cfg.Sources.Defender.HTTPTimeoutSeconds) * time.Second,
      })
      if err != nil {
          log.Fatal().Err(err).Msg("failed to init defender client")
      }
      defer dfClient.Close()
      dfIngester := ingest.NewUnifiedIngester(st, ingest.WithObservationCache(sharedCache), ingest.WithScorer(scorer), ingest.WithHostDepsExtractor(hostDepsExtractor))
      dfPoller := defender.NewPoller(dfClient, dfIngester, st, cfg.Sources.Defender)
      go dfPoller.Run(dfCtx)
      log.Info().Str("tenant_id", cfg.Sources.Defender.TenantID).Msg("defender poller started")
  }
  ```
  **VERIFY AT EXECUTION (do not assume):** CE's `cmd/cipherflag/main.go` ingester construction
  may differ from EE's. Before pasting any wiring block, read how CE already builds a
  `NewUnifiedIngester` (grep `NewUnifiedIngester` in CE main.go) and match its exact option set.
  CE's `internal/ingest/ingester.go` is confirmed to export `NewUnifiedIngester`,
  `WithObservationCache`, `WithScorer`, and `WithHostDepsExtractor` — but confirm whether CE
  main.go already has a `hostDepsExtractor`, `sharedCache`, and `scorer` in scope at the
  insertion point. If `hostDepsExtractor` is NOT defined in CE main.go, omit that option (the
  other connectors' ingesters in CE main.go are the source of truth for the correct option set).
- **Connectors are OFF by default** (`Enabled: false`), so wiring them changes nothing for
  existing deployments until configured.

---

## File Structure

| Path | Responsibility |
|---|---|
| `internal/ingest/defender/` | Microsoft Defender connector (OAuth client + KQL query + mapper + poller) |
| `internal/ingest/sentinelone/` | SentinelOne connector (dual mappers: app-inventory + RSO, RSO cursor) |
| `internal/ingest/tanium/` | Tanium connector (GraphQL client + mapper + poller) |
| `internal/ingest/absolute/` | Absolute connector (HMAC signer + dual mappers + reach cursor) |
| `internal/ingest/netwrix/` | Netwrix connector (NTLM client + AD CS event mapper + poller) |
| `internal/export/venafi/` | Venafi TPP+Cloud push client (restored from CE git history) |
| `internal/api/handler/venafi.go` | Venafi config/status HTTP handler (restored) |
| `internal/store/migrations/004_venafi_push.sql` | Venafi push state migration (restored) |
| `cmd/cipherflag/main.go` (modify) | `Enabled`-gated poller wiring per connector + Venafi scheduler |
| `go.mod` / `go.sum` (modify) | add `github.com/Azure/go-ntlmssp` |
| `NOTICE` (modify) | attribute `Azure/go-ntlmssp` |
| `README.md` (modify) | move ported connectors out of the EE-only moat list |

Each connector is an independent, separately-committable unit. Tasks 2–6 may be done in any
order; Task 1 (Venafi) is first because it is lowest-risk (restore from CE's own history).

---

## Task 1: Re-add the Venafi export connector (restore from CE git history)

**Files:**
- Restore from `origin/main` (`7b6010e`): `internal/export/venafi/{client,cloud,tpp_adapter,pusher,interface}.go` (+ `client_test.go`), `internal/api/handler/venafi.go`, `internal/store/migrations/004_venafi_push.sql`
- Modify: `cmd/cipherflag/main.go`

- [ ] **Step 1: List exactly what venafi files exist on origin/main**

Run: `git -C /Users/Erik/projects/cipherflag ls-tree -r --name-only origin/main | grep -iE 'venafi|004_venafi'`
Expected: the 6 `internal/export/venafi/*.go`, `internal/api/handler/venafi.go`, `internal/store/migrations/004_venafi_push.sql`, plus docs. (Capture any additional `*_test.go` and restore them too.)

- [ ] **Step 2: Restore the venafi code files from origin/main into the working tree**

Run:
```bash
cd /Users/Erik/projects/cipherflag
for f in $(git ls-tree -r --name-only origin/main | grep -E '^internal/(export/venafi|api/handler/venafi|store/migrations/004_venafi)'); do
  mkdir -p "$(dirname "$f")"
  git show "origin/main:$f" > "$f"
done
git status --short internal/export/venafi internal/api/handler/venafi.go internal/store/migrations/004_venafi_push.sql
```
Expected: the venafi files appear as untracked/new in the working tree. (They already carry the Apache-2.0 header — they were CE-licensed; verify with `head -1` on one.)

- [ ] **Step 3: Build to find what wiring is missing**

Run: `go build ./... 2>&1 | head -30`
Expected: build errors ONLY about the venafi handler not being referenced / unused, or an undefined route — NOT about the venafi package itself failing to compile. If the venafi package fails to compile, the restored set is incomplete — re-check Step 1 for a missed file (e.g. a shared types file). Record the errors.

- [ ] **Step 4: Wire the Venafi push scheduler into main.go**

Read the EE scheduler block for reference: `sed -n '593,640p' /Users/Erik/projects/cipherflag-EE/cmd/cipherflag/main.go`. Reproduce the `if cfg.Export.Venafi.Enabled { ... }` block in CE `cmd/cipherflag/main.go` (cloud vs tpp platform branch, push interval ticker), adding the `venafi` import. Match CE's existing config field names under `cfg.Export.Venafi` (read `internal/config/config.go` for the exact `VenafiConfig`/export struct). Wire the handler route if the restored `handler/venafi.go` expects registration in `internal/api/server.go` (grep `venafi` in EE `internal/api/server.go` for the route lines).

- [ ] **Step 5: Build + vet**

Run: `go build ./... && go vet ./internal/export/venafi/ ./internal/api/handler/`
Expected: exit 0, no output.

- [ ] **Step 6: Run venafi tests**

Run: `go test ./internal/export/venafi/ ./internal/api/handler/ 2>&1 | tail -20`
Expected: PASS. If a restored `*_test.go` references a helper that wasn't restored, restore it and re-run.

- [ ] **Step 7: gofmt + full build/test**

Run: `gofmt -l internal/export/venafi internal/api/handler/venafi.go && go build ./... && go test ./... 2>&1 | grep -vE '^ok|no test files' | head`
Expected: gofmt prints nothing; build clean; no FAIL lines.

- [ ] **Step 8: Commit**

```bash
git add internal/export/venafi internal/api/handler/venafi.go internal/store/migrations/004_venafi_push.sql cmd/cipherflag/main.go internal/api/server.go
git commit -m "feat(venafi): re-add Venafi TPP+Cloud export connector to CE

Restored from origin/main (7b6010e); dropped from CE v2 in 9a8348a.
Owner confirmed Venafi is an intended CE feature.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Port the Defender connector

**Files:**
- Create (copy from `EE/internal/ingest/defender/`, add Apache header): `client.go`, `oauth_client.go`, `mapper.go`, `poller.go`, `mock_client.go`, `client_test.go`, `oauth_client_test.go`, `mapper_test.go`, `poller_test.go`, `main_test.go`, `poller_integration_test.go`, `testdata/`
- Modify: `cmd/cipherflag/main.go`

- [ ] **Step 1: Copy the package from EE and add headers**

Run:
```bash
cd /Users/Erik/projects/cipherflag
mkdir -p internal/ingest/defender
cp -R /Users/Erik/projects/cipherflag-EE/internal/ingest/defender/. internal/ingest/defender/
ls internal/ingest/defender/
```
Expected: all 11 files + `testdata/` present.

- [ ] **Step 2: Prepend the Apache-2.0 header to every `.go` file lacking it**

For each `*.go` in `internal/ingest/defender/`, prepend the header block from Pre-flight if the
file does not already start with `// Copyright 2026 net4n6-dev`. Verify:
Run: `for f in internal/ingest/defender/*.go; do head -1 "$f" | grep -q 'Copyright 2026' || echo "MISSING HEADER: $f"; done`
Expected: no output (all headed).

- [ ] **Step 3: Build the package in isolation**

Run: `go build ./internal/ingest/defender/`
Expected: exit 0. If it fails on a missing CE symbol, STOP and report — it means a contract the
connector needs is absent from CE (unexpected; the spec verified they all exist).

- [ ] **Step 4: Run the connector's unit tests**

Run: `go test ./internal/ingest/defender/ 2>&1 | tail -20`
Expected: PASS (these are mock-HTTP unit tests, no live creds). The `poller_integration_test.go`
is tag-gated (`//go:build integration`) and is skipped by default.

- [ ] **Step 5: Wire the Enabled-gated poller into main.go**

In CE `cmd/cipherflag/main.go`: add `"github.com/net4n6-dev/cipherflag/internal/ingest/defender"`
to imports plus `"github.com/net4n6-dev/cipherflag/internal/ingest"`, and insert the Defender
wiring block (the CE-correct template in Pre-flight, verbatim) inside `runServe` AFTER the CBOM
runtime block (~line 199) and BEFORE `router := api.NewRouter(...)` (~line 210). Use the option
set `WithObservationCache(sharedCache)` + `WithScorer(scorer)` ONLY — CE has NO
`WithHostDepsExtractor`. Use the serve `ctx` directly. Do NOT touch `enabledSourceCount` — it
does not exist in CE (see Pre-flight).

- [ ] **Step 6: Build + vet + full test**

Run: `go build ./... && go vet ./internal/ingest/defender/ && go test ./internal/ingest/defender/`
Expected: exit 0; tests PASS.

- [ ] **Step 7: gofmt**

Run: `gofmt -l internal/ingest/defender cmd/cipherflag/main.go`
Expected: no output.

- [ ] **Step 8: Commit**

```bash
git add internal/ingest/defender cmd/cipherflag/main.go
git commit -m "feat(defender): port Microsoft Defender endpoint connector to CE

Pure net/http connector (Azure AD OAuth). Off by default. Ported from EE
under Apache-2.0.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Port the SentinelOne connector

**Files:**
- Create (copy from `EE/internal/ingest/sentinelone/`, add header): `client.go`, `http_client.go`, `mapper_appinventory.go`, `mapper_rso.go`, `rso_cursor.go`, `poller.go`, `mock_client.go`, `client_test.go`, `mapper_appinventory_test.go`, `mapper_rso_test.go`, `rso_cursor_test.go`, `poller_test.go`, `main_test.go`, `poller_integration_test.go`, `testdata/`
- Modify: `cmd/cipherflag/main.go`

- [ ] **Step 1: Copy + header**

Run:
```bash
cd /Users/Erik/projects/cipherflag
mkdir -p internal/ingest/sentinelone
cp -R /Users/Erik/projects/cipherflag-EE/internal/ingest/sentinelone/. internal/ingest/sentinelone/
for f in internal/ingest/sentinelone/*.go; do head -1 "$f" | grep -q 'Copyright 2026' || { printf '%s\n' "$(cat /tmp/apache_header.txt)" | cat - "$f" > "$f.tmp" && mv "$f.tmp" "$f"; }; done
for f in internal/ingest/sentinelone/*.go; do head -1 "$f" | grep -q 'Copyright 2026' || echo "MISSING: $f"; done
```
(First create `/tmp/apache_header.txt` once from the Pre-flight header block.)
Expected: no MISSING lines.

- [ ] **Step 2: Build the package**

Run: `go build ./internal/ingest/sentinelone/`
Expected: exit 0.

- [ ] **Step 3: Run unit tests**

Run: `go test ./internal/ingest/sentinelone/ 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 4: Wire into main.go**

Add the `sentinelone` import + `if cfg.Sources.SentinelOne.Enabled { ... }` block mirroring the
EE SentinelOne block (`grep -n 'SentinelOne' /Users/Erik/projects/cipherflag-EE/cmd/cipherflag/main.go`
for the exact `NewClient`/`NewPoller` signature — note S1's `NewPoller` returns `(poller, err)`).
Use the CE wiring template (no `WithHostDepsExtractor`, serve `ctx`); do NOT touch
`enabledSourceCount` (absent in CE).

- [ ] **Step 5: Build + vet + test + gofmt**

Run: `go build ./... && go vet ./internal/ingest/sentinelone/ && go test ./internal/ingest/sentinelone/ && gofmt -l internal/ingest/sentinelone cmd/cipherflag/main.go`
Expected: exit 0, tests PASS, gofmt silent.

- [ ] **Step 6: Commit**

```bash
git add internal/ingest/sentinelone cmd/cipherflag/main.go
git commit -m "feat(sentinelone): port SentinelOne endpoint connector to CE

Pure net/http; dual ingestion modes (app inventory + RSO). Off by default.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Port the Tanium connector

**Files:**
- Create (copy from `EE/internal/ingest/tanium/`, add header): `client.go`, `graphql_client.go`, `mapper.go`, `poller.go`, `mock_client.go`, `client_test.go`, `mapper_test.go`, `poller_test.go`, `main_test.go`, `poller_integration_test.go`, `testdata/`
- Modify: `cmd/cipherflag/main.go`

- [ ] **Step 1: Copy + header**

```bash
cd /Users/Erik/projects/cipherflag
mkdir -p internal/ingest/tanium
cp -R /Users/Erik/projects/cipherflag-EE/internal/ingest/tanium/. internal/ingest/tanium/
for f in internal/ingest/tanium/*.go; do head -1 "$f" | grep -q 'Copyright 2026' || { cat /tmp/apache_header.txt "$f" > "$f.tmp" && mv "$f.tmp" "$f"; }; done
for f in internal/ingest/tanium/*.go; do head -1 "$f" | grep -q 'Copyright 2026' || echo "MISSING: $f"; done
```
Expected: no MISSING lines.

- [ ] **Step 2: Build**

Run: `go build ./internal/ingest/tanium/`
Expected: exit 0.

- [ ] **Step 3: Unit tests**

Run: `go test ./internal/ingest/tanium/ 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 4: Wire into main.go**

Add `tanium` import + `if cfg.Sources.Tanium.Enabled { ... }` block mirroring EE
(`grep -n 'Tanium' /Users/Erik/projects/cipherflag-EE/cmd/cipherflag/main.go`), using the CE
wiring template (no `WithHostDepsExtractor`, serve `ctx`). Do NOT touch `enabledSourceCount`
(absent in CE).

- [ ] **Step 5: Build + vet + test + gofmt**

Run: `go build ./... && go vet ./internal/ingest/tanium/ && go test ./internal/ingest/tanium/ && gofmt -l internal/ingest/tanium cmd/cipherflag/main.go`
Expected: exit 0, tests PASS, gofmt silent.

- [ ] **Step 6: Commit**

```bash
git add internal/ingest/tanium cmd/cipherflag/main.go
git commit -m "feat(tanium): port Tanium endpoint connector to CE

Pure net/http GraphQL client. Off by default.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Port the Absolute connector

**Files:**
- Create (copy from `EE/internal/ingest/absolute/`, add header): `client.go`, `http_client.go`, `hmac_signer.go`, `mapper_inventory.go`, `mapper_reach.go`, `reach_cursor.go`, `poller.go`, `mock_client.go`, `client_test.go`, `hmac_signer_test.go`, `mapper_inventory_test.go`, `mapper_reach_test.go`, `reach_cursor_test.go`, `poller_test.go`, `main_test.go`, `poller_integration_test.go`, `testdata/`
- Modify: `cmd/cipherflag/main.go`

- [ ] **Step 1: Copy + header**

```bash
cd /Users/Erik/projects/cipherflag
mkdir -p internal/ingest/absolute
cp -R /Users/Erik/projects/cipherflag-EE/internal/ingest/absolute/. internal/ingest/absolute/
for f in internal/ingest/absolute/*.go; do head -1 "$f" | grep -q 'Copyright 2026' || { cat /tmp/apache_header.txt "$f" > "$f.tmp" && mv "$f.tmp" "$f"; }; done
for f in internal/ingest/absolute/*.go; do head -1 "$f" | grep -q 'Copyright 2026' || echo "MISSING: $f"; done
```
Expected: no MISSING lines.

- [ ] **Step 2: Build**

Run: `go build ./internal/ingest/absolute/`
Expected: exit 0.

- [ ] **Step 3: Unit tests**

Run: `go test ./internal/ingest/absolute/ 2>&1 | tail -20`
Expected: PASS (includes `hmac_signer_test.go` — HMAC request signing).

- [ ] **Step 4: Wire into main.go**

Add `absolute` import + `if cfg.Sources.Absolute.Enabled { ... }` block mirroring EE
(`grep -n 'Absolute' /Users/Erik/projects/cipherflag-EE/cmd/cipherflag/main.go` — note Absolute's
`NewPoller` returns `(poller, err)`). Use the CE wiring template (no `WithHostDepsExtractor`,
serve `ctx`); do NOT touch `enabledSourceCount` (absent in CE).

- [ ] **Step 5: Build + vet + test + gofmt**

Run: `go build ./... && go vet ./internal/ingest/absolute/ && go test ./internal/ingest/absolute/ && gofmt -l internal/ingest/absolute cmd/cipherflag/main.go`
Expected: exit 0, tests PASS, gofmt silent.

- [ ] **Step 6: Commit**

```bash
git add internal/ingest/absolute cmd/cipherflag/main.go
git commit -m "feat(absolute): port Absolute endpoint connector to CE

Pure net/http with HMAC request signing; dual modes (inventory + reach).
Off by default.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Port the Netwrix connector (+ new dependency)

**Files:**
- Create (copy from `EE/internal/ingest/netwrix/`, add header): `client.go`, `ntlm_client.go`, `mapper.go`, `poller.go`, `mock_client.go`, `client_test.go`, `ntlm_client_test.go`, `mapper_test.go`, `poller_test.go`, `main_test.go`, `poller_integration_test.go`, `testdata/`
- Modify: `cmd/cipherflag/main.go`, `go.mod`, `go.sum`, `NOTICE`

- [ ] **Step 1: Add the go-ntlmssp dependency**

Run: `cd /Users/Erik/projects/cipherflag && go get github.com/Azure/go-ntlmssp@v0.1.0`
Expected: `go.mod`/`go.sum` updated with `github.com/Azure/go-ntlmssp`.

- [ ] **Step 2: Copy + header**

```bash
mkdir -p internal/ingest/netwrix
cp -R /Users/Erik/projects/cipherflag-EE/internal/ingest/netwrix/. internal/ingest/netwrix/
for f in internal/ingest/netwrix/*.go; do head -1 "$f" | grep -q 'Copyright 2026' || { cat /tmp/apache_header.txt "$f" > "$f.tmp" && mv "$f.tmp" "$f"; }; done
for f in internal/ingest/netwrix/*.go; do head -1 "$f" | grep -q 'Copyright 2026' || echo "MISSING: $f"; done
```
Expected: no MISSING lines.

- [ ] **Step 3: Build**

Run: `go build ./internal/ingest/netwrix/`
Expected: exit 0 (resolves `Azure/go-ntlmssp` + `google/uuid`, both now in go.mod).

- [ ] **Step 4: Unit tests**

Run: `go test ./internal/ingest/netwrix/ 2>&1 | tail -20`
Expected: PASS (includes `ntlm_client_test.go`).

- [ ] **Step 5: Wire into main.go + attribute the dep in NOTICE**

Add `netwrix` import + `if cfg.Sources.Netwrix.Enabled { ... }` block mirroring EE
(`grep -n 'Netwrix' /Users/Erik/projects/cipherflag-EE/cmd/cipherflag/main.go` — note Netwrix's
`NewPoller(client, st, cfg)` takes the store directly, NOT an ingester, per the EE signature —
so Netwrix may not need a `NewUnifiedIngester` at all; follow the EE Netwrix block exactly).
Do NOT touch `enabledSourceCount` (absent in CE). Append a `github.com/Azure/go-ntlmssp`
(Apache-2.0) attribution line to `NOTICE` following the existing format.

- [ ] **Step 6: Build + vet + test + gofmt + tidy**

Run: `go mod tidy && go build ./... && go vet ./internal/ingest/netwrix/ && go test ./internal/ingest/netwrix/ && gofmt -l internal/ingest/netwrix cmd/cipherflag/main.go`
Expected: exit 0, tests PASS, gofmt silent.

- [ ] **Step 7: Commit**

```bash
git add internal/ingest/netwrix cmd/cipherflag/main.go go.mod go.sum NOTICE
git commit -m "feat(netwrix): port Netwrix AD CS connector to CE

Pure net/http with NTLM auth (adds Azure/go-ntlmssp, Apache-2.0). Off by
default.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Reframe README moat list + full-suite verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the EE-only "What's NOT included" list**

In `README.md`, in the "What's NOT included (CipherFlag EE)" / Layer-3 section: REMOVE
Defender, SentinelOne, Tanium, Absolute, Netwrix and the Venafi push client from the EE-only
list (they now ship in CE). KEEP as EE-only: Velociraptor, container image scanner (Layer 6.2),
active network scanner (Layer 6.3), AWS discovery, AI enrichment (Layer 6.1d), and the deeper
Thales CipherTrust / TPP policy-management Venafi tier. Move the now-CE connectors into the
"Core capabilities" list. Verify with: `grep -niE 'velociraptor|defender|sentinelone|tanium|netwrix|absolute|venafi' README.md`.

- [ ] **Step 2: Full build + vet + test + gofmt across the repo**

Run:
```bash
go build ./... && go vet ./... && gofmt -l . | grep -v '^$' || echo gofmt-clean
go test ./... 2>&1 | grep -vE '^ok|no test files'
```
Expected: build/vet clean; gofmt-clean; no FAIL lines (note any pre-existing, DB-dependent
failures and confirm they are not introduced by this work).

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: move ported connectors out of the EE-only moat list

Defender/SentinelOne/Tanium/Absolute/Netwrix + Venafi push now ship in CE.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 8 (optional, can defer): CI import guard

**Files:**
- Create: `.github/workflows/ce-moat-guard.yml` (or extend the existing CI workflow)

- [ ] **Step 1: Add a job that fails on forbidden imports**

Add a CI step that greps the CE tree and fails if any non-test Go file imports a forbidden
module/path:
```bash
! grep -rnE 'www\.velocidex\.com|anthropic-sdk-go|anchore/(syft|stereoscope)|google/go-containerregistry|"github\.com/net4n6-dev/cipherflag/internal/(ai|scanner/image|ingest/(velociraptor|aws))"' --include='*.go' .
```
(Does NOT block `aws-sdk-go-v2` — the S3 CBOM export sink legitimately uses it.)

- [ ] **Step 2: Verify the guard locally**

Run the grep above; expected: no matches (exit 1 from grep → `!` makes the step pass). Plant a
fake `import "www.velocidex.com/x"` in a scratch file, confirm the guard catches it, remove it.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/
git commit -m "ci: guard against EE-only moat imports in public CE

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Notes for the implementer

- **The `main.go` wiring is the one non-mechanical part.** Each EE connector block differs
  slightly (some `NewPoller` return `(poller, err)`, Netwrix takes the store not an ingester,
  Defender has OAuth + `Close()`). ALWAYS read the EE block for that specific connector and
  match CE's existing ingester-construction option set — do not blind-copy.
- **If a connector's unit test fails on a `testdata/` golden mismatch**, the EE testdata was
  copied verbatim; investigate whether a mapper depends on an EE-only field absent from CE's
  `DiscoveryResult`. The spec verified the contract exists, so this is unlikely — report if seen.
- **Do not enable any connector by default.** All stay `Enabled: false`.
- **Pre-existing repo state:** on branch `main`, ahead of `origin/main`. Do NOT push. The earlier
  IP-audit work (severed EE remote, committed strategy/connector specs) is already on `main`.
- **`/tmp/apache_header.txt`**: create once from the Pre-flight header block; Tasks 3–6 reuse it.
