# CipherFlag CE — Connector Port Design

**Date:** 2026-05-31
**Status:** Approved (pending written-spec review)
**Author:** Erik + Claude (Opus 4.8)
**Related:** `docs/superpowers/specs/2026-05-31-ce-v2-strategy-and-ip-audit.md` (the A+C
strategy + the CE/EE dividing-line rule this port implements)

---

## Goal

Bring six commercial-product connectors into the public Apache-2.0 CipherFlag CE, per the
owner's rule: **connectors that use a documented API ship in free CE; only connectors that
require a vendor SDK or a license-limited agreement stay EE-only.**

- **5 endpoint ingest connectors** (verified pure `net/http`, no vendor SDK): Microsoft
  **Defender**, **SentinelOne**, **Tanium**, **Absolute**, **Netwrix** → `internal/ingest/<name>/`
- **1 export connector, re-added**: **Venafi** (TPP + Cloud push) → `internal/export/venafi/`.
  This shipped in CE v1, was dropped from CE v2 in commit `9a8348a`; the owner wants it back.

**Explicitly NOT ported (remain EE-only):** `velociraptor` (gRPC vendor SDK —
`www.velocidex.com/.../proto` + `google.golang.org/grpc`), container image scanner
(`internal/scanner/image`, go-containerregistry), AWS discovery (`internal/ingest/aws`,
`aws-sdk-go-v2`), AI enrichment (`internal/ai`, paid Anthropic API + Ed25519 license gate).

## Source-of-truth & licensing

- EE connector source lives on disk at `/Users/Erik/projects/cipherflag-EE` (tip v1.27.0).
  Owner authorized reading EE and reproducing the connectors in CE under Apache-2.0 (owner owns
  both repos). EE source files carry **no** license header — every ported file gets the standard
  CE Apache-2.0 header (matching CE's 100%-header convention).
- **Venafi is restored from CE's own `origin/main` git history** (commit `7b6010e`), where it
  already exists Apache-2.0-licensed — not copied from EE. This is the cleanest provenance.

## Why this port is low-risk (verified)

Every contract the connectors depend on already exists in CE `main` (confirmed by reading the
trees):
- `internal/ingest/ingest.go` -> `DiscoveryResult`; `internal/ingest/ingester.go` ->
  `UnifiedIngester` + `ingest.Ingester`
- `internal/ingest/dedup`, `internal/ingest/scriptparse`, `internal/normalize` — all present
- `model.IngestionState` + store `GetIngestionState`/`SetIngestionState` — present
- the cursor table `ingestion_state` is already in `internal/store/migrations/v2.0_baseline.sql`
  -> **NO new DB migration needed for the ingest connectors**
- the `*SourceConfig` structs (`DefenderSourceConfig`, `SentinelOneSourceConfig`,
  `TaniumSourceConfig`, `AbsoluteSourceConfig`, `NetwrixSourceConfig`) already exist with real
  fields in `internal/config/config.go`, wired into `SourcesConfig`.

So the port is: copy implementation files, add headers, wire pollers into `main.go`, restore
the Venafi migration, add one dependency. No schema/contract changes.

---

## Architecture

Each ingest connector is an isolated package. The shared shape is **client -> mapper -> poller**:

- **client** (`client.go`, plus a transport/auth helper where the vendor needs one) — implements
  an `APIClient` interface; auth + paginated fetch over `net/http`. A `mock_client.go` provides
  the test double.
- **mapper** (`mapper*.go`) — vendor payload -> `ingest.DiscoveryResult` (crypto libraries /
  certs). Some connectors have **two** mappers (dual ingestion modes).
- **poller** (`poller.go`) — `NewPoller(client, ingester, store, cfg)` + `Run(ctx)`; cursor-based
  incremental polling via the `ingestion_state` table; per-cycle error isolation.

Data flow (all): `poller.Run` -> client fetch (cursor since last `IngestionState`) -> mapper ->
`ingest.DiscoveryResult` -> `UnifiedIngester.Ingest` -> store; cursor advanced.

Venafi (export) keeps its CE-v1 shape: `client.go` (TPP), `cloud.go` (Cloud), `tpp_adapter.go`,
`pusher.go`, `interface.go`, plus `internal/api/handler/venafi.go` and migration
`004_venafi_push.sql`; driven by the export push scheduler.

### Files to create (exact, verified inventory from EE on disk)

Connectors are **not** uniform — each has its own auth/transport quirk, and several have
dual-mode mappers. Verified per-connector file lists (impl + tests + `testdata/`):

- **defender** (12 files): `client.go`, `oauth_client.go` (Azure AD OAuth), `mapper.go`,
  `poller.go`, `mock_client.go` + `client_test.go`, `oauth_client_test.go`, `mapper_test.go`,
  `poller_test.go`, `main_test.go`, `poller_integration_test.go`, `testdata/`.
- **sentinelone** (14 files): dual modes — `client.go`, `http_client.go`,
  `mapper_appinventory.go`, `mapper_rso.go`, `rso_cursor.go`, `poller.go`, `mock_client.go` +
  `client_test.go`, `mapper_appinventory_test.go`, `mapper_rso_test.go`, `rso_cursor_test.go`,
  `poller_test.go`, `main_test.go`, `poller_integration_test.go`, `testdata/`.
- **tanium** (11 files): GraphQL — `client.go`, `graphql_client.go`, `mapper.go`,
  `poller.go`, `mock_client.go` + `client_test.go`, `mapper_test.go`, `poller_test.go`,
  `main_test.go`, `poller_integration_test.go`, `testdata/`.
- **absolute** (16 files): HMAC-signed requests + dual mode — `client.go`, `http_client.go`,
  `hmac_signer.go`, `mapper_inventory.go`, `mapper_reach.go`, `reach_cursor.go`, `poller.go`,
  `mock_client.go` + `client_test.go`, `hmac_signer_test.go`, `mapper_inventory_test.go`,
  `mapper_reach_test.go`, `reach_cursor_test.go`, `poller_test.go`, `main_test.go`,
  `poller_integration_test.go`, `testdata/`.
- **netwrix** (12 files): NTLM auth — `client.go`, `ntlm_client.go`, `mapper.go`,
  `poller.go`, `mock_client.go` + `client_test.go`, `ntlm_client_test.go`, `mapper_test.go`,
  `poller_test.go`, `main_test.go`, `poller_integration_test.go`, `testdata/`.

Venafi — restore from CE's own `origin/main` (`7b6010e`), already Apache-2.0:
- `internal/export/venafi/{client,cloud,tpp_adapter,pusher,interface}.go` + `client_test.go`
- `internal/api/handler/venafi.go`
- `internal/store/migrations/004_venafi_push.sql`

(At restore time, re-check `origin/main` for any additional venafi test files — e.g. a handler
test — and restore whatever exists.)

### Files to modify
- `cmd/cipherflag/main.go` — add 5 ingest imports + per-connector `Enabled`-gated
  `NewClient`/`NewPoller`/`go Run(ctx)` blocks (mirroring EE main.go ~lines 421-520); wire the
  Venafi export push-scheduler block (EE main.go ~lines 593+); extend `enabledSourceCount()` to
  count the new sources.
- `go.mod` / `go.sum` — add `github.com/Azure/go-ntlmssp` (Netwrix NTLM auth). `google/uuid`
  already present.
- `NOTICE` — attribute `Azure/go-ntlmssp` (Apache-2.0).
- `README.md` — move Defender/SentinelOne/Tanium/Absolute/Netwrix + Venafi push OUT of the
  EE-only moat list; keep Velociraptor, container scan, AWS, AI as EE.

---

## Tests

Per owner decision, port **full unit tests + mocks AND integration tests**:
- Unit (`client_test.go`, `mapper*_test.go`, `poller_test.go`, `main_test.go`, the per-connector
  transport/signer/cursor tests, `mock_client.go`, `testdata/`) — all mock HTTP, no live
  credentials; run in default `go test ./...`.
- Integration (`poller_integration_test.go`) — behind `//go:build integration`, excluded from
  the default build (matches CE's existing `internal/ingest/ingester_*_integration_test.go` and
  the `testdb` harness). Zero cost to the normal test run.

Verification gate (every connector): `go build ./...`, `go vet ./...`, `go test ./...` green;
`gofmt -l` clean; Apache-2.0 header on every new file.

## Error handling

Pollers isolate per-cycle failures (a failed cycle logs and retries next tick; never crashes the
server) — the EE `runOneCycleSafely` pattern, preserved. Connectors are **off by default**
(`Enabled: false`); a missing/invalid config for a disabled source is a no-op. A misconfigured
*enabled* connector fails its client construction with a logged fatal at startup (matching EE),
surfacing the problem immediately rather than silently.

---

## Security / IP hygiene

- No vendor SDKs enter CE: each ingest connector imports only stdlib `net/http` + CE-internal
  packages (+ `Azure/go-ntlmssp` + `google/uuid` for Netwrix — both OSS).
- `velociraptor` is NOT ported (gRPC vendor SDK). `VelociraptorSourceConfig` remains as dormant
  config only; its implementation is excluded and CI-guarded.
- **CI import guard** (companion task, may land separately): fail the build if CE imports any of
  `www.velocidex.com/...velociraptor`, `anthropic-sdk-go`, `anchore/{syft,stereoscope}`,
  `go-containerregistry`, or packages `internal/ai` / `internal/scanner/image` /
  `internal/ingest/{velociraptor,aws}`. Does NOT block endpoint-connector names or
  `aws-sdk-go-v2` (the S3 CBOM export sink legitimately uses it).

---

## Build sequence (one self-contained, separately-committable unit per step)

1. **Venafi** (re-add from `origin/main`): restore the export files + handler + migration +
   tests; wire the push scheduler; `go build`/`go test`. Simplest + most-wanted; restores a v1
   feature from known-good CE-licensed source.
2. **Defender** (endpoint template): copy package + OAuth client + tests; add headers; wire
   `Enabled`-gated poller in main.go; `go build`/`go test`.
3. **SentinelOne** — same pattern (note dual mappers + RSO cursor).
4. **Tanium** — same pattern (note GraphQL client).
5. **Absolute** — same pattern (note HMAC signer + dual mappers + reach cursor).
6. **Netwrix** — same pattern (note NTLM client) + add `Azure/go-ntlmssp` to go.mod + NOTICE.
7. **README reframe** + (optionally) the **CI import guard**.

Connectors are mutually independent, so steps 2-6 can proceed in any order / be parallelized;
the sequence front-loads the highest-value, lowest-risk items. Each connector's per-vendor quirk
(OAuth / GraphQL / HMAC / NTLM / dual-mappers) is the main per-step effort — they are NOT
copy-paste clones of one template.

## Out of scope (explicit)

- The post-login dashboard hang (separate bug; deferred per "connectors first").
- The operator sidebar shell port (Strategy C; later).
- Porting EE-only connectors (velociraptor/container/AWS/AI).
- Frontend settings UI for the new connectors (config is TOML-only for now; a settings-page
  port can be a later batch).

## Open questions (non-blocking; owner can decide at implementation)

- Per-vendor **legal axis**: some endpoint vendor APIs (Defender, SentinelOne, Tanium, Absolute)
  may require a partner/API agreement to access in practice. Technically CE-eligible; whether to
  document a "bring your own vendor API access" note is the owner's call. Does not affect the
  code port.
