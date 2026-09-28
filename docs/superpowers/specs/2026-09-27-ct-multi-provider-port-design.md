# CipherFlag CE — CT Multi-Provider Port Design

**Date:** 2026-09-27
**Status:** Draft (pending written-spec review)
**Author:** Erik + Claude (Sonnet 5)
**Related:** `docs/handover-ee-features-ready-to-port.md` (the originating handover, 2026-05-28,
now stale in several particulars — corrected below); `docs/superpowers/specs/2026-05-31-ce-connector-port-design.md`
(the 5-endpoint-connector port this design's structure and conventions are modeled on);
`docs/superpowers/ce-port/manifest-phase2-l4.yaml` (predecessor port's audit record, which
already lists "CT multi-provider arc" as a deliberate later increment — this is that increment).

---

## Goal

Port EE's Certificate Transparency multi-provider ingest arc (`ct_crtsh`, `ct_static`,
`ct_certspotter`, `ct_multi`) into CE, backend + `config.toml` only. CE currently has **zero**
CT ingestion — no `internal/ingest/ct/` package exists, and the `CtCrtsh`/`CtStatic` fields
already declared in `internal/config/config.go:293-301` are dead scaffolding left over from the
Phase 1 squash (verified: zero non-test, non-config.go references anywhere in the tree).

## Corrections to the 2026-05-28 handover

The handover this port originates from is four months stale. Re-verified against EE (now
v4.10.8, history rewritten 2026-06-03) and CE (now v2.2.5, fully synced with `origin/main`) on
2026-09-27:

- **CE does not have "the legacy v1.x crtsh adapter"** the handover claimed. `grep -rli crtsh`
  across CE hits only the dead config stub. There is no rename migration needed — CE never had
  the `ct_domain` kind EE's migration 049 renames.
- **§2 of the handover (Layer 4 catalog hardening) already shipped** in CE v2.1.0
  (`c3df9b9`). Not part of this port.
- **CE has no frontend surface for any connector** — Defender, SentinelOne, Tanium, Absolute,
  Netwrix are all `config.toml`-only, zero dialogs or discovery routes anywhere in
  `frontend/src/`. This port follows that convention: **no frontend**, matching every existing
  connector rather than introducing UI where none of CE's other connectors have it.
- **EE's CT arc gained a "coverage envelope" / contribution-kind concept** after the handover
  (rm:0282, 2026-07-21) that touches `externalsource.KindSpec.ContributableTypes`/
  `ContributedTypes` across all four kinds. **Deferred** — CE has no `externalsource` package for
  it to attach to (see below), and folding it in now would pull in unrelated EE infrastructure.
- **The Provider interface, `CTEntry` shape, and the 4 kind set are otherwise unchanged** since
  the handover — confirmed via EE's post-2026-05-28 commit history on `internal/ingest/ct/`
  (hardening/gosec/test passes only, no interface changes).

## The core architectural mismatch, and how this port resolves it

EE's entire CT arc is built on `internal/externalsource` (EE-only): a generic plugin registry
(`KindSpec`, `Deps`, dynamic per-source rows in an `external_sources` table, UUID-keyed JSONB
config editable at runtime). **CE has no such package, and no other CE connector uses one.**
Verified: `internal/ingest/tanium/poller.go:35-58` and the equivalent Defender/SentinelOne/
Absolute/Netwrix pollers all follow one pattern instead — a concrete `Poller` struct built by
`NewPoller(client, ingester, store, cfg)`, wired by hand in `cmd/cipherflag/main.go` behind an
`Enabled` config flag (`cmd/cipherflag/main.go:231-274`, the Defender/SentinelOne blocks).

Digging into what EE's registry is actually used for per-provider (not just how it's wired)
shows the real dependency is small and substitutable:

| EE mechanism | Used for | CE substitute |
|---|---|---|
| `externalsource.KindSpec{Validate, NewPoller, ContributableTypes, ContributedTypes}` | Startup registration + config validation | Direct `NewPoller(...)` call in `main.go`, gated on `cfg.Sources.CtX.Enabled` — matches every existing CE connector |
| `store.ExternalSource` row + `GetExternalSource`/`UpdateExternalSource(Config)` (UUID-keyed) | Per-source checkpoint scratchpad: crtsh's seen-ID set (`crtsh/poller.go:39-42`), static's `LastSeenTreeSize` (`static/poller.go:22-28`, `static/config.go:33-38`), certspotter's cursor string (`certspotter/poller.go:32-47`) | `model.IngestionState.Cursor` (`internal/model/source.go:29-33`), `SourceName`-keyed, already used identically by every existing CE poller via `GetIngestionState`/`SetIngestionState` |
| `external_sources` + `external_source_scan_history` tables | Dynamic, UI-editable per-domain source registration | Not needed — CE's connectors are all statically configured via `config.toml`, restart to change (see "Multi-domain config" below for how N domains are still supported without a DB-backed registry) |
| `asset_provenance.external_source_id` (UUID FK to `external_sources`) | Links provenance rows to their registry row | Column already exists (`internal/store/migrations/v2.0_baseline.sql:395-398`, "CE-flavor... NULL when CE") and stays NULL for CT rows, exactly as it does for every other CE connector. Attribution instead flows through `DiscoveryResult.Source` (`internal/ingest/ingest.go:26`). |

**Consequence: this port requires zero new database migrations.** `ingestion_state` and
`asset_provenance` already carry everything needed; this mirrors the precedent set by the
5-connector port (`docs/superpowers/specs/2026-05-31-ce-connector-port-design.md:44-45`, "NO new
DB migration needed for the ingest connectors").

## Multi-domain config (a real design decision, not carried over verbatim)

EE's model lets an operator register an arbitrary number of independently-configured CT sources
at runtime (one `external_sources` row per monitored domain per kind). CE's `config.toml` model
is static-at-startup. A CT connector that could only watch a single domain per kind would be far
less useful than EE's — organizations typically want to monitor certificate issuance across
several of their own domains at once.

CE already has precedent for a statically-configured *list* of monitored targets via TOML
array-of-tables — `ScopeConfig` (`internal/config/config.go:388-395`), which `CBOMConfig.Scopes`
(`internal/config/config.go:376-385`) holds as `[]ScopeConfig`, giving `[[cbom.scopes]]` blocks
(`CBOM CBOMConfig` is `toml:"cbom"` at `internal/config/config.go:35`). This port follows that
precedent: each CT kind's `SourceConfig` carries `Domains []CtDomainConfig` (or, for
`ct_certspotter`, `[]CtCertspotterDomainConfig`; `ct_multi` groups analogously), one
`[[sources.ct_crtsh.domains]]` block per monitored domain, each with its own `Enabled`,
`IncludeSubdomains`, and other per-domain fields carried over from EE's `Config` structs
(`crtsh/config.go:29-34`, `static/config.go:21-33`, `certspotter/config.go:27-38`).

Per-domain checkpoints are keyed as `"<kind>:<domain>"` (e.g. `"ct_crtsh:example.com"`) when
calling `GetIngestionState`/`SetIngestionState` — `SourceName` is a plain string
(`internal/model/source.go:30`), so this needs no schema change, just a naming convention. The
poller loops over its configured `Domains` list each tick, isolating failures per-domain (one
domain's error doesn't block the others in the same cycle — mirrors the existing
per-cycle-isolation pattern the 5-connector port established,
`docs/superpowers/specs/2026-05-31-ce-connector-port-design.md:134-138`).

`ct_static`'s `LastSeenTreeSize` and `ct_crtsh`'s seen-ID set become the JSON-encoded `Cursor`
string for that domain's `IngestionState` row (not a bare int/string like certspotter's, since
they're structured); `ct_certspotter`'s cursor is already a bare string and needs no encoding.

`ct_multi`'s children (`multi/config.go:14-21`) are themselves `CtDomainConfig`-shaped entries
for crtsh/static/certspotter, sharing the parent domain — the tagged-union shape and the
"children must share the parent's domain" validation (`multi/config.go:99-120`, rm:0256) port
directly since they're pure validation logic with no registry dependency.

## Components

`internal/ingest/ct/` (new package):

- **`provider.go`** — `Provider` interface (`QueryDomain(ctx, domain) ([]CTEntry, error)`,
  `Name() string`) + `CTEntry` struct, ported near-verbatim from
  `cipherflag-EE/internal/ingest/ct/provider.go:25-71`. Pure data contract, no registry
  dependency — the one file with no rework needed beyond the license header.
- **`throttle.go`** — shared rate-limit helper (`cipherflag-EE/internal/ingest/ct/throttle.go`),
  portable as-is.
- **`crtsh/`** — `client.go` (crt.sh JSON API), `mapper.go`-equivalent conversion to `CTEntry`,
  `poller.go` rebuilt on `NewPoller(client, ingester, store, cfg)` + per-domain `Cursor`
  checkpoint instead of `storeUpdater`/`external_sources`.
- **`static/`** — `hashreader.go`, `merkle.go`, `sth.go`, `tile.go`, `tileleaf.go` (Plan A.6:
  RFC 6962 / c2sp.org §1.1.4 leaf-format correctness, the load-bearing piece for
  production-correct Sunlight log verification) — pure Go computation, no registry ties, ports
  unchanged. **`provider.go`** (`cipherflag-EE/internal/ingest/ct/static/provider.go:1-45+`) is
  the actual `ct.Provider` implementation (`QueryDomain`) that ties the Merkle/STH/tile
  primitives together and owns the runtime `LastSeenTreeSize` field — without it the other files
  don't assemble into a working provider; must be included in the port. `poller.go` rebuilt the
  same way as crtsh: persists `Provider.LastSeenTreeSize` into the domain's `Cursor` string after
  each successful tick (mirroring what EE calls `Cache.LastTreeSize`, `static/config.go:42` — a
  distinct, persisted-shape field name from the runtime `LastSeenTreeSize`; keep that naming
  distinction in mind at implementation time so the CE port doesn't conflate the two).
- **`certspotter/`** — `client.go` (SSLMate hosted API, optional API token), **`ratelimit.go`**
  (`cipherflag-EE/internal/ingest/ct/certspotter/ratelimit.go` — a separate rate limiter
  constructed via `NewRateLimiter(requestsPerHour)` and injected into the client; not folded
  into `client.go` in EE, must be ported as its own file), `poller.go` rebuilt the same way,
  checkpoint = cursor string directly.
- **`multi/`** — `children.go`, `composer.go`, and **`poller.go`**
  (`cipherflag-EE/internal/ingest/ct/multi/poller.go:34-38`, explicitly commented
  "LOAD-BEARING — spec §2.4" in EE) all three required. `composer.go` runs `Provider.QueryDomain`
  concurrently across configured children and returns the union of results — **cross-child
  fingerprint dedup is intentionally NOT done** in EE (`multi/composer.go:44-47`: "overlapping
  certs get one CTEntry per source"; only defensive within-child dedup happens, for
  well-behaved children that shouldn't emit duplicates anyway). It's `poller.go`, not
  `composer.go`, that groups the composer's output by each entry's `Source` field and calls
  `Ingester.Ingest` **once per distinct child source** (not once for the merged set) — this is
  the per-child grouping that makes `asset_provenance.source` correctly attribute each cert to
  its originating provider (`"ct_crtsh"`/`"ct_static"`/`"ct_certspotter"`) rather than a flat
  `"ct_multi"`.

Every ported file gets the standard CE Apache-2.0 header (`internal/ingest/defender/client.go:1-15`
is the template — EE source carries no header, consistent with how the 5-connector port handled
this, `docs/superpowers/specs/2026-05-31-ce-connector-port-design.md:30-32`). Every EE import of
`internal/externalsource`, `internal/externalsource/probe`, or `internal/store` (for
`storeUpdater`) gets rewritten to CE's `internal/ingest`, `internal/model`, and the narrow
`Store` interface pattern `tanium/poller.go:35-40` already establishes.

## Config

Replace, not extend, the dead stub (`internal/config/config.go:271-301`:
`ExternalSourcesCTKindConfig`, `ExternalSourcesSourceConfig.CtCrtsh`/`.CtStatic`, plus the
now-inaccurate comments claiming a "ct_crtsh in v1.11, renamed from ct_domain by migration 049"
history CE never had). New structs, following the `TaniumSourceConfig` template
(`internal/config/config.go:225-232`) and the `ScopeConfig` array-of-tables template
(`internal/config/config.go:388-395`):

```go
type CtCrtshSourceConfig struct {
    Domains []CtDomainConfig `toml:"domains"`
}

type CtDomainConfig struct {
    Enabled             bool   `toml:"enabled"`
    Domain              string `toml:"domain"`
    IncludeSubdomains   bool   `toml:"include_subdomains"`
    PollIntervalSeconds int    `toml:"poll_interval_seconds"`
}

// CtStaticSourceConfig, CtCertspotterSourceConfig follow the same
// Domains []...Config shape with their own per-kind fields (LogURL/
// PublicKeyPEM for static; APIToken/RequestsPerHour for certspotter).

type CtMultiSourceConfig struct {
    Groups []CtMultiGroupConfig `toml:"groups"`
}
```

wired into `SourcesConfig` (`internal/config/config.go:126-136`) as `CtCrtsh`, `CtStatic`,
`CtCertspotter`, `CtMulti`, replacing the removed `ExternalSourcesSourceConfig` fields. (The
`ExternalSourcesSourceConfig.Enabled`/`TickIntervalSeconds`/`ShutdownGraceSeconds` fields
described a scheduler that was never built in CE — removed along with the CT stub rather than
kept as further dead scaffolding.)

`main.go` gets 4 `Enabled`-gated blocks (one per kind, each iterating its `Domains`/`Groups`
list to construct one `Poller` instance per kind — not per domain, since a single poller can
loop its own domain list per tick), matching the Defender/SentinelOne pattern
(`cmd/cipherflag/main.go:231-274`).

## Tests

Full unit tests + mocks ported per provider, matching the 5-connector port's precedent
(`docs/superpowers/specs/2026-05-31-ce-connector-port-design.md:119-127`): mock HTTP, no live
credentials, default `go test ./...`. EE's `static/e2e_integration_test.go` and any
`poller_integration_test.go`-equivalents move behind `//go:build integration`, matching CE's
existing `internal/ingest/ingester_*_integration_test.go` convention.

Verification gate: `go build ./...`, `go vet ./...`, `go test ./...` green; `gofmt -l` clean;
Apache-2.0 header on every new file; and — per this repo's own spec rules
(`docs/CLAUDE.md`, "Schema reconciliation before commit") — grep confirmation that no new file
references a table/column this design didn't already verify exists.

## Error handling

Per-domain failure isolation within a kind's poller (one domain's error doesn't block others in
the same cycle, doesn't crash the process); the `runOneCycleSafely` pattern the 5-connector port
preserved (`docs/superpowers/specs/2026-05-31-ce-connector-port-design.md:134-138`) carries over
unchanged. Connectors are off by default (`Enabled: false`); a misconfigured *enabled* domain
entry fails validation at startup with a logged fatal, surfacing the problem immediately rather
than silently — same convention as every other CE connector.

## Security / IP hygiene

No vendor SDKs — `crtsh`/`static`/`certspotter` clients are stdlib `net/http` (EE's own
`docs/superpowers/specs/2026-05-25-ct-multi-provider-design.md` describes them as such; nothing
in the file lists (`ls` of each subpackage, 2026-09-27) shows a non-stdlib HTTP dependency).
`static`'s Merkle/STH verification uses stdlib `crypto/ed25519`/`crypto/x509` only. The Layer
4.4 risk-scoring entanglement the original handover warned about (§1, "EE-only entanglements to
strip") is moot for CE: `internal/analysis/risk` and an EE-only `external_sources.go` handler do
not exist in CE, so any such import fails the build loudly during the port rather than silently
leaking EE-only scoring logic in.

## Build sequence (one self-contained, separately-committable unit per step)

1. **Provider interface + `crtsh`** — foundation; everything else depends on the `Provider`/
   `CTEntry` contract. `go build`/`go test`.
2. **`static`** (Plan A.6 leaf-format correctness) — required for production-correct Sunlight
   log verification; independent of certspotter.
3. **`certspotter`** — independent of static; depends only on the Provider contract.
4. **`multi`** — depends on all three (composes children of any of the three kinds).
5. **Config + `main.go` wiring** — replace the dead stub, wire all 4 `Enabled`-gated blocks.
6. **README moat-list update** — CT multi-provider arc moves out of any EE-only listing (mirrors
   `docs/superpowers/specs/2026-05-31-ce-connector-port-design.md:114-115`).

Steps 1-3 are largely independent after the Provider interface lands and could be parallelized;
step 4 gates on all three landing first. Per CE's port methodology, lands as one squash commit
pinning the EE source SHA, with a `manifest-*.yaml` audit record following
`docs/superpowers/ce-port/manifest-phase2-l4.yaml`'s `vendored:`/`surgical_edits:`/
`reconciliation:` shape.

## Out of scope (explicit)

- Frontend: no dialogs, no discovery routes, no sources-hub IA. Matches CE's existing
  config-only convention for every connector.
- EE's coverage-envelope / contribution-kind wiring (rm:0282, `ContributableTypes`/
  `ContributedTypes` on `externalsource.KindSpec`) — CE has no `externalsource` package for it
  to attach to; deferred as its own future port if CE ever needs the concept.
- Dynamic, UI-editable per-source registration (EE's `external_sources` table/API) — CE's CT
  sources are `config.toml`-configured like every other connector, restart to change.
- Any EE Layer 4.4 risk-scoring / Insights-tab wiring — CE has neither package; not applicable.

## Open questions (non-blocking; owner can decide at implementation)

- Exact per-domain field names/defaults for the TOML shape above are illustrative — final field
  list should be confirmed against each EE `Config` struct
  (`crtsh/config.go:29-34`, `static/config.go:21-33`, `certspotter/config.go:27-38`,
  `multi/config.go:14-21`) at implementation time, since this design summarizes rather than
  exhaustively transcribes every field.
- Migration filename/version tag for CE's own `CHANGELOG.md` (e.g. whether this lands in
  v2.3.0 or a later minor) is a release-scheduling call, not a design call — no migration file is
  needed either way per the "zero new migrations" finding above, so this only affects
  `CHANGELOG.md` framing, not schema.
