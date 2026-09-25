# CBOM export completion (v2.3, Spec 1 of 3)

Status: design approved in conversation 2026-09-25; awaiting written-spec review.
Target release: **2.3.0**.
Source: `docs/handover-cbom-v2.3-candidates.md` (re-verified against the code on
2026-09-25; corrections noted below).

## Context and slicing

The v2.3 candidate set was split into three specs plus one small change:

1. **This spec:** estate and application CBOM export, the shared serialiser
   (signed-output fix), honest asset counts (handover bug 2), syslog TLS
   without a client certificate (handover bug 5).
2. Import signature policy (off / verify / require_trusted) and a shared
   `Verify` used by the `verify-cbom` CLI.
3. CBOM UI (download and import), built on specs 1 and 2.
4. Sightings retention loop: a bounded change, handled separately.

Already shipped and out of scope here: 2.2.2 (nil FIPS-lookup crash), 2.2.3
(`verify-cbom` validation, admin-only import, scheduler panic containment,
import normalization).

Porting rules (settled in `project_ce_v2_strategy`): CE is a clean-room repo
that vendors curated EE pieces under Apache-2.0; EE-only models and imports are
stripped, not carried over.

## Goals

- `GET /api/v1/export/cbom/estate` and `GET /api/v1/applications/{tag}/cbom`
  exist, are signed when `[cbom.signing]` is enabled, and never silently lose
  their signature.
- One assembly pipeline instead of three near-copies.
- A BOM's asset counts describe what it actually contains.
- Syslog-over-TLS works against servers that do not require client certificates.

## Findings that shape the design

1. **Signed output is lost on three writers (found in this brainstorm; not in
   the handover).** `cdx.JSFSignature` embeds `*JSFSigner` with `json:"-"`
   (cyclonedx-go v0.10.0, `cyclonedx.go:852-853`), so any encoder built on
   `encoding/json` drops the algorithm, value and public key. The file and HTTP
   sinks avoid this via `encodeBOM` -> `MarshalSignedBOM`. These do not:
   - `internal/api/handler/cbom.go:149` (`GET /export/cbom`, `cdx.NewBOMEncoder`)
   - `internal/api/handler/repo_cbom.go:77` (`json.NewEncoder`)
   - `internal/export/cbom/sinks/s3/s3.go:118` (`cdx.NewBOMEncoder`)

   Established from the struct tag and call sites; **not yet reproduced at
   runtime**. Reproducing it is the first implementation step. The handler
   tests have no signing case. With signing enabled the server logs "CBOM
   signing enabled" at startup, so operators would believe these outputs are
   signed.
2. **The pipelines are not identical.** `Generate` (`generator.go`) and
   `GenerateForApplication` (`application.go`) differ in:
   dependency scope (`func(string) bool { return true }` vs `inBom[ref]`),
   root-component properties (`host_count` vs `application.tag` /
   `fisma_id_alias`), mapping-error handling (`Generate` returns the error,
   `GenerateForApplication` skips the row), and log labels. The shared builder
   must parameterise these or the golden tests will fail.
3. **`WriteTimeout` is 30s server-wide** (`cmd/cipherflag/main.go:363`) with no
   per-route override, and the handlers build the whole BOM before writing. A
   large estate can be cut off mid-response.
4. **Bug 2 in CE is narrower than in EE.** The CE scorer dispatches only
   certificate, ssh_key, crypto_library and crypto_config
   (`internal/analysis/scoring/dispatcher.go`), and `crypto_protocol` is
   EE-only. `asset_count = len(rows)` is still wrong whenever a health report's
   asset has been deleted, because `mapRow` returns no component for it.
5. **Bug 5 confirmed:** `syslog.go` calls `tls.LoadX509KeyPair` unconditionally
   and `SyslogSinkConfig.Validate` requires `cert_file`/`key_file` for
   `protocol="tls"`. CE's Splunk sink already offers `tls_insecure`
   (`config_sinks.go:88`).
6. Verified unchanged: `ListAllAssetHealthReports` (`store/cbom_store.go:185`)
   and `GenerateForApplication` have no caller or route today. The CE frontend
   has no CBOM references (relevant to Spec 3).

## Design

### Units

**`bomcodec`** (new package `internal/export/cbom/bomcodec`)
- Holds `MarshalSignedBOM` (moved from `signing.go`, with `jsfSignatureJSON` /
  `jsfPublicKeyJSON`) and `Write(w io.Writer, bom *cdx.BOM) error`.
- Depends only on `cyclonedx-go`. This lets `sinks/s3` import it; `s3` cannot
  import `cbom` (import cycle).
- `cbom.MarshalSignedBOM` remains as a one-line wrapper so
  `cmd/cipherflag/cbom_sign.go` and `encodeBOM` compile unchanged.
- `cbom.encodeBOM` delegates to `bomcodec`; the S3 sink calls `bomcodec`
  directly.

**`buildBOMFromRows`** (`cbom/generator.go`)
- The mapping, enrichment, dependency and signing steps move out of `Generate`
  into one function. Input: rows plus a parameter struct
  `{root *cdx.Component, label string, inScope func(ref string) bool}`.
- `Generate` (scope), `GenerateForApplication`, and the new
  `GenerateWholeEstate` become wrappers that choose rows and build the root:
  - scope and estate: `inScope = always true` (current `Generate` behaviour);
  - application: `inScope = inBom[ref]` (current behaviour).
- EE's rule-engine provenance properties (`ruleEngineMetadataProperties`,
  `documentRuleProvenanceProperties`) are **not** ported.
- Mapping errors fail the export for all three (see Decisions).

**`writeBOM`** (handler package, one helper for all four export handlers)
- Encodes through `bomcodec` into a buffer first, so a serialisation failure
  becomes a real `500` (today headers are sent before encoding and the error is
  dropped).
- Sets `Content-Type`; sets `Content-Disposition: attachment` when given a
  filename. The existing scope download passes none, so its response headers do
  not change.
- A companion `extendWriteDeadline(w)` calls
  `http.NewResponseController(w).SetWriteDeadline(time.Time{})`, ignoring
  `http.ErrNotSupported`, and is called at the top of each export handler
  (scope, estate, application, repo-CBOM), before generation starts.

### API surface

| | Estate | Application |
|---|---|---|
| Route | `GET /api/v1/export/cbom/estate` | `GET /api/v1/applications/{tag}/cbom` |
| Access | any authenticated user | any authenticated user |
| Filename | `cipherflag-cbom-estate-YYYY-MM-DD.cdx.json` | `cipherflag-cbom-app-<tag>-YYYY-MM-DD.cdx.json` (tag sanitised to `[A-Za-z0-9._-]`) |
| Rows | `ListAllAssetHealthReports` | `ListApplicationScopeAssets` |
| Root component | `bom-ref` `estate`, property `cipherflag:estate.asset_count` | existing `application:<tag>` root |

- Tag handling: trimmed like the `/applications/{tag}/metadata` routes; empty
  gives `400`. A tag with no scored assets returns `404`
  ("no scored assets carry this application tag") via a sentinel error from
  `GenerateForApplication` when the row query returns zero rows. Rows that all
  turn out to be omitted still return `200` with the omission properties.
- Generation failure returns a generic `500`; the error is logged (today the
  handlers discard it).
- Both routes sit in the existing authenticated group; no `RequireAdmin`.

### Honest asset counts (bug 2)

- `buildBOMFromRows` overwrites the root's `*.asset_count` value with the number
  of asset components actually emitted (was `len(rows)`).
- When any rows produced no component it appends `*.assets_omitted` (count) and
  `*.assets_omitted_types` (sorted, comma-joined asset types), using the same
  prefix as the count property. Absent when nothing was omitted.
- Property order is preserved by patching in place and appending at the end,
  as EE does; the golden property tests are the guard.
- In CE, a non-zero omission means orphaned health reports.

### Syslog TLS (bug 5)

- `cert_file` and `key_file` become optional but must be set together
  (`Validate` rejects one without the other). Neither set: server-authenticated
  TLS against `ca_file` or the system roots. Both set: mutual TLS as today.
- New `tls_insecure` (default `false`) sets `InsecureSkipVerify`, mirroring the
  Splunk sink; a warning is logged when the sink is constructed with it on.
- `docs/configuration.md` documents the option and the both-or-neither rule.

## Decisions log

| Decision | Choice | Alternatives rejected |
|---|---|---|
| Slicing | Three specs + one small change | One umbrella spec; backend-only v2.3 |
| Signed-output bug | Fold into this spec (ships in 2.3.0) | Separate 2.2.4 patch first; log and defer |
| Large estates | Extend write deadline on export routes; no cap | Configurable cap; cap with 30s timeout |
| Architecture | Shared pipeline + shared serialiser (A) | Third copy + in-place patches (B); port EE `generator.go` wholesale (C) |
| Mapping errors | Fail the export | Skip and disclose |
| Empty application tag | `404` | Empty `200` BOM |

The fold-in of the signed-output bug means it stays in released 2.2.x until
2.3.0 ships; this was a deliberate call by the owner.

## Testing

Order of work (each step a separate, revertable commit; at most 5 files per
phase per `docs/CLAUDE.md`; apply the Step-0 dead-code rule to any touched file
over 300 LOC):

1. **Signed-output fix.** Failing tests first for each writer; then `bomcodec`
   and the writer changes.
2. **Pure refactor** to `buildBOMFromRows`. Existing golden tests
   (`golden_test.go`, `golden_properties_test.go`,
   `generator_dependencies_test.go`, `repo_generator_test.go`) pass unchanged.
3. **Count fix and disclosure**, then the two endpoints, then syslog TLS and
   docs.

Tests:
- **Signatures:** for scope download, repo CBOM, estate, application and the S3
  encoder, a signed BOM has a full `signature` block. The test strips the
  block, canonicalises with `cbom.Canonicalize`, and checks it with
  `ed25519.Verify` against the embedded key.
- **Counts:** an orphaned row lowers `asset_count` and adds the omission
  properties; a clean run has neither.
- **Endpoints (via `NewRouter`, like `server_import_gate_test.go`):**
  unauthenticated 401, viewer allowed, tag `400`/`404`, filename sanitisation,
  empty estate returns a valid BOM.
- **Deadline:** a real `httptest.Server` with a short `WriteTimeout` and a slow
  handler; the helper lets it finish. (`httptest.ResponseRecorder` cannot
  exercise this.)
- **Syslog:** `Validate` table; TLS with `ca_file` and no client cert against a
  local TLS server; `tls_insecure` against a self-signed server; verification
  failure with neither.

Success criteria: golden and existing tests unchanged; `go test ./...` green;
every signed output verifies; docs updated.

## Out of scope

Filtered export; CBOM UI (Spec 3); import signature policy and shared `Verify`
(Spec 2); sightings pruning; export streaming or a size cap; EE rule-engine
provenance, `pqc_disposition` and `identity_kind` properties.

## Known limits (to be documented)

- The estate BOM is assembled in memory (a signed BOM must be, because JCS
  canonicalisation cannot stream), with one store lookup per asset.
- The write-deadline extension is per response; very large estates are bounded
  only by client patience and server memory.

## Release notes to carry into the changelog

- Security: signed BOMs from `GET /export/cbom`, the repo-CBOM route and the S3
  sink were emitted without their signature. Re-download anything relied on as
  signed.
- Added: estate and application CBOM endpoints.
- Fixed: `asset_count` now reflects emitted components, with omission
  disclosure; syslog TLS no longer requires a client certificate; export
  handlers no longer time out at 30s or drop serialisation errors.
- Follow-up outside this repo: the EE context should check whether EE's
  `DownloadEstate` and related handlers have the same unsigned-output problem.
