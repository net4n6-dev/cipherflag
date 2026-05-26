# L4-E CBOM Golden-File Snapshot Suite

This directory holds the committed byte-level snapshots of the CBOM
emit pipeline, scrubbed of volatile fields. Three goldens, one per
public emit method:

| Golden                   | Source method              | Scope                                |
|--------------------------|----------------------------|--------------------------------------|
| `scope_rich.json`        | `Generator.Generate`       | Full unfiltered output of rich seed  |
| `application_rich.json`  | `GenerateForApplication`   | Scoped to `app-1` (seed.App1Tag)     |
| `repo_rich.json`         | `GenerateForRepo`          | Algorithm-only output for `repo-1`   |

All three use the SAME seed (`seedPKIScenarioForCBOMRich` in
`../../cbom_testhelper_rich_test.go`). One seed, three filtered views.

Note: `repo_rich.json` contains ALGORITHM components only — the repo
scope emits no certificate components by design (see Task 7 discovery
in the spec). The repo scope's job is to surface algorithm coverage
per repository, not cert inventory.

## Regeneration

Any expected change to emit logic — algorithm field surface, scope
filter, JCS layout — produces a byte diff in these files. Regenerate:

```bash
go test -tags integration -count=1 \
  -run TestGolden_ ./internal/export/cbom/ -update
```

Note: the path is `./internal/export/cbom/` (no `/...`) — the `-update`
flag is only defined in `internal/export/cbom/golden_test.go`, and the
sub-packages (`sinks/syslog`, `sinks/types`, `sinks/s3`, `sinks/splunk`)
don't redeclare it, so passing `/...` would fail flag parsing in those
packages.

After regen: **always** `git diff testdata/golden/` and confirm every
byte change is intended. A reviewer should see the diff in the PR and
ask "is this expected?".

## Scrubbed (volatile) fields

The `scrubVolatileFields` helper in `../../scrub_test.go` replaces these
paths with placeholders before comparison so the goldens stay stable
across runs:

| JSON path                                        | Placeholder    |
|--------------------------------------------------|----------------|
| `serialNumber`                                   | `<SERIAL>`     |
| `metadata.timestamp`                             | `<TIME>`       |
| `metadata.tools.components[].version`            | `<VERSION>`    |
| `components[].properties[].value` (`first_seen`) | `<TIME>`       |
| `components[].properties[].value` (`last_seen`)  | `<TIME>`       |
| `components[].properties[].value` (`scored_at`)  | `<TIME>`       |
| `signature.value`                                | `<SIGNATURE>`  |

Scrubbing is **pure test code**. Operators / auditors / downstream
consumers always receive the un-scrubbed bytes. See the spec at
`docs/superpowers/specs/2026-05-16-l4-e-cbom-golden-suite-design.md`
for the compliance note.

`signature.value` is scrubbed because `Generator.Generate` populates
`bom.SerialNumber = uuid.New()` and `metadata.timestamp = time.Now()`
on every call; even with a deterministic signing key, the signed
payload would differ each run. The surrounding `algorithm` and
`publicKey` fields are NOT scrubbed, so structural regressions still
fail the diff — only the per-run signature bytes are opaque.

## Fixture signing key

`fixture-signing.key` (raw 64-byte Ed25519 in PEM, NOT PKCS#8) is
checked in so the JSF signature *shape* is byte-stable. The PEM body
is the literal `ed25519.PrivateKey` (seed || public key), which is
the format `NewFileSigner` in `../../signer_file.go` reads directly
from `block.Bytes`. See `fixture-signing.key.README` for the
derivation seed and constraints. NOT FOR PRODUCTION USE.

## Property tests

`../../golden_properties_test.go` contains five structural assertions
on the live `*cdx.BOM` (before serialisation). They run alongside the
goldens and catch shape regressions that byte diffs might miss after a
regen. Notes on adaptations from the spec:

- Property 1 asserts the cert fingerprint is encoded in the BOMRef
  (`cert:<fingerprint>`), not in a separate property. The
  `cipherflag:fingerprint_sha256` property the spec named doesn't
  exist in production emit — `mapper.go:144` emits the fingerprint
  as the BOMRef prefix. The adapted assertion catches the same class
  of regression ("a cert component must carry an identifying
  fingerprint").
- Property 5 walks the `dependsOn` graph to validate cert ref
  integrity. The rich seed emits no `related-crypto-material`
  components today (no SSH keys), so the original spec form
  (iterating related-crypto-material refs) is vacuous and reserved
  for future expansion. The adapted assertion iterates the
  `dependsOn` graph and asserts every `cert:` reference there
  resolves to a cert component in the BOM.
  `cert:cbom-rich-shadow-issuer-1` is the one documented dangling
  ref (orphan-CA fixture case) and is explicitly allowlisted.

## Determinism work to support this suite

Five auxiliary commits accompanied the suite to make emit reproducible
across runs:

- `generator.go` — sort `enrichedAlgos` map keys before component
  emit (JCS canonicalises object keys but preserves array order per
  RFC 8785 §3.2.2). Commit `15c2c92`.
- `properties.go` — sort `Compliance`/`RiskFactors` map keys before
  property emit, same bug class. Bundled in `15c2c92`.
- `application.go` — same fix for `GenerateForApplication`. Commit
  `fe432d4`.
- `mapper.go` — `.UTC()` normalisation on cert validity timestamps
  (Postgres driver returned local-timezone times). Commit `1062ed3`.
- `cbom_testhelper_rich_test.go` — pin seed `now` to fixed UTC
  timestamp so cert `notValidBefore`/`notValidAfter` (which aren't
  scrubbed) are stable. Commit `bcfb91b`.

Each is pure-additive (no semantic content change) — only emit order
and value normalisation. Without them the JSF signature is
non-reproducible.

## Adding a new golden

1. Add a `TestGolden_<NewMethod>` to `../../golden_test.go` following
   the existing pattern (`withGoldenDB` → seed → generate → emit →
   `runGoldenAssert`).
2. Run with `-update` to materialise the file.
3. Add the file to this README's table.
4. If the new method exposes a new volatile field, extend
   `volatileScrubs` in `../../scrub_test.go` and document it here.
5. Run with `-count=3` to confirm reproducibility before committing.
