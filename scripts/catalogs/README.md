# Catalog generators

Reproducibly regenerates the three Layer 4 reference catalogs from upstream:

- `refresh-eol.go` → `internal/analysis/scoring/library_eol_data.go` (from endoflife.date)
- `refresh-fips.go` → `internal/analysis/scoring/library_fips_data.go` (from manual `watchlists/fips.yaml`)
- `refresh-pqc.go` → `internal/analysis/pqc/catalog.go` + `synonyms.go` (from NIST FIPS, liboqs, IETF + `watchlists/pqc.yaml`)

## Usage

From the repo root:

```bash
make refresh-catalogs
git diff   # review
git add -p && git commit -m "data(catalogs): refresh $(date +%Y-%m-%d)"
```

Or per-catalog:

```bash
make refresh-eol
make refresh-fips
make refresh-pqc
```

## Generator file convention

Each generator follows a split-file pattern to avoid `func main()` conflicts across the three generators in `package main`:

- `refresh-<kind>.go` carries `//go:build ignore` + `func main()`. Excluded from `go build` and `go test`, but runnable via `go run ./refresh-<kind>.go`.
- `<kind>_gen.go` holds the testable helpers (types + transform functions + I/O). No build tag — contributes to `package main` for both `go build` and `go test`.

Refresh-eol.go is the original pattern and currently does NOT use this split — it has `func main()` without the build tag. When a third generator is added (PQC), all three will need the split-file pattern to coexist.

## Stale-entry policy

Each generator emits **only** what the upstream + watchlist currently contains. Entries that disappear from upstream are deleted on refresh. To preserve a historical entry (e.g., NIST CMVP withdrew a cert but the library is still deployed), add it under the corresponding `watchlists/*.yaml` `manual:` section.

## When upstream schemas change

If a generator panics on a malformed upstream response, the upstream schema may have drifted. Update the generator's parsing logic + the test fixture in `testdata/`. Then re-run.

## FIPS automation status

NIST CMVP has no clean JSON API as of 2026. `refresh-fips.go` reads `watchlists/fips.yaml` (manually curated). To add a FIPS entry: search `https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search`, find the cert number, add it to the watchlist, re-run.

## Separate Go module

This directory has its own `go.mod` so the generator-only dependencies (`gopkg.in/yaml.v3`) don't pollute the main module's runtime dependency tree.
