# Changelog

All notable changes to CipherFlag are documented in this file.

## [2.3.1] - Unreleased

### Fixed
- **A stock install never scored anything.** `analysis.scorer_enabled`
  defaulted to false and the shipped config did not set it, so the dashboard
  grade donut, risk cards, health findings, compliance gauge and CBOM findings
  stayed empty. Scoring is now on by default (set `scorer_enabled = false` to
  opt out), the shipped configs set it explicitly, `docs/configuration.md`
  documents it, and `serve` logs a warning when scoring is off.
- **CipherFlag has not read Zeek logs since 2.0.0.** The 2.0.0 release
  dropped the Zeek log poller, so from 2.0.0 to 2.3.0 no certificate or TLS
  session seen by a Zeek sensor reached CipherFlag, although
  `[sources.zeek_file]`, its Settings tab, the sensor image and the docs all
  remained. A new poller reads the sensor's `x509` and `ssl` logs from
  `log_dir`:
  - It covers live logs, the files Zeek's hourly rotation renames them to,
    and each offline PCAP job once the sensor has finished it.
  - Certificates are stored in full from the PEM the sensor now logs;
    sessions become observations (server, SNI, TLS version, cipher, JA3).
  - Files are followed across rotation, only complete lines are read, and
    the position is kept in `ingestion_state`, so a restart resumes where it
    left off.
- **The Zeek sensor image failed at startup.** `cipherflag-ce-zeek` was
  built on `zeek/zeek:latest`, which moved to Zeek 9, and Zeek 9 removed the
  `extract-certs-pem` policy the sensor loaded. The images published for
  2.3.0 (and `latest`) have this bug:
  - Live capture exits at once.
  - Every PCAP job is marked done with no logs.

  The fixed image:
  - pins Zeek 9.0.0 by digest;
  - logs each certificate in `x509.log` (`log-certs-base64`);
  - ignores the invalid TCP checksums that NIC offloading produces, which
    otherwise made Zeek drop all TLS traffic;
  - marks a PCAP job Zeek cannot process `.failed` instead of `.done`.
- **Docker Compose no longer ran the Zeek sensor.** The `zeek` service was
  removed in 2.0.0. It is back as an opt-in profile,
  `docker compose --profile zeek up -d`:
  - It captures on `NETWORK_INTERFACE` (Linux hosts) and processes PCAP
    files copied into `./pcap-input/<job>/`.
  - `cipherflag` reads its logs read-only at the configured `log_dir`.
  - A plain `docker compose up` is unchanged.
- **Documentation described things CE does not do.** The README,
  quickstart, user guide, configuration reference and Venafi guide
  described:
  - `VENAFI_*` environment variables (CipherFlag reads none);
  - a PCAP upload page;
  - an install script and interactive setup wizard;
  - the API on port 8080 (it is 8443);
  - an agent token issued at setup.

  They also said to change `POSTGRES_PASSWORD` without the matching change
  to `postgres_url`, which leaves CipherFlag unable to connect. All of
  these are corrected.

### Changed
- CI (and so the release workflow) builds the Zeek sensor image and runs it
  over a fixture PCAP before anything is published.

### Notes
- On upgrade, installs with `[sources.zeek_file] enabled = true` (the
  default) start reading `log_dir`. That includes any logs already there,
  worked through 16 MB per file per poll. If nothing writes to `log_dir`,
  CipherFlag logs one warning and carries on.
- Zeek sees a server's certificate only in TLS 1.2 and earlier handshakes;
  TLS 1.3 encrypts it.

## [2.3.0] - 2026-09-27

### Security
- **Signed BOMs were emitted without their signature on three paths.**
  With `[cbom.signing]` enabled, `GET /api/v1/export/cbom`, the repo-CBOM
  download and the S3 sink wrote `"signature":{}`: the signature was
  computed but lost when the BOM was serialised. The server logged
  "CBOM signing enabled" at startup, so these outputs looked signed. All
  writers now go through one serialiser that keeps the signature, and
  tests verify the signature on every path. Re-download any BOM you
  relied on as signed. (File and HTTP sinks were not affected.)

### Added
- `GET /api/v1/export/cbom/estate`: a CBOM over every scored asset.
- `GET /api/v1/applications/{tag}/cbom`: a CBOM of the assets carrying an
  application tag (`404` when no scored asset carries it).
- Both are readable by any authenticated user and signed when signing is
  enabled.
- Syslog sink: `tls_insecure` option, and `cert_file`/`key_file` are now
  optional for `protocol = "tls"` (server-authenticated TLS). Setting only
  one of the two is a configuration error.
- **Certificate Transparency sources** (off by default, configured in
  `config/cipherflag.toml` only): `ct_crtsh` (crt.sh), `ct_static` (Static
  CT API / Sunlight logs, verifying each log's signed checkpoint and the
  inclusion of every leaf), `ct_certspotter` (SSLMate CertSpotter), and
  `ct_multi`, which combines the other three for one set of domains and
  records which provider found each certificate. Configured domains are
  validated at startup. They replace the CT settings stub of earlier
  versions, which did nothing. `ct_static` watches forward from the log's
  current head; historical coverage comes from `ct_crtsh` and
  `ct_certspotter`. See the README for the per-log values `ct_static`
  needs.

### Fixed
- BOMs named their producing tool as `cipherflag dev`; they now carry the
  release version, as does the CBOM push `User-Agent`.
- **Settings → Sources showed made-up values, and saving overwrote the real
  Zeek configuration.** Since 2.0.0 the sources API no longer returned the
  Zeek settings the page reads, so the page silently kept its placeholder
  defaults (Zeek enabled, `/var/log/zeek/current`) and "Save Source
  Configuration" wrote them to `config/cipherflag.toml`. The API returns the
  Zeek settings again; the page checks the response, and if it cannot load
  the configuration it says so and disables Save. A contract test pins the
  response shape on both sides. If you saved this tab on 2.0.0 to 2.2.x,
  check `[sources.zeek_file]` in your config.
- **Certificates posted to `/api/v1/ingest` with only their PEM were stored
  blank.** The ingester derived the fingerprint from `RawPEM` but nothing
  else, so subject, issuer, CA flag, key and validity stayed empty; such
  certificates were scored on nothing and never appeared in the PKI graph.
  A certificate that arrives with its PEM, from any source, is now stored
  with everything in it: names, organization, serial, validity, key,
  signature, SANs, CA flag and path length, key usages, key IDs, SPKI
  fingerprint and OCSP and CRL locations. Values a client or adapter sends
  are kept over the PEM's, except an `Unknown` algorithm. A fingerprint
  that does not match the PEM is now rejected (the certificate is skipped
  with a warning) instead of stored.
- **A certificate's "last seen" never moved after its first ingest.** A
  re-observed certificate was written back with the `last_seen` it was
  read with, so reports showed the first-seen date as last seen and the
  Venafi push, which re-sends certificates seen since their last push,
  never picked a re-observed certificate up again. Re-observations now
  update `last_seen`.
- A certificate stored with missing details now gets them when it is seen
  again: each empty field (including an `Unknown` algorithm) is filled from
  the new observation, a field that is already set is never overwritten,
  and a CA is never recorded as a non-CA. `source_discovery` now keeps the
  source that first discovered the certificate; every source that saw it
  is still recorded in its provenance.
- Re-observing a certificate no longer erases its stored authority and
  subject key IDs (every re-observation wrote empty ones over them), and
  the SPKI fingerprint, which was never stored, is now recorded. Nothing in
  CE displays these yet; the data is now kept intact.
- Certificates an earlier version stored blank (posted to `/api/v1/ingest`
  with only their PEM) are repaired automatically: at startup `serve`
  rebuilds them from their stored PEM, scores them, and logs how many it
  repaired. Nothing needs to be re-sent. A stored PEM that does not parse,
  or belongs to a different certificate, is left as it is and counted as
  skipped in the same log line.
- **`scan-truststore` stored almost nothing and still reported success.**
  Trust-store and private-key rows reference certificates by fingerprint,
  but the command never stored the certificates it found, so every row for
  a certificate CipherFlag had not already seen failed and was dropped with
  a warning. A scan of a macOS host found 414 trust-store entries and stored
  none. The command now stores each certificate it finds first (with its
  metadata, provenance on the scanned host, and scoring), and then the rows.
  As a result, CA certificates from scanned trust stores now appear in the
  certificate inventory, and in findings, like any other certificate.
- The CBOM signing key is read once, at startup, and that one key signs
  every emitted and downloaded CBOM. It used to be read up to four times
  during startup, so a key file replaced or briefly empty at that moment
  could crash `serve` after the startup check had passed, or have the
  runtime and the download handlers sign with different keys. As before, a
  new key takes effect on restart.
- **A CA or private key removed from a host stayed in the inventory
  forever.** `scan-truststore` only added and refreshed rows. It now also
  removes, for each trust bundle and keystore it actually read, the CAs and
  keys no longer in it. A bundle that is missing, cannot be read (a
  permission problem, a locked keychain), cannot be decoded (a keystore
  password that does not match) or was not probed in this run is left
  exactly as it was, as is a bundle with a row the scan could not write. A
  keystore with a private-key entry that the keystore password does not
  open keeps its held keys (its CAs are still reconciled). A bundle that is
  deleted outright keeps its rows; only removals from a bundle that is
  still readable are reconciled.
- **One unwritable trust-store or private-key row lost the whole scan's
  rows.** The rows were written as one batch, which the database runs as a
  single transaction, so one failure aborted every row after it and rolled
  back the ones before it, which had reported success. Each row is now
  written on its own.
- **`host_ip_sightings` grew without limit.** Ingest records a sighting
  for every host and IP it observes, and nothing deleted them. `serve` now
  deletes sightings not seen for 7 days, once at startup and then daily.
- **`asset_count` overstated BOM contents.** It now equals the number of
  asset components in the BOM. When health reports were dropped because
  their asset no longer exists, `assets_omitted` and `assets_omitted_types`
  properties disclose it.
- Application exports now fail on a mapping error instead of silently
  omitting the asset, matching scope exports.
- CBOM export handlers no longer time out at the server's 30-second write
  limit, no longer discard generation errors silently, and return a real
  `500` if serialisation fails instead of a truncated `200`.
- The PKI Constellation's "View full detail" link and its search fallback
  went to `/assets/certificate/…`, a route CE does not have, and showed the
  not-found page. They now open the certificate detail page. A frontend test
  now fails the build when any in-app link names a route that does not
  exist.
- Clicking a CA in Analytics → Chain Flow opened the PKI Constellation with
  nothing selected: the link went through the `/pki` redirect, which
  dropped its `?select=` parameter. It now opens the constellation with that
  CA selected (or its certificate page if the CA is not in the graph), and
  old `/pki?select=` links keep working.
- **`verify-cbom` reported a trust mismatch for a genuine BOM when
  `--trusted-key` was a standard SPKI public key** (from OpenSSL, or from
  CipherFlag EE 4.11's `generate-signing-key`). It read the PEM body as a
  raw key, which never matched, and exited `1`. Every signing-key reader
  (the file and env signers and `--trusted-key`) now accepts standard
  PKCS#8/SPKI keys as well as the raw keys CE has always written. A
  trusted key that is not an Ed25519 public key (including a PEM block
  labelled other than `PUBLIC KEY` or `ED25519 PUBLIC KEY`, such as a
  private key) is now reported as an error naming the file instead of as
  a trust mismatch. A raw private key
  whose public half does not match its seed, which signed BOMs no verifier
  accepts, is now rejected when loaded. See "Key formats" in
  `docs/configuration.md`.
- **A signing key that could not be loaded crash-looped the server.** With
  `[cbom.signing]` enabled and a missing or unusable key, `serve` got past
  startup and then panicked while building the CBOM runtime or the CBOM
  download handlers, so a container under `restart: unless-stopped`
  restarted forever. `serve` now checks the key first and exits with one
  line naming the key file or environment variable and the way out
  (`[cbom.signing] enabled = false`), before connecting to the database.

### Changed
- `docker-compose.yml` runs the release it ships with
  (`ghcr.io/net4n6-dev/cipherflag-ce:2.3.0`) instead of `:latest`.
- **`verify-cbom` exits `3` when it could not verify (breaking for
  scripts).** Its documented codes are `0` (valid), `1` (valid, signed by a
  different key) and `2` (invalid), but runs that checked nothing exited
  with those codes too: `-h` exited `0`, a missing `--bom` and an unloadable
  `--trusted-key` exited `1`, and an unreadable BOM or an unknown flag
  exited `2`. A stray extra argument was ignored and `--bom` verified as
  usual. All of these now exit `3`. Malformed, unsigned and tampered BOMs
  still exit `2`, as does a BOM with no RFC 8785 canonical form (no valid
  signature can cover one). The trusted key is now loaded before the
  signature is checked, so a run that cannot finish the trust check no
  longer prints "Signature valid" first. Scripts that treated `1` as
  "wrong key" for an unreadable key file should treat `3` as a failure to
  run.
- **`generate-signing-key` writes standard PKCS#8 and SPKI key files.** It
  wrote Go's raw key bytes under the PKCS#8/SPKI PEM labels, which OpenSSL
  and other tools could not read. The printed fingerprint is still the
  SHA-256 of the raw 32-byte public key, so fingerprints recorded for older
  keys stay valid, and raw keys made by earlier versions keep working.
  CipherFlag CE before 2.3.0 cannot load the new files: its `verify-cbom`
  reports a trust mismatch on a new `.pub` and its signer rejects a new
  `.key`. Use 2.3.0 or later wherever a new key is used.
- **Releases are gated on the full CI suite.** The release workflow used to
  publish images on any `v*` tag without running tests. It now runs the
  CI workflow (Go, integration and frontend jobs) and checks that the tag
  matches `Version` in `cmd/cipherflag/main.go` before building images. A
  prerelease tag (for example `v2.3.0-rc1`) no longer moves `:latest` and is
  marked as a prerelease on GitHub.
- **CLI subcommands exit `2` when invoked wrongly (breaking for scripts).**
  `generate-signing-key`, `sign-cbom`, `scan-truststore`, `declared-cas
  import`, `ownership declare`/`import`/`backfill` and
  `application-metadata declare`/`import` now exit `0` when they did what
  was asked, `1` when they tried and failed, and `2` when the invocation
  was wrong and nothing was done. Before, `-h` exited `0` (success), a
  missing or invalid required flag exited `1` (failure), and a stray
  argument was ignored: `generate-signing-key foo` wrote
  `cbom-signing.*`. Stray arguments are now rejected. `verify-cbom` keeps
  its own `0`-`3` codes.
- The README documented `verify-cbom <file>` and `sign-cbom <file>`; both
  take flags (`--bom`, `--trusted-key`, `--key`), and the positional form
  failed. The README now shows the real usage.

### Removed
- **The Upload (PCAP) page.** It was listed in the sidebar but could never
  work in CE: PCAP upload and processing are Enterprise Edition features and
  CE registers none of the `/api/v1/pcap/*` routes the page called. The
  page, its sidebar entry and the PCAP settings cards are gone. The `[pcap]`
  config section is no longer in the sample configs; existing configs that
  contain it still load, and the settings API still reports it, but CE does
  not use it.

### Notes
- The estate export is assembled in memory with one lookup per asset; very
  large inventories cost memory and time proportional to their size.

## [2.2.5] - 2026-09-25

### Fixed
- **Release pipeline could never publish CE container images.** The Release
  workflow pushed to `ghcr.io/net4n6-dev/cipherflag` and `cipherflag-zeek`,
  names already owned by the Enterprise Edition's packages, so every push was
  denied and no CE image or GitHub Release was published for v2.2.1 through
  v2.2.4. CE images are now published as `ghcr.io/net4n6-dev/cipherflag-ce` and
  `ghcr.io/net4n6-dev/cipherflag-ce-zeek`, tagged with the version and `latest`.
  `docker-compose.yml` uses the new name (it also builds from source, so
  `docker compose up --build` needs no pre-built image).

### Changed
- GitHub Releases no longer attach CLI binaries; build from source. The release
  page is created with generated notes only.

### Notes
- The previous `ghcr.io/cyberflag-ai/cipherflag` images are a v1.0 build from
  March 2026 and are not maintained.

## [2.2.4] - 2026-09-25

### Fixed
- **A database built from CE's migrations lacked columns, keys and tables that
  CE's own code uses.** The v2.0 baseline was cut from EE's migrations, but the
  ported Go code was not trimmed to match and several CE-bound columns and
  keys were dropped. On a fresh database this broke:
  - host ingestion and merging (`hosts.aliases`, `hosts.discovery_sources`;
    host merge also updated an EE-only table);
  - SSH key and crypto library ingestion from every agent and endpoint
    connector (`ssh_keys.owner_user`/`is_authorized`/`is_protected`/`grants_root`,
    `crypto_libraries.package_manager`, and unique keys that did not match the
    `ON CONFLICT` targets the upserts use);
  - asset scoring and every CBOM export query (`asset_health_reports.risk_score`,
    `risk_factors`);
  - shadow-CA and application-metadata storage (`added_by`/`added_at` were
    named `declared_by`/`declared_at`);
  - ownership and host-IP sightings (`created_at`; `host_ip_sightings.ip` was
    `inet` while the code treats it as text; `host_id` was NOT NULL although
    unattributed-IP sightings carry no host);
  - the Netwrix connector (`ad_cs_events` table).
  A new migration, `v2.2.4_schema_parity.sql`, adds the missing columns,
  renames the mis-named ones, converts `host_ip_sightings.ip` to text (existing
  rows keep their address, without the `/32` mask), adds the unique keys and
  the EE CHECK constraints CE code relies on, gives the `added_by` foreign keys
  `ON DELETE SET NULL` (see below), and creates `ad_cs_events`. It
  applies automatically at startup and is idempotent. Existing rows are
  preserved (covered by an upgrade test). The CHECK constraints are added
  `NOT VALID`, so they enforce new and updated rows without scanning old ones.
- **Deleting a user who had declared a CA or application metadata now works.**
  The baseline's `declared_by` foreign keys had no `ON DELETE` clause. Those
  tables could not be written before this release, so it went unnoticed; once
  writable, `DELETE /api/v1/auth/users/{id}` would have failed with a
  foreign-key error for any such user. The migration replaces them with
  `added_by ... ON DELETE SET NULL`, matching EE and the stores' own
  documentation: the rows are kept and `added_by` becomes empty.
- Removed CE code that queried EE-only objects CE never creates: the
  `protocol_endpoints` legs of the application summary, application detail,
  deadline, weak-algorithm, application-CBOM, ownership-backfill and HNDL tag
  queries, the `protocol_observations` update in host merge, and the unused
  application-posture-snapshot store functions. Those queries failed on every
  CE database. `GetApplication` no longer runs a snapshot query that always
  failed; `score_delta_7d` and `reference_snapshot_at` stay zero in CE, as
  before.

### Changed
- CI now runs the integration-tagged test suite against a Postgres service, so
  schema drift fails the build. The integration suite (previously not run in
  CI, with 11 failing packages) is green.
- Integration tests and CBOM goldens that asserted EE-only behaviour now assert
  CE's: no PCI DSS 4 / FIPS 203-205 compliance frameworks, no risk-engine
  factors, no certificate-to-issuer dependency edges in CBOMs.

### Notes
- `asset_health_reports.risk_score` and `risk_factors` stay at their defaults in
  CE; the risk engine is EE-only.
- Because the affected write paths never succeeded against the old schema, the
  tables that gain new unique keys were empty on every 2.x database.

## [2.2.3] - 2026-09-25

### Security
- **`verify-cbom` accepted signature blocks that were not Ed25519.** The
  command parsed but never checked the signature `algorithm`, `kty` or
  `crv`, so a BOM whose signature block claimed `RS256`, `RSA` or `P-256`
  was verified as Ed25519 and reported valid (exit 0) whenever the
  Ed25519 signature bytes checked out. It now exits 2 on anything other
  than `Ed25519` / `OKP` / `Ed25519`, and also checks the signature and
  public-key lengths. Re-verify any BOM you previously relied on
  `verify-cbom` to accept.
- **`POST /api/v1/import/cbom` is now admin-only.** It writes
  certificates, SSH keys, libraries and configs from a foreign BOM into
  the shared inventory, but was open to any authenticated caller,
  including the read-only `viewer` role and agent tokens.

### Fixed
- **`verify-cbom` panic on a non-32-byte public key.** A signature block
  with an embedded key of any other length crashed the command
  (`ed25519: bad public key length`); it now exits 2 with a message.
- **CBOM push scheduler no longer dies on a panic.** The scheduled-push,
  event-drain and notify goroutines had no `recover`, so a panic in
  generation, in a sink, or while handling a notify event terminated the
  server. Panics are now contained and logged with a stack: a panicking
  sink no longer starves later sinks in the scope, a panicking scope is
  skipped for that tick while other scopes keep pushing, and the notify
  worker drops the bad event and keeps running.
- **CBOM import now normalizes SSH key types and library names.** Imported
  keys were stored as `ssh-ed25519` and libraries as their raw package
  name (`libssl3`), unlike scanner-discovered assets (`ed25519`,
  `openssl`). Imports now use the same canonical names, so they match
  discovered assets and the FIPS library lookup.

### Notes
- **Behaviour change:** agent tokens, and installs with no users yet, now
  receive `403` on `POST /api/v1/import/cbom`, consistent with the other
  admin-only routes. Use an admin session to import.
- Records created by earlier imports keep their old (non-canonical)
  names. Re-importing a BOM does not update an existing SSH key's type,
  and a library re-imported under its canonical name (for example
  `openssl` instead of `libssl3`) is stored as a new record alongside
  the earlier one, because the library name is part of its identity.

## [2.2.2] - 2026-09-25

### Fixed
- **CBOM export panic when signing is disabled (the default).**
  `NewGeneratorWithSigning` returned a generator with no FIPS library
  lookup when `[cbom.signing]` was off, so any export whose scope held
  both a crypto library and an algorithm component (a certificate or
  SSH key) hit a nil-pointer dereference. The download endpoints
  returned a 500; the scheduled push runs in a background goroutine
  without a `recover`, so it could terminate the process. The disabled
  path now builds the same generator as the signing path, minus the
  signer. Application-scoped CBOM generation shared the same defect and
  is fixed by the same change.

## [2.2.1] - 2026-06-16

### Changed
- **Venafi push-scheduler hot-reload.** The always-on, self-gating
  Venafi pusher now re-reads a thread-safe `LiveConfig` each cycle, so
  `PUT /api/v1/venafi/config` changes (enable / interval / credentials /
  platform) take effect without restarting the server — the API
  response note changes from "restart required" to "applied". Venafi
  client construction is centralized in `BuildClient`, reusing the
  existing TPP base-URL normalization.

### Notes
- Ported from CipherFlag EE v2.6.0.

## [2.2.0] - 2026-06-01

### Operator UI de-moat (Phases 1–3)

CE gains a real operator frontend. The v1 demo UI is superseded by the
operator shell ported from CipherFlag EE under Apache 2.0, backed by
newly de-moated graph, analytics, and live-update APIs. (EE retains the
advanced UX that depends on EE-only backends — host-dependency /
risk-prioritization blast-radius views, AI enrichment, etc.)

### Added

**Operator shell (Layer 8, de-moated)**
- AppShell layout (sidebar + topbar + content) with CE-native
  navigation and a CE badge.
- Dark / light / system theme store; EE design tokens and fonts; full
  light-theme color tokenization.
- TopBar with breadcrumb, theme toggle, global search, and a live SSE
  status dot.

**PKI Constellation explorer**
- 3D PKI constellation page (three.js + threlte scene + `d3-force-3d`
  physics) with an automatic 2D fallback for clients without WebGL.
- `/pki` now redirects to `/constellation` — the constellation is the
  primary PKI explorer.

**PKI graph backend (de-moated)**
- Five `/api/v1/graph/*` routes (`landscape`, `chain/{fingerprint}`,
  `landscape/aggregated`, `ca/{fingerprint}/children`,
  `ca/{fingerprint}/blast-radius`) restore the CE PKI Explorer backend.
- Chain graph builders (`BuildGraphData` / `BuildChainTree`).

**Analytics cutover**
- Analytics page with a CVE-colored, host-count-sized
  library-distribution treemap and an SSH key analytics tab, both with
  graceful empty states.
- Stats routes registered: `chain-flow`, `ownership`, `deployment`,
  `source-lineage`.

**SSE live updates**
- SSE hub + handler + listener fed by Postgres `pg_notify` triggers on
  asset events; `GET /api/v1/events/stream` event stream.
- Frontend `EventSource` client connects on auth; the dashboard
  refreshes (debounced) on `asset.scored` / `asset.discovered` and
  keeps last-good data on a failed refresh.

### Changed
- `POST /api/v1/import/cbom` documented as cert-only by default; pass
  `?host_id=<uuid>` to also import SSH keys, libraries, and crypto
  configs against that host.

## [2.1.0] - 2026-05-29

### Added
- Reproducible Layer 4 catalog generators under `scripts/catalogs/` (`make refresh-catalogs`): EOL (endoflife.date), FIPS (manual NIST CMVP watchlist), PQC (NIST FIPS 203/204/205 + IETF hybrids + watchlist classical).
- Per-entry `Source` URL on the EOL, FIPS, and PQC catalogs.
- `HealthFinding.Evidence` map — `source_url` on EOL (LIB-003) and FIPS (LIB-005) findings; the frontend renders a "source" link / "manually curated" indicator on both the certificate detail page and the graph detail panel. Vitest test infrastructure introduced for the frontend.

### Changed
- `rule_engine_version` bumped 4 → 5: the cron sweeper re-classifies all stored assets on first deploy, backfilling `Evidence` and flagging libraries previously classified "unknown" (expanded catalog coverage). Expect a wave of new EOL/FIPS findings on first post-upgrade scan.

### Notes
- The FIPS catalog is a manually-curated watchlist (NIST CMVP has no clean API). The liboqs PQC registry fetch and a CI auto-refresh job are deferred; refresh is the manual `make refresh-catalogs` contributor workflow.

## [2.0.0] - 2026-05-26

### Major release: EE→CE port (Phase 1)

This release is a fundamental expansion of CipherFlag CE. The feature
set grows from v1.x's certificate-inventory demo into a working
post-quantum migration inventory + CycloneDX 1.6 CBOM toolkit for
budget-constrained federal/state government and developer audiences.

The release vendors a curated subset of features from the proprietary
**CipherFlag EE** product under Apache 2.0. EE remains a separate
product with additional capabilities — see the README §"What's NOT
included" for the moat list.

### Added

**Foundation (Layer 0)**
- Unified crypto asset model with multi-source ingestion
  (`POST /api/v1/ingest`)
- Host identity resolution with deduplication and provenance tracking
- Agent-token auth for unattended ingest

**Endpoint discovery (Layer 1)**
- osquery webhook adapter (`POST /api/v1/ingest/osquery`)
- 4 bash + 4 PowerShell discovery scripts under `discovery-packs/scripts/`
- Script-output parser that auto-classifies output into the unified
  asset model

**Native scanners (Layer 2)**
- SSH key scanner (system + user `~/.ssh/`)
- Crypto-library scanner (OpenSSL, libgcrypt, BoringSSL, mbedTLS,
  GnuTLS, NSS, wolfSSL, language-runtime crypto stdlibs)
- Cert-file scanner (PEM/DER/PKCS12/JKS on disk; matches private
  keys to certs by SPKI fingerprint)
- Config-file scanner (sshd, openssl.cnf, nginx, apache, envoy,
  haproxy)
- Truststore scanner (OS bundles, JVM cacerts, language-runtime CA
  stores)

**Scoring (Layer 4.1 + 4.1b)**
- 47-rule scoring catalog (CE subset: SSH-001..008, LIB-003..005,
  CFG-001..004, and PQC-relevant certificate rules)
- CVE-based library scoring against open NVD/OSV data (LIB-001 +
  LIB-002); 37 seed CVEs covering known crypto-library
  vulnerabilities

**PQC taxonomy (Layer 4.2)**
- 122 recognized algorithm spellings across 8 categories
- Vulnerable, weakened, hybrid, and quantum-safe classification

**Compliance evaluation (Layer 4.3)**
- NIST SP 800-131A Rev 2
- NSA CNSA 2.0
- FIPS 140-3 (algorithm allowlist)
- EU NIS2

**CBOM (Layer 5.1 + 5.2 + 5.3)**
- CycloneDX 1.6 CBOM generation (`GET /api/v1/export/cbom`)
- CBOM import endpoint (`POST /api/v1/import/cbom`)
- Scheduled push with file sink + HTTP sink
- Export sinks: S3 (AWS or S3-compatible), Splunk HEC, Syslog
  (RFC 5424 + CEF)

**Git repository scanner (Layer 6.1a–c)**
- Block 1: PEM/DER/SSH/PKCS12/JKS file parsing
- Block 3: tree-sitter Python + Java parsers, Go AST parser
- Block 4: server config file parsing (nginx/apache/envoy/haproxy/
  openssl.cnf)
- Per-repo CBOM export endpoint

**Performance**
- In-process observation cache for intake dedup
  (`internal/ingest/observcache/`)

### Changed

- **Schema baseline.** Replaced incremental v1.x migrations 001-005
  with single `internal/store/migrations/v2.0_baseline.sql` (24
  tables). Future CE migrations start at `v2.0.1_*.sql` (see
  `internal/store/migrations/README.md`).
- **Repository structure.** `internal/` packages now mirror the
  layered architecture documented in CipherFlag EE
  (analysis/compliance/, analysis/pqc/, analysis/scoring/,
  export/cbom/, ingest/, scanner/, etc.).
- **CryptoStore interface trimmed** — `internal/store/store.go` no
  longer declares risk-engine, blast-radius, host-dependency edge,
  PQC-migration-planner, protocol-endpoint, external-source
  registry, AD CS event, briefing cache, AI ledger, or multi-tenant
  teams methods. Those are EE-only.
- **HTTP API surface** reduced to CE-bound routes. EE-only routes
  (`/risk/*`, `/blast-radius/*`, `/hosts/{id}/dependencies`,
  `/hosts/{id}/subgraph`, `/hosts/{id}/blast-radius`,
  `/hosts/{id}/trust-store`, `/briefing`, `/events/stream`,
  `/teams`, `/external-sources/*`, `/pqc-migration/*`, `/risk/*`,
  `/repo/ai/*`, `/repo/images/*`, `/network/targets/*`, `/venafi/*`,
  `/ad-cs-events`, `/evidence-pack`, `/agency/omb`) are not wired.
  Five application-management routes from `applications.go` (List,
  Get, History, ExportCBOM, ExportOMB, OwnershipRollup) are also
  dropped in CE v2.0 — that handler was excluded from the manifest.
  The single `/applications/{tag}/metadata` endpoint (GET/PUT/DELETE)
  IS wired via `appMetaH` and remains CE-bound.

### Removed

- v1.x seed-data fixtures (replaced by real ingest paths from osquery
  webhook + Layer 2 scanners + git repo scanner)
- v1.x install script (`scripts/install.sh`) — superseded by
  `docker-compose up -d`
- Legacy CE v1 exports (`internal/export/csv.go`,
  `internal/export/json.go`) — superseded by CBOM
- Legacy Zeek file poller — `cipherflag serve` now relies on the
  osquery webhook and Layer 2 scanners for live evidence. The Zeek
  log poller may be re-introduced in a follow-up minor.

### Known limitations

- **Frontend.** CE v2.0 retains the v1.x demo frontend in
  `frontend/`. The production operator UI (Layer 8) is part of
  CipherFlag EE. The v1 frontend was preserved so the upgrade
  doesn't leave CE with no UI at all; it does not surface the v2
  feature set.
- **Certificate Transparency.** CT ingestion (ct_crtsh + ct_static +
  ct_certspotter + ct_multi) is deferred to v2.1 (Phase 2). The
  underlying external-source registry is also deferred.
- **No AI-enriched scanning.** Git-scan modes `triage`, `enrichment`,
  and `deep` return 409 Conflict — only `deterministic_only` is
  accepted in CE. AI-enriched modes are EE-only.
- **No per-asset risk prioritization.** Asset health reports include
  4-framework compliance grades but no risk score / blast-radius
  fan-out. Layer 4.4 is EE-only.
- **No container image scanning.** Layer 6.2 is EE-only.
- **No active network scanning.** Layer 6.3 is EE-only.
- **No PCI DSS 4.0 evaluator.** Layer 4.3 ships with 4 of 5
  compliance frameworks; PCI DSS is EE-only (private-sector
  commerce focus).
- **No Venafi / Thales CipherTrust push.** Layer 5.4 is EE-only.
- **No endpoint adapters beyond osquery.** Layer 3 (Velociraptor,
  Wazuh, Defender, SentinelOne, Tanium, Absolute, Netwrix) is
  EE-only.

### Compatibility

**v2.0.0 is a breaking change from v1.x.** There is no automated
upgrade path for v1.x deployments. The schema baseline is option (ii)
from the port design spec: existing v1.x users must reinitialize
their database. v1.x users with valuable data should export it
(`/api/v1/export/certificates` on v1) before upgrading.

### Acknowledgments

This release vendors features from CipherFlag EE under Apache 2.0.
EE source SHA is referenced in the squashed port commit. Manifest +
extraction tooling lives at `docs/superpowers/ce-port/` (in the EE
repository).

Third-party software acknowledgments: see `NOTICE`.

---

## [1.1] - 2026-03-31

### Added
- **Deployment guide** in how-to documentation covering on-prem (SPAN/TAP), AWS (VPC Traffic Mirroring with dual ENI), and Azure (vTAP + Network Watcher PCAP fallback)
- **Dual NIC architecture** documented: management NIC for SSH/web/API + capture NIC for traffic mirror target
- **Network interface selector** in Settings > Sources — dropdown populated from host interfaces with name, IP, MAC, and status
- **Network interface config API** — `GET /api/v1/config/interfaces` lists available network interfaces
- **Deployment comparison table** — traffic source, encapsulation, NIC requirements, live capture support, and cost per platform

### Changed
- How-to guide expanded from 10 to 11 sections with new Deployment Guide as section 2
- Prerequisites section updated to specify dual NIC requirement for live capture deployments
- User guide, quickstart, and README updated with deployment and network interface information

## [1.0] - 2026-03-29

### Added
- **Settings page** with tabbed layout:
  - Users: list, create, delete, toggle roles (admin only)
  - Sources: Zeek poller, Corelight, PCAP config with guardrails
  - Venafi: config management with platform/region dropdowns, masked credentials, test connection, push interval (5-1440 min)
  - System: cert counts, grade distribution, sources overview
  - Profile: view profile, change password
- **Venafi config API** — GET/PUT with validation, test connection endpoint
- **Sources config API** — GET/PUT with guardrails (poll interval 5-300s, PCAP size 1-5000MB)
- **Docker containerization** — optimized 40MB image, docker-compose with pre-built GHCR images, Docker-specific config template
- Settings link (gear icon) and profile link in nav bar

### Changed
- NewRouter accepts config pointer for live config management
- Venafi handler uses config reference instead of static values

## [0.9] - 2026-03-28

### Added
- **Authentication system** — JWT tokens in HTTP-only cookies, bcrypt password hashing, admin/viewer roles
- **Login page** (`/login`) — email + password authentication
- **First-visit admin setup** (`/setup-admin`) — creates initial admin account when no users exist
- **Auth middleware** — protects all API endpoints, backward compatible (no users = no auth)
- **User management API** — admin-only CRUD for users (list, create, update, delete)
- **Password change** — authenticated users can change their own password
- **User menu in nav** — display name, role badge (admin/viewer), logout button
- **Dashboard redesign** — command center layout with compliance gauge, grade donut, algorithm landscape, priority actions, radial PKI tree
- **Compliance report visual layer** — category donut, severity distribution, expandable category cards before raw tables

### Changed
- All API endpoints now require authentication when users exist
- Setup wizard creates first admin account
- Reports landing uses treemap for domain overview

## [0.36] - 2026-03-28

### Added
- **Reports visual dashboard** — treemap domain overview, CA concentration bars, compliance gauge, and expiry timeline replace the old card-based landing
- **Drillable analytics** across all tabs:
  - Crypto Posture: click any key algorithm, key size, signature algorithm, or TLS heatmap cell to see matching certificates
  - Expiry Forecast: click any weekly bar to drill into expiring certificates for that week
  - Deployment chart: click any domain bar to expand and see deployed certificates
- **TLS version and cipher strength filters** on certificate search API (`tls_version`, `cipher_strength`)
- **Domain report charts** — grade distribution donut, key algorithm bars, and match type breakdown
- **Reports drill-down flow** — visual dashboard → click chart element → detailed report

### Fixed
- Bar track elements absorbing click events in crypto posture (pointer-events: none)
- Drilldown panels rendering below fold (moved above strength summary, auto-scroll)
- Compliance score rounded to 1 decimal place
- CA report partial name matching (ILIKE)
- Replaced unreadable bubble chart with treemap for domain overview

## [0.35] - 2026-03-28

### Added
- **Reports page** with 4 report types: Domain Certificate, CA Authority, Crypto Compliance, Expiry Risk
- **Domain Report** — enter a domain, see all certs (exact, wildcard, SAN, subdomain matches), deployments, findings, wildcard coverage
- **CA Report** — select a CA (partial name match), see issued certs, grade distribution, crypto breakdown, chain context
- **Crypto Compliance Report** — compliance score, critical issues, remediation priorities, non-agile certs, wildcard inventory
- **Expiry Risk Report** — 30/60/90 day window, grouped by issuer and owner, ghost certs, deployments at risk
- Report toolbar with Print and Download CSV on every report
- **8 new health scoring rules** (24 total, up from 16):
  - WLD-001/002: Wildcard certificate detection (medium/high/critical)
  - EXP-006: Validity >200 days (2026 industry direction)
  - KEY-002 updated: RSA 2048 below 3072 recommendation
  - KEY-005: RSA 3072 info acknowledgment
  - AGI-001/002/003: Crypto agility (non-ACME, unusual ACME validity, FIPS readiness)

### Fixed
- Compliance score rounded to 1 decimal place
- CA report supports partial name matching (ILIKE)
- NULL raw_pem no longer crashes certificate scans

## [0.34] - 2026-03-28

### Added
- **Global search bar** — searches across certificate names, organizations, fingerprints, serial numbers, SANs, server names, and IPs from the top nav on every page
- **New search filters** — `subject_ou`, `issuer_org`, `key_algorithm`, `signature_algorithm`, `server_name` parameters on the certificate search API
- **Global search API** — `GET /api/v1/search?q=...` with four search strategies: full-text, fingerprint prefix, SAN match, and observation match
- **Comprehensive user guide** — rewritten to cover setup wizard, analytics tabs, PKI explorer, global search, Venafi Cloud/TPP, and all API endpoints

### Fixed
- NULL `raw_pem` crashes on certificate detail and list pages
- Certificate search now works with all key algorithm and signature algorithm filters

## [0.33] - 2026-03-28

### Added
- **Setup wizard** (`cipherflag setup`) — interactive CLI that walks through network interface selection, Venafi credential validation, config file generation, Docker image pull, and service startup
- **Install script** — `curl -fsSL .../install.sh | sh` one-liner that downloads the right binary for your platform
- **CI/CD pipeline** — GitHub Actions workflow builds Docker images (cipherflag + zeek) and CLI binaries (linux/darwin × amd64/arm64), publishes to GHCR, creates GitHub Release on tag push
- **Venafi Cloud support** — API key auth against `api.venafi.cloud` (US) and `api.venafi.eu` (EU) via unified `VenafiClient` interface
- **Venafi push scheduler** — background goroutine batches certificates into Discovery/Import API calls with per-cert failure tracking, exponential backoff, and dead-lettering
- **Push status API** — `GET /api/v1/venafi/status` returns pending, pushed, failed, and dead-lettered counts
- **Pre-built Docker images** — `ghcr.io/net4n6-dev/cipherflag` and `ghcr.io/net4n6-dev/cipherflag-zeek`

### Changed
- Venafi config adds `platform` (cloud/tpp), `api_key`, and `region` fields
- Dockerfile updated to Go 1.25
- README Quick Start now recommends install script + setup wizard

## [0.32] - 2026-03-28

### Added
- Venafi Cloud client with API key authentication and batch import
- Unified `VenafiClient` interface (Cloud + TPP behind same API)
- Push scheduler with exponential backoff and dead-lettering after 5 failures
- `GET /api/v1/venafi/status` endpoint
- Venafi integration guide rewritten for both Cloud and TPP

## [0.3] - 2026-03-27

### Added
- **PKI Explorer** — D3 force-directed graph replacing tree view, with detail side panel, blast radius analysis, and server-side search
- **Analytics dashboard** with 5 tabs:
  - Chain Flow (Sankey diagram colored by CA family)
  - Ownership (treemap by issuer org × subject OU + deployment bar chart)
  - Crypto Posture (key algorithm donut, key size bars, TLS × cipher heatmap, signature algorithm bars)
  - Expiry Forecast (52-week stacked bar chart by issuer)
  - Source Lineage (discovery source cards with category icons)
- Server-side aggregation for enterprise-scale graph rendering
- 10 new API endpoints for graph and analytics data
- Search dropdown with client-side and server-side fallback

## [0.1] - 2026-03-19

### Added
- Initial open-source release
- Passive TLS certificate discovery via Zeek
- PCAP upload and analysis
- Health scoring engine (16 rules, grades A+ through F)
- Certificate chain validation
- Venafi TPP export (OAuth2)
- CSV/JSON export
- Docker Compose deployment
