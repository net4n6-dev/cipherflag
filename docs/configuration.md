# Configuration Reference

CipherFlag is configured through two files:

- **`.env`** -- Environment variables consumed by Docker Compose
- **`config/cipherflag.toml`** -- Application configuration consumed by the CipherFlag binary

---

## Environment Variables (`.env`)

These variables are read by `docker-compose.yml` and configure the
containers. The CipherFlag binary does not read `POSTGRES_PASSWORD` or any
other Compose variable above; it takes its settings from
`config/cipherflag.toml` or Settings. The environment variables the binary
does read are listed under [Environment variables the binary reads](#environment-variables-the-binary-reads).

| Variable | Default | Description |
|----------|---------|-------------|
| `NETWORK_INTERFACE` | *(empty)* | Interface the Zeek sensor (profile `zeek`) captures on, e.g. `eth0`. Empty: the sensor only processes PCAP files. Live capture needs a Linux host. |
| `ZEEK_PCAP_DIR` | `./pcap-input` | Host directory the Zeek sensor takes PCAP files from, one subdirectory per job. |
| `ZEEK_LOG_RETENTION_HOURS` | `168` | Hours the Zeek sensor keeps rotated logs and finished job logs; `0` keeps everything. See [Zeek sensor environment](#zeek-sensor-environment). |
| `ZEEK_RETENTION_INTERVAL_SECONDS` | `3600` | Seconds between the sensor's retention passes. See [Zeek sensor environment](#zeek-sensor-environment). |
| `PCAP_SETTLE_SECONDS` | `10` | Seconds a PCAP must be unchanged before the sensor processes it. See [Zeek sensor environment](#zeek-sensor-environment). |
| `POSTGRES_PASSWORD` | `changeme` | The `postgres` container's password. If you change it, change the password in `[storage] postgres_url` in `config/cipherflag.toml` to match, or CipherFlag cannot connect. |

Venafi is configured in `[export.venafi]` or Settings > Venafi, not in
`.env`; see [venafi-export.md](venafi-export.md).

Saving from Settings rewrites only the tables Settings edits:
`[sources.zeek_file]` and `[export.venafi]`. (The sources API can also
rewrite `[sources.corelight]` and `[pcap]`, which CE does not use.)
Every other line of the file, comments included, is kept as it is. Inside a
rewritten table, comments, keys CipherFlag does not know and a trailing comment
on the `[table]` header line are not kept.

Settings writes the values it shows for the tables you save, so a table you
edited by hand after CipherFlag started is overwritten when you save that table
from Settings (the previous file is kept as `cipherflag.toml.bak`). A Sources
save only rewrites the tables the request carried.

Before it writes, CipherFlag copies the previous file to `cipherflag.toml.bak`
next to it. That copy holds only the immediately previous version and has the
same permissions as the config file. It is best effort when the file can be
replaced atomically; when the file has to be written in place (a config mounted
as a single file), a failed backup stops the save. In that single-file case the
`.bak` is written inside the container, not next to the file on the host. The
new file keeps the owner and permissions of the old one where the platform
allows it.

A read-only config file (or a read-only mount) makes saves from Settings fail;
edit the file by hand in that case. A config that is a symlink stays a
symlink and its target is updated.

---

## Application Configuration (`config/cipherflag.toml`)

### `[server]`

| Key | Default | Description |
|-----|---------|-------------|
| `listen` | `0.0.0.0:8443` | Address and port for the HTTP server. |
| `frontend_url` | `http://localhost:5174` | Allowed origin for CORS. In Docker, the frontend is served from the same origin so this is not used. For local development, set to the Vite dev server URL. |
| `jwt_secret_path` | `/var/lib/cipherflag/jwt-secret.key` | File holding the per-install key that signs session cookies. Created on first start with mode 0600. Delete it and restart to rotate the key (everyone is signed out). In Docker it lives on the `cipherflag-state` volume. Removing that volume (for example `docker compose down -v`) deletes the key, so everyone signs in again; it holds no certificate inventory (the database is a separate volume). |
| `setup_token_path` | `/var/lib/cipherflag/setup-token` | File holding the token required to create the first admin account. Created on first start with mode 0600 and printed in the log while no admin exists. Ignored once an admin exists. To regenerate it, delete the file and restart. Removing the `cipherflag-state` volume (for example `docker compose down -v`) also deletes it: if no admin exists yet, a new token is generated and logged at the next start. |

### `[storage]`

| Key | Default | Description |
|-----|---------|-------------|
| `postgres_url` | *(none)* | PostgreSQL connection string. The shipped `config/cipherflag.toml` points at the Compose `postgres` service (`postgres://cipherflag:changeme@postgres:5432/cipherflag?sslmode=disable`); keep its password in step with `POSTGRES_PASSWORD`. |
| `sqlite_path` | *(none)* | Not used by CE. The key is accepted so older files load, but PostgreSQL is the only storage backend. |

### `[analysis]`

| Key | Default | Description |
|-----|---------|-------------|
| `recheck_interval_hours` | `6` | How often to re-run health scoring on existing certificates (hours). |
| `expiry_warning_days` | *(none)* | Not used by CE. The key is accepted so older files load, but nothing reads it. |
| `scorer_enabled` | `true` | Score certificates as they are ingested and re-check them every `recheck_interval_hours`. Scoring is the only writer of health reports, so with `false` the grade donut, risk cards, findings, compliance gauge and CBOM findings stay empty. `serve` logs a warning at startup when it is off. |
| `rule_sweep_batch_size` | `1000` | Certificates re-scored per batch by the recheck sweeper. |

### `[analysis.protocol_policy]`

Not used by CE. The table (`min_tls_version`, `require_forward_secrecy`, `require_aead`, `banned_ciphers`) is still accepted so that existing configuration files load unchanged, but nothing reads the values: changing them has no effect on scoring, findings or compliance.

### `[sources.zeek_file]`

Controls the Zeek log poller, which reads a Zeek sensor's JSON logs:
`x509` logs (certificates, stored in full when the sensor logs them with
`log-certs-base64`) and `ssl` logs (TLS sessions, recorded as observations).
It reads the live logs, the files Zeek's rotation renames them to
(`x509.<time>.log`), and each PCAP job directory (`<job>/`, or `<job>--<file name>/` for a job holding several captures) once the sensor
has marked it `.done`.

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Enable Zeek log ingestion. With no sensor writing to `log_dir`, CipherFlag warns once at startup and reads nothing. |
| `log_dir` | `/var/log/zeek/current` | Directory the sensor writes its logs to. In Docker Compose, the `zeek-logs` volume is mounted here (read-only) when the `zeek` profile runs. |
| `poll_interval_seconds` | `30` | How often to check for new log lines (seconds). |
| `network_interface` | *(empty)* | Shown and saved by Settings > Sources, but not used: the Compose sensor captures on `NETWORK_INTERFACE`. |

The poller's position in each file is kept in the `ingestion_state` table,
so a restart resumes where it left off.

### Zeek sensor environment

The Compose `zeek` service reads these variables (set them in `.env`):

| Variable | Default | Description |
|----------|---------|-------------|
| `ZEEK_LOG_RETENTION_HOURS` | `168` | Once an hour the sensor deletes rotated logs of every Zeek log type (`<type>.<YYYY-MM-DD-HH-MM-SS>.log` and `.log.gz`) and finished job directories (`.done` or `.failed`) older than this many hours. `0` keeps everything. A value that is not a whole number between 0 and 999999 logs a warning and turns retention off. |
| `ZEEK_RETENTION_INTERVAL_SECONDS` | `3600` | Pause between retention passes (1 to 999999; anything else logs a warning and uses 3600). |
| `PCAP_SETTLE_SECONDS` | `10` | A capture is processed only after its file has been unchanged this long, so a `cp` in progress is not run truncated. A value that is not a whole number of at most 9 digits logs a warning and uses 10. |

Retention never touches live logs, a job directory still in progress (no
`.done` or `.failed`), or a finished one whose capture is not recorded as
processed and is still in `pcap-input`. The sensor records each processed
capture in `/zeek-logs/.state/<job>/<file name>`; deleting a job's log
directory does not make the capture run again, and a marker is pruned only
once its capture is gone from `pcap-input` and the marker is older than the
window (markers are not pruned when retention is 0, nor while `pcap-input`
holds no captures at all). The CipherFlag container mounts the logs volume read-only, so only
the sensor prunes it. CipherFlag ingests new logs within its poll interval
(30 seconds by default), so the default window is far longer than needed
unless CipherFlag is stopped: logs older than the window are removed even if
CipherFlag was down and never read them.

Sizing: 168 hours keeps every rotated log type (conn, dns, http and the
rest), not just x509 and ssl, so on a busy interface give the `zeek-logs`
volume enough space or use a shorter window.

### `[sources.corelight]`

Not used by CE. The table (`enabled`, `api_url`, `api_token`) is still accepted so that existing configuration files load unchanged, but CE has no Corelight poller and ingests nothing from it.

### Endpoint sources

Each of these runs a poller in `cipherflag serve` only when its `enabled` is
`true`. All are off by default and are not in the shipped `config/cipherflag.toml`;
add the table to enable one. Secrets (`client_secret`, `api_token`, `password`,
`secret_key`) are plain values in the file; they are not read from the
environment. Poll intervals are seconds; a value of `0` or unset uses the
default shown.

#### `[sources.defender]`

Microsoft Defender for Endpoint, read through the Advanced Hunting API.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Start the Defender poller. |
| `tenant_id` | string | *(empty)* | Azure AD tenant; the OAuth token URL is built from it. Required: empty stops `serve` at startup. |
| `client_id` | string | *(empty)* | App registration client ID. Required: empty stops `serve` at startup. |
| `client_secret` | string | *(empty)* | App registration client secret. |
| `api_base_url` | string | `https://api.security.microsoft.com` | API base URL; set it for a sovereign cloud. |
| `poll_interval_seconds` | int | `21600` (6 hours) | Time between polls. |
| `http_timeout_seconds` | int | `60` | HTTP request timeout. |

#### `[sources.sentinelone]`

SentinelOne. Two modes run independently, each with its own `enabled` (both
`false` by default, so setting only the top-level `enabled` polls nothing).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Start the SentinelOne poller. |
| `api_token` | string | *(empty)* | SentinelOne API token. |
| `console_url` | string | *(empty)* | Management console URL, e.g. `https://mgmt.sentinelone.net`. |
| `http_timeout_seconds` | int | `60` | HTTP request timeout. |
| `app_inventory.enabled` | bool | `false` | Poll the installed-applications inventory for cryptographic libraries. |
| `app_inventory.poll_interval_seconds` | int | `3600` (1 hour) | Time between inventory polls. |
| `rso.enabled` | bool | `false` | Run the discovery scripts through remote script execution. |
| `rso.trigger` | string | `scheduled` | Only `scheduled` is supported; with `rso.enabled`, anything else stops `serve` at startup. |
| `rso.target` | string | `all` | Only `all` is supported; with `rso.enabled`, anything else stops `serve` at startup. |
| `rso.poll_interval_seconds` | int | `86400` (24 hours) | Time between script runs. |
| `rso.cert_script_id`, `rso.ssh_keys_script_id`, `rso.libraries_script_id`, `rso.config_files_script_id`, `rso.cert_files_script_id` | string | *(empty)* | IDs of the uploaded SentinelOne scripts for each discovery kind (certificates, SSH keys, libraries, config files, certificate files). |

#### `[sources.tanium]`

Tanium, pulled through GraphQL.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Start the Tanium poller. |
| `api_token` | string | *(empty)* | Tanium API token. |
| `console_url` | string | *(empty)* | API URL, e.g. `https://customer-api.cloud.tanium.com`. |
| `poll_interval_seconds` | int | `3600` (1 hour) | Time between polls. |
| `http_timeout_seconds` | int | `60` | HTTP request timeout. |
| `page_size` | int | `500` | Page size (the GraphQL `first` argument). |

#### `[sources.absolute]`

Absolute Software. Two modes run independently, each with its own `enabled`
(both `false` by default).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Start the Absolute poller. |
| `token_id` | string | *(empty)* | API token ID. |
| `secret_key` | string | *(empty)* | API secret key. |
| `console_url` | string | *(empty)* | API URL, e.g. `https://api.absolute.com`. |
| `http_timeout_seconds` | int | `60` | HTTP request timeout. |
| `inventory.enabled` | bool | `false` | Poll the installed-applications inventory for cryptographic libraries. |
| `inventory.poll_interval_seconds` | int | `3600` (1 hour) | Time between inventory polls. |
| `reach.enabled` | bool | `false` | Run the discovery scripts through Absolute Reach. |
| `reach.trigger` | string | `scheduled` | Only `scheduled` is supported; with `reach.enabled`, anything else stops `serve` at startup. |
| `reach.target` | string | `all` | Only `all` is supported; with `reach.enabled`, anything else stops `serve` at startup. |
| `reach.poll_interval_seconds` | int | `86400` (24 hours) | Time between script runs. |
| `reach.cert_script_id`, `reach.ssh_keys_script_id`, `reach.libraries_script_id`, `reach.configs_script_id` | string | *(empty)* | IDs of the Absolute scripts for each discovery kind (certificates, SSH keys, libraries, configs). |

#### `[sources.netwrix]`

Netwrix Auditor, reading the AD CS change feed.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Start the Netwrix poller. |
| `base_url` | string | *(empty)* | Netwrix Auditor URL. Required: an empty value stops `serve` at startup. |
| `username` | string | *(empty)* | Login name. Required with `password`. |
| `password` | string | *(empty)* | Login password. Required with `username`. |
| `insecure_skip_tls` | bool | `false` | Skip TLS certificate verification (a warning is logged). For self-signed test servers only. |
| `poll_interval_seconds` | int | `300` (5 minutes) | Time between polls. |
| `http_timeout_seconds` | int | `60` | HTTP request timeout. |

### Certificate Transparency sources

Four pollers read public CT data for domains you name. Each is an array of
tables (`[[sources.ct_crtsh.domains]]` and so on), is off unless at least one
entry has `enabled = true`, and polls every hour (not configurable). An
enabled entry that fails validation stops `serve` at startup with an error
naming the domain. A domain must be lowercase, for example `example.com`.

#### `[[sources.ct_crtsh.domains]]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Poll this domain. |
| `domain` | string | *(empty)* | Domain to look up in crt.sh. Required. |
| `include_subdomains` | bool | `false` | Also fetch certificates for its subdomains. |

#### `[[sources.ct_static.domains]]`

Reads a Static CT API (Sunlight) log directly. `log_url`, `origin` and
`public_key_pem` come from the log's entry in Google's `log_list.json`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Poll this entry. |
| `domain` | string | *(empty)* | Domain to collect certificates for. Required. |
| `log_url` | string | *(empty)* | The log's monitoring URL, where the checkpoint and tiles are read. Required; must be `https` and end with `/`. |
| `origin` | string | *(empty)* | The log's submission URL without `https://` and without the trailing `/`; it is the checkpoint's origin line and signature key name. Required. |
| `public_key_pem` | string | *(empty)* | The log's public key as a `PUBLIC KEY` PEM block (ECDSA P-256 or Ed25519). Required. |

#### `[[sources.ct_certspotter.domains]]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Poll this domain. |
| `domain` | string | *(empty)* | Domain to look up in SSLMate CertSpotter. Required. |
| `include_subdomains` | bool | `false` | Also fetch certificates for its subdomains. |
| `api_token` | string | *(empty)* | CertSpotter API token, sent as a bearer token when set. |
| `requests_per_hour` | int | `50` | Client-side request limit; `0` uses the default. Must be 0 to 100000. |

#### `[[sources.ct_multi.groups]]`

Queries several CT providers for one domain and combines the results.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Poll this group. |
| `domain` | string | *(empty)* | Domain shared by all children. Required. |
| `children` | array of tables | *(none)* | `[[sources.ct_multi.groups.children]]`: at least 2 per group, each holding exactly one sub-table, `crtsh`, `static` or `certspotter`. |

A child's `static` table takes `log_url`, `origin` and `public_key_pem` as
above (plus an optional `domain`, which must equal the group's). A child's
`certspotter` table takes `api_token` and `requests_per_hour` as above (plus
an optional `domain`, which must equal the group's). A child's `crtsh` table
takes no keys.

### `[export.venafi]`

Controls automated certificate push to Venafi (Cloud or TPP).

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `false` | Enable Venafi export. |
| `platform` | `cloud` | Venafi platform: `cloud` (TLS Protect Cloud SaaS) or `tpp` (on-prem TPP). |
| `api_key` | *(empty)* | Venafi Cloud API key. Required when `platform = "cloud"`. |
| `region` | `us` | Venafi Cloud region: `us` (`api.venafi.cloud`) or `eu` (`api.venafi.eu`). |
| `base_url` | *(empty)* | Venafi TPP server URL (e.g., `https://tpp.example.com`). Required when `platform = "tpp"`. |
| `client_id` | *(empty)* | TPP OAuth2 client ID. Required when `platform = "tpp"`. |
| `refresh_token` | *(empty)* | TPP OAuth2 refresh token. Required when `platform = "tpp"`. |
| `folder` | `\VED\Policy\Discovered\CipherFlag` | Policy folder in Venafi TPP where certificates are imported. TPP only. |
| `push_interval_minutes` | `60` | How often to push new/updated certificates (minutes). |

### `[cbom]`

Pushing CBOMs to sinks. `enabled` turns on the push runtime that `serve`
builds at startup; signing is configured separately under `[cbom.signing]`
below.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Build the push runtime. With `false`, no scope is pushed anywhere. |
| `output_dir` | string | *(empty)* | Value of `{output_dir}` in a file sink's `path_template`. |
| `push_interval` | duration | `24h` | How often every scope that has sinks is generated and pushed. A duration string such as `24h`. |
| `event_push_enabled` | bool | `false` | Also push when an asset is scored, for the scopes whose hosts it belongs to, at most once per `min_emit_interval`. Needs `[analysis] scorer_enabled`. |
| `min_emit_interval` | duration | `5m` | With `event_push_enabled`, how often scopes with pending changes are pushed. |
| `signing` | table | | See [CBOM signing](#cbom-signing-cbomsigning). |
| `scopes` | array of tables | *(none)* | `[[cbom.scopes]]`, below. |

Each `[[cbom.scopes]]` entry is one named group of hosts:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | string | *(none)* | Required, unique, letters, digits, `.`, `_` and `-` only. |
| `host_patterns` | array of strings | *(none)* | Hostname patterns, matched case-insensitively against the canonical hostname; `*` matches any run of characters and `?` one character. |
| `host_ids` | array of strings | *(none)* | Host UUIDs. Combined with the hosts `host_patterns` match. |
| `asset_types` | array of strings | *(none)* | Limit to `certificate`, `ssh_key`, `crypto_library`, `crypto_protocol` and `crypto_config`; an unknown value is an error. Empty keeps all types. |
| `min_risk_score` | int | `0` | Minimum risk score for included assets (`0` is no floor). |
| `sinks` | array of tables | *(none)* | `[[cbom.scopes.sinks]]`, below. A scope with no sinks is never pushed. |

Each `[[cbom.scopes.sinks]]` entry has the keys below and exactly one
sub-table named after its `type` (`[cbom.scopes.sinks.http]` and so on). When
`enabled = true`, an invalid scope or sink stops every command at config load.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `type` | string | *(none)* | Required: `http`, `file`, `s3`, `splunk` or `syslog`. |
| `granularity` | string | `cbom` for `http`, `file` and `s3`; `asset` for `splunk` and `syslog` | What is sent: `cbom`, `asset` or `finding`. `cbom` is rejected for `splunk` and `syslog`. |
| `timeout` | duration | `30s` | Request timeout for the `http` and `splunk` sinks, connection timeout for `syslog`. |
| `retries` | int | `3` | Retries after a failed request, for the `http` and `splunk` sinks. |

Sub-table keys:

| Sink | Key | Description |
|------|-----|-------------|
| `http` | `url` | Endpoint the payload is POSTed to. Required. |
| `http` | `auth` | `none` (or empty), `bearer` or `header`. |
| `http` | `auth_ref` | Name of an environment variable holding the secret for `bearer` or `header`. |
| `http` | `auth_header_name` | Header that carries the secret when `auth = "header"`. Required then. |
| `file` | `path_template` | Output path; `{output_dir}`, `{scope}` and `{timestamp}` are replaced. Required. |
| `s3` | `bucket`, `region` | Bucket and region. Both required. |
| `s3` | `prefix` | Key prefix; `{scope}`, `{date}` and `{timestamp}` are replaced. |
| `s3` | `endpoint_url` | Endpoint for an S3-compatible store (MinIO, LocalStack, GCS). |
| `s3` | `content_encoding` | Empty or `gzip`. |
| `splunk` | `url` | HTTP Event Collector URL. Required. |
| `splunk` | `token_ref` | Name of an environment variable holding the HEC token. Required. |
| `splunk` | `index`, `source`, `sourcetype` | Sent with each event. |
| `splunk` | `batch_size` | Events per request; `0` uses 100. Negative is an error. |
| `splunk` | `tls_insecure` | Skip server certificate verification. |
| `syslog` | `protocol`, `address`, `format` | See the next section. |
| `syslog` | `facility` | Syslog facility, 0 to 23; `0` uses 16 (local0). |

### CBOM syslog sink (`[cbom.scopes.sinks.syslog]`)

A CBOM scope can forward per-asset or per-finding events to a syslog receiver:

```toml
[[cbom.scopes]]
name = "prod"

[[cbom.scopes.sinks]]
type = "syslog"

[cbom.scopes.sinks.syslog]
protocol = "tls"                # "udp" | "tcp" | "tls"
address  = "siem.example.com:6514"
format   = "rfc5424"            # "rfc5424" | "cef"
ca_file  = "/etc/cipherflag/siem-ca.pem"   # optional; system roots if unset
# cert_file = "/etc/cipherflag/client.pem" # optional client certificate (mutual TLS)
# key_file  = "/etc/cipherflag/client.key" # required if, and only if, cert_file is set
# tls_insecure = false          # true skips server certificate verification
```

For `protocol = "tls"`:

- Without `cert_file`/`key_file` the sink does server-authenticated TLS only. Set both for mutual TLS; setting only one is a configuration error.
- The receiver's certificate is verified against `ca_file` (or the system roots). `tls_insecure = true` disables that check, which exposes the feed to interception; use it only for lab receivers. A warning is logged when it is on.

### CBOM signing (`[cbom.signing]`)

Signing emitted CBOMs with Ed25519 is opt-in:

```toml
[cbom.signing]
enabled = true
signer  = "file"                          # "file" | "env"
path    = "/etc/cipherflag/signing.key"   # for signer = "file"
env_var = "CIPHERFLAG_SIGNING_KEY"        # for signer = "env"
```

Generate a keypair with:

    cipherflag generate-signing-key --out /etc/cipherflag/signing

This writes `signing.key` (private, mode 0600) and `signing.pub` (public) and prints the public key's SHA-256 fingerprint. Record the fingerprint out of band so verifiers can check it. With signing enabled, `cipherflag serve` logs the same fingerprint at startup.

#### Key formats

The signer (`signer = "file"`, and `signer = "env"` with a PEM value) reads a `PRIVATE KEY` (or `ED25519 PRIVATE KEY`) PEM block; `verify-cbom --trusted-key` reads a `PUBLIC KEY` (or `ED25519 PUBLIC KEY`) PEM block. Each accepts two encodings of an Ed25519 key:

- **Standard**: a PKCS#8 private key and an SPKI public key, as written by `cipherflag generate-signing-key` (2.3.0 and later), OpenSSL, an HSM or a cloud KMS export, and CipherFlag EE 4.11 and later. To make the pair with OpenSSL instead:

      (umask 077; openssl genpkey -algorithm ed25519 -out /etc/cipherflag/signing.key)
      openssl pkey -in /etc/cipherflag/signing.key -pubout -out /etc/cipherflag/signing.pub

  The subshell's `umask 077` keeps the private key at mode 0600. OpenSSL prints no fingerprint; the one CipherFlag logs and prints is the SHA-256 of the raw 32-byte public key, which this computes:

      openssl pkey -pubin -in /etc/cipherflag/signing.pub -outform DER | tail -c 32 | sha256sum

- **Raw**: Go's 64-byte private key and 32-byte public key, as written by `cipherflag generate-signing-key` before 2.3.0. These files carry the same PEM labels as the standard encoding but are not PKCS#8 or SPKI, so other tools (OpenSSL included) cannot read them. They keep working; there is no need to regenerate a key only to change its encoding, and its fingerprint is unchanged.

With `signer = "env"`, a value that does not start with `-----BEGIN` is read as standard base64 of either encoding's key bytes (PKCS#8 DER or the raw 64 bytes). Other key types (RSA, ECDSA) and a raw private key whose public half does not match its seed are rejected. With signing enabled, a key that cannot be loaded stops `cipherflag serve` at startup, before it connects to the database, with one `FTL` line naming the key file or environment variable and the reason.

CipherFlag CE before 2.3.0 reads only the raw encoding. Its `verify-cbom` misreads a standard `.pub` (from 2.3.0's `generate-signing-key`, OpenSSL or EE 4.11) and reports a trust mismatch for a genuine BOM, and its signer rejects a standard `.key`. Sign and verify with 2.3.0 or later.

#### Verifying a signed CBOM

    cipherflag verify-cbom --bom /path/to/bom.json --trusted-key /etc/cipherflag/signing.pub

Exit codes:

- `0`: the signature is valid and the embedded key matches `--trusted-key`.
- `1`: the signature is valid but the embedded key does not match: someone else signed this BOM. Not necessarily a forgery, but not from the expected signer.
- `2`: the signature is invalid: the BOM was changed after signing, or its `signature` block is absent or malformed, or the BOM is not valid JSON or has no RFC 8785 canonical form.
- `3`: could not verify; nothing was checked. A usage error (for example a missing `--bom`, an unknown flag or an extra argument), `-h`, an unreadable BOM file, or an unloadable `--trusted-key`. The reason is printed on stderr. Treat `3` as a failure to run, never as a verdict.

Without `--trusted-key`, the exit codes are `0` (valid), `2` (invalid) or `3` (could not verify); the `1` case does not apply.

Before 2.3.0, `verify-cbom` had no code `3`: it exited `0` for `-h`, `1` for an unloadable `--trusted-key` and `2` for an unreadable BOM.

### `[intake.dedup]`

An in-memory cache that skips writing an observation identical to one seen
recently, shared by the pollers. Off by default.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Turn the cache on. With `false`, every observation is written. |
| `ttl_seconds` | int | `3600` | How long an entry suppresses repeats. The value actually used is capped at half of the shortest `[attrition]` threshold. |
| `max_entries` | int | `500000` | Cache size. A value below `1000` is raised to `1000`. |

### `[attrition]`

In CE these keys have one effect: the shortest of them (the `network_*` values
as days, the `cycle_*` values as that many poll intervals of the Zeek log
poller, the only source counted, and skipped when it is off) caps `[intake.dedup] ttl_seconds` at half that time. CE does
not run a job that marks assets stale or removed from them.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `check_interval_minutes` | int | `60` | Not used by CE. |
| `cycle_stale_threshold` | int | `3` | Poll cycles without a sighting before an asset counts as stale; used only for the dedup cap. |
| `cycle_removed_threshold` | int | `7` | Poll cycles without a sighting before an asset counts as removed; used only for the dedup cap. |
| `network_stale_days` | int | `7` | Days without a sighting before a network-observed asset counts as stale; used only for the dedup cap. |
| `network_removed_days` | int | `30` | Days without a sighting before a network-observed asset counts as removed; used only for the dedup cap. |

### `[scanners]`

Read only by `cipherflag scan-truststore`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `jvm_keystore_passwords` | array of strings | `["changeit"]` | Passwords tried in order when opening a JVM `cacerts` (JKS) keystore. Add yours if your hosts changed the default. |

### `[pcap]`

Not used by CE. PCAP upload is an Enterprise Edition feature; CE has no PCAP upload page or API, and processes PCAP files through the Zeek sensor instead (copy them into `./pcap-input/<job>/`; see `[sources.zeek_file]`). The section (`max_file_size_mb`, `retention_hours`, `input_dir`) is still accepted so that existing configuration files load unchanged, and the settings API still reports it, but nothing in CE reads the values.

---

## Overriding Configuration

### Environment variables the binary reads

| Variable | Read when | Description |
|----------|-----------|-------------|
| `CIPHERFLAG_CONFIG` | every command | Path of the config file; default `config/cipherflag.toml`. Compose sets it to `/app/config/cipherflag.toml`. |
| the name in `[cbom.signing] env_var` | `signer = "env"` | Holds the CBOM signing key (PEM or base64). See [CBOM signing](#cbom-signing-cbomsigning). |
| the name in a CBOM http sink's `auth_ref` | `auth = "bearer"` or `"header"` | Holds the secret sent to the endpoint. An unset variable sends an empty value. |
| the name in a CBOM Splunk sink's `token_ref` | Splunk sink | Holds the HEC token. An empty value logs a warning and is sent as is. |
| `NODE_EXTRA_CA_CERTS` | `cipherflag scan-truststore` | If set, the trust bundle file it names is included in the scan. |
| `JAVA_HOME` | `cipherflag scan-truststore` | If set, `$JAVA_HOME/lib/security/cacerts` is included in the scan. |

Nothing else in the binary is configured from the environment: database
credentials, source credentials and all other settings come from
`config/cipherflag.toml`. Under Compose, set the sink and signing-key
variables in the `cipherflag` service's `environment`; the binary does not
read `.env` itself.

### Using another config file

The config file path can be overridden with the `CIPHERFLAG_CONFIG` environment variable:

```bash
CIPHERFLAG_CONFIG=/path/to/custom.toml ./bin/cipherflag serve
```

### Docker

`docker-compose.yml` bind-mounts the host's `./config` directory at
`/app/config` in the `cipherflag` container. To change the configuration, edit
`./config/cipherflag.toml` on the host and restart the container
(`docker compose restart cipherflag`); CipherFlag reads the file at startup.
No override file is needed.

Settings saves write to that same file, so keep the mount writable: do not
add `:ro` to it, and do not replace it with a read-only mount of another file.
A read-only config makes saves from Settings fail with a "not writable"
error; the file must then be edited by hand.
