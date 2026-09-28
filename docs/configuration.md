# Configuration Reference

CipherFlag is configured through two files:

- **`.env`** -- Environment variables consumed by Docker Compose
- **`config/cipherflag.toml`** -- Application configuration consumed by the CipherFlag binary

---

## Environment Variables (`.env`)

These variables are used by `docker-compose.yml` and passed to containers at runtime.

| Variable | Default | Description |
|----------|---------|-------------|
| `NETWORK_INTERFACE` | *(empty)* | Network interface for Zeek live capture (e.g., `eth0`, `en0`). Leave empty for PCAP-only mode. |
| `POSTGRES_PASSWORD` | `changeme` | PostgreSQL password. Change for non-local deployments. |
| `VENAFI_ENABLED` | `false` | Enable automated push to Venafi. |
| `VENAFI_PLATFORM` | `cloud` | Venafi platform: `cloud` (TLS Protect Cloud) or `tpp` (on-prem TPP). |
| `VENAFI_API_KEY` | *(empty)* | Venafi Cloud API key (Cloud only). |
| `VENAFI_REGION` | `us` | Venafi Cloud region: `us` or `eu` (Cloud only). |
| `VENAFI_BASE_URL` | *(empty)* | Venafi TPP server URL, e.g., `https://tpp.example.com` (TPP only). |
| `VENAFI_CLIENT_ID` | *(empty)* | Venafi TPP OAuth2 client ID (TPP only). |
| `VENAFI_REFRESH_TOKEN` | *(empty)* | Venafi TPP OAuth2 refresh token (TPP only). |
| `VENAFI_FOLDER` | `\VED\Policy\Discovered\CipherFlag` | Target policy folder (TPP only). |

---

## Application Configuration (`config/cipherflag.toml`)

### `[server]`

| Key | Default | Description |
|-----|---------|-------------|
| `listen` | `0.0.0.0:8443` | Address and port for the HTTP server. |
| `frontend_url` | `http://localhost:5174` | Allowed origin for CORS. In Docker, the frontend is served from the same origin so this is not used. For local development, set to the Vite dev server URL. |

### `[storage]`

| Key | Default | Description |
|-----|---------|-------------|
| `postgres_url` | `postgres://cipherflag:dev@localhost:5432/cipherflag?sslmode=disable` | PostgreSQL connection string. In Docker, this is overridden to point to the `postgres` service. |

### `[analysis]`

| Key | Default | Description |
|-----|---------|-------------|
| `recheck_interval_hours` | `6` | How often to re-run health scoring on existing certificates (hours). |
| `expiry_warning_days` | `[30, 60, 90, 180]` | Thresholds for expiration warnings in the dashboard. |

### `[analysis.protocol_policy]`

Controls the protocol compliance checks applied to TLS observations.

| Key | Default | Description |
|-----|---------|-------------|
| `min_tls_version` | `1.2` | Minimum acceptable TLS version. Observations below this version are flagged. |
| `require_forward_secrecy` | `true` | Flag cipher suites that do not provide forward secrecy. |
| `require_aead` | `true` | Flag cipher suites that do not use AEAD encryption (e.g., CBC-mode ciphers). |
| `banned_ciphers` | `["RC4", "DES", "3DES", "NULL", "EXPORT"]` | Cipher suite substrings that are always flagged as insecure. |

### `[sources.zeek_file]`

Controls the Zeek log file poller.

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Enable Zeek log file ingestion. |
| `log_dir` | `/var/log/zeek/current` | Directory to watch for Zeek log files. In Docker, this is the `zeek-logs` shared volume. |
| `poll_interval_seconds` | `30` | How often to check for new log entries (seconds). |

### `[sources.corelight]`

Corelight sensor integration (placeholder for v1.1).

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `false` | Enable Corelight sensor API ingestion. |
| `api_url` | *(empty)* | Corelight sensor REST API URL. |
| `api_token` | *(empty)* | Corelight API authentication token. |

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

### `[pcap]`

Controls PCAP upload and processing.

| Key | Default | Description |
|-----|---------|-------------|
| `max_file_size_mb` | `500` | Maximum PCAP file size for uploads (megabytes). |
| `retention_hours` | `24` | How long processed PCAP files are retained before cleanup (hours). |
| `input_dir` | `/pcap-input` | Directory where uploaded PCAPs are written for Zeek processing. In Docker, this is the `pcap-input` shared volume. |

---

## Overriding Configuration

The config file path can be overridden with the `CIPHERFLAG_CONFIG` environment variable:

```bash
CIPHERFLAG_CONFIG=/path/to/custom.toml ./bin/cipherflag serve
```

In Docker, the config is baked into the image at `/app/config/cipherflag.toml`. To override, mount a custom config:

```yaml
# docker-compose.override.yml
services:
  cipherflag:
    volumes:
      - ./my-config.toml:/app/config/cipherflag.toml:ro
```
