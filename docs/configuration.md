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
| `VENAFI_ENABLED` | `false` | Enable automated push to Venafi TPP. |
| `VENAFI_BASE_URL` | *(empty)* | Venafi TPP server URL (e.g., `https://tpp.example.com/vedsdk`). |
| `VENAFI_CLIENT_ID` | *(empty)* | Venafi OAuth2 client ID. |
| `VENAFI_REFRESH_TOKEN` | *(empty)* | Venafi OAuth2 refresh token. |
| `VENAFI_FOLDER` | `\VED\Policy\Discovered\CipherFlag` | Target policy folder in Venafi for imported certificates. |

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

Controls automated certificate push to Venafi TPP.

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `false` | Enable Venafi TPP export. |
| `base_url` | *(empty)* | Venafi TPP server URL (e.g., `https://tpp.example.com/vedsdk`). |
| `client_id` | *(empty)* | OAuth2 client ID registered in Venafi. |
| `refresh_token` | *(empty)* | OAuth2 refresh token for token lifecycle management. |
| `folder` | `\VED\Policy\Discovered\CipherFlag` | Policy folder path in Venafi where certificates are imported. |
| `push_interval_minutes` | `60` | How often to push new/updated certificates to Venafi (minutes). |

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
