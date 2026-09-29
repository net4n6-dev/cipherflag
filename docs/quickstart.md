# Quick Start Guide

Deploy CipherFlag with Docker Compose in under 5 minutes.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) (20.10+)
- [Docker Compose](https://docs.docker.com/compose/install/) (v2, the `docker compose` command)

### Network Interfaces

CipherFlag itself needs no special network access. The optional Zeek sensor
discovers certificates from network traffic in two ways:

| Mode | What you need |
|------|---------------|
| **Live capture** | A **Linux** host with a capture interface that receives mirrored or tapped traffic (SPAN port, TAP, or cloud traffic mirror), in addition to the management interface you reach the web UI (:8443) on. On Docker Desktop (macOS, Windows) the sensor sees the Docker VM's network, not the machine's. |
| **Offline PCAP** | Nothing extra, on any platform: copy capture files into `./pcap-input/`. |

See the [How-To Deployment Guide](https://cipherflag.com/howto.html#deployment) for platform-specific setup (on-prem, AWS, Azure).

---

## Step 1: Clone the Repository

```bash
git clone https://github.com/net4n6-dev/cipherflag.git
cd cipherflag
```

## Step 2: Configure Environment

```bash
cp .env.example .env
```

Docker Compose reads `.env`:

| Variable | Description |
|----------|-------------|
| `NETWORK_INTERFACE` | Interface the Zeek sensor captures on (e.g. `eth0`). Leave empty to only process PCAP files. |
| `ZEEK_PCAP_DIR` | Host directory the sensor takes PCAP files from. Default `./pcap-input`. |
| `POSTGRES_PASSWORD` | The database password (default `changeme`). If you change it, change the password in `postgres_url` under `[storage]` in `config/cipherflag.toml` to match, or CipherFlag cannot connect. |

Everything else (sources, Venafi, CBOM export) is configured in
`config/cipherflag.toml` or in the web UI's Settings. See
[configuration.md](configuration.md).

## Step 3: Start CipherFlag

Without the network sensor:

```bash
docker compose up -d
```

With the Zeek network sensor:

```bash
docker compose --profile zeek up -d
```

| Container | Purpose |
|-----------|---------|
| `postgres` | PostgreSQL 16 database |
| `cipherflag` | Go API server and web UI |
| `zeek` | Zeek network sensor, only with `--profile zeek` (live capture and PCAP processing) |

CipherFlag runs database migrations automatically on first start.

## Step 4: Open the Dashboard

Open [http://localhost:8443](http://localhost:8443) in your browser. The
first visit asks you to create the admin account. It also needs the setup
token printed in the server log:
`docker compose logs cipherflag | grep setup_token`.

The dashboard is empty until a source reports something: the Zeek sensor,
the osquery webhook, the scanners, or an enabled connector.

## Step 5: Process a Test PCAP

With the `zeek` profile running, give each capture its own job directory:

```bash
mkdir -p pcap-input/test-1
cp capture.pcap pcap-input/test-1/
```

The sensor processes it within a few seconds and marks the job done;
CipherFlag reads the job's logs on its next poll (every 30 seconds by
default), and the certificates appear on the dashboard. To check a job:

```bash
docker compose exec zeek ls -a /zeek-logs/test-1
# .done    processed; .failed if Zeek could not read the file
```

Zeek sees a server's certificate in TLS 1.2 and earlier handshakes. In
TLS 1.3 the certificate is encrypted, so those sessions yield none.

If you do not have a PCAP file handy, you can capture one:

```bash
# Capture 60 seconds of HTTPS traffic (requires sudo)
sudo tcpdump -i en0 -w test-capture.pcap -G 60 -W 1 port 443
```

## Step 6: Configure Venafi (Optional)

To push discovered certificates to Venafi (Cloud or on-prem TPP), use
**Settings > Venafi** in the web UI or `[export.venafi]` in
`config/cipherflag.toml`. Changes made in Settings take effect without a
restart. See [venafi-export.md](venafi-export.md) for details.

---

## Verifying the Deployment

Check that all services are running:

```bash
docker compose ps
```

Test the API:

```bash
curl http://localhost:8443/healthz
```

View logs:

```bash
docker compose logs -f cipherflag
docker compose logs -f zeek
```

CipherFlag logs `zeek: ingested logs` with counts after each poll that
found something, and warns once if its Zeek log directory does not exist.

---

## Stopping CipherFlag

```bash
docker compose --profile zeek down
```

Data is kept in Docker volumes (`pg-data`, `zeek-logs`). To remove all data:

```bash
docker compose --profile zeek down -v
```
