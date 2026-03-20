# Quick Start Guide

Deploy CipherFlag with Docker Compose in under 5 minutes.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) (20.10+)
- [Docker Compose](https://docs.docker.com/compose/install/) (v2+)

---

## Step 1: Clone the Repository

```bash
git clone https://github.com/cipherflag/cipherflag.git
cd cipherflag
```

## Step 2: Configure Environment

```bash
cp .env.example .env
```

Edit `.env` and set the following:

| Variable | Required | Description |
|----------|----------|-------------|
| `NETWORK_INTERFACE` | No | Network interface for live capture (e.g., `eth0`, `en0`). Leave empty for PCAP-only mode. |
| `POSTGRES_PASSWORD` | Yes | Database password. Change from the default for any non-local deployment. |

Venafi settings are optional and can be configured later. See [venafi-export.md](venafi-export.md).

## Step 3: Start CipherFlag

```bash
docker-compose up -d
```

This starts three containers:

| Container | Purpose |
|-----------|---------|
| `postgres` | PostgreSQL 15 database |
| `zeek` | Zeek network sensor (live capture and PCAP processing) |
| `cipherflag` | Go API server + SvelteKit frontend |

CipherFlag runs database migrations automatically on first start.

## Step 4: Open the Dashboard

Open [http://localhost:8443](http://localhost:8443) in your browser.

You will see the certificate landscape graph. If no network interface is configured, the dashboard will be empty until you upload a PCAP file.

## Step 5: Upload a Test PCAP

1. Navigate to the **Upload** page
2. Drag and drop a `.pcap` or `.pcapng` file (or use the file picker)
3. Wait for processing to complete -- you will see a summary of discovered certificates
4. Return to the dashboard to view the certificates in the landscape graph

If you do not have a PCAP file handy, you can capture one:

```bash
# Capture 60 seconds of traffic (requires sudo)
sudo tcpdump -i en0 -w test-capture.pcap -G 60 -W 1 port 443
```

## Step 6: Configure Venafi (Optional)

To push discovered certificates to Venafi TPP, edit `.env`:

```bash
VENAFI_ENABLED=true
VENAFI_BASE_URL=https://tpp.example.com/vedsdk
VENAFI_CLIENT_ID=your-client-id
VENAFI_REFRESH_TOKEN=your-refresh-token
VENAFI_FOLDER=\VED\Policy\Discovered\CipherFlag
```

Then restart CipherFlag:

```bash
docker-compose restart cipherflag
```

See [venafi-export.md](venafi-export.md) for detailed setup instructions.

---

## Verifying the Deployment

Check that all services are healthy:

```bash
docker-compose ps
```

Test the API:

```bash
curl http://localhost:8443/healthz
```

View logs:

```bash
docker-compose logs -f cipherflag
docker-compose logs -f zeek
```

---

## Stopping CipherFlag

```bash
docker-compose down
```

Database data is persisted in a Docker volume (`pg-data`). To remove all data:

```bash
docker-compose down -v
```
