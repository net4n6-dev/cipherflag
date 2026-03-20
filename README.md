# CipherFlag

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

CipherFlag is an open-source certificate inventory tool that uses [Zeek](https://zeek.org/) to passively discover TLS certificates from network traffic. It scores certificate health against industry standards (16 rules, grades A+ through F), visualizes PKI relationships with Cytoscape.js, and exports discovered inventory to [Venafi TPP](https://venafi.com/) or as CSV/JSON. Deploy with a single `docker-compose up` command.

---

## Quick Start

```bash
git clone https://github.com/cipherflag/cipherflag.git
cd cipherflag
cp .env.example .env          # edit to set NETWORK_INTERFACE for live capture
docker-compose up -d
```

Open [http://localhost:8443](http://localhost:8443) to access the dashboard.

---

## Features

- **Passive network discovery** -- Zeek monitors a network interface (SPAN port or tap) and extracts TLS certificates without disrupting traffic
- **PCAP upload** -- Upload .pcap/.pcapng files for offline certificate analysis with drag-and-drop UI
- **Health scoring** -- 16 rules covering expiration, key strength, signature algorithm, chain trust, revocation, and CT compliance. Grades from A+ (95+) to F
- **Venafi TPP export** -- Automated push of discovered certificates to Venafi Trust Protection Platform via REST API with OAuth2 token refresh
- **CSV/JSON export** -- Manual download of certificate inventory in formats compatible with Venafi bulk import
- **PKI visualization** -- Interactive Cytoscape.js graph showing certificate chains, issuers, and endpoint relationships

---

## Configuration

CipherFlag uses two configuration layers:

| File | Purpose |
|------|---------|
| `.env` | Docker Compose environment variables (network interface, database password, Venafi credentials) |
| `config/cipherflag.toml` | Application configuration (analysis rules, polling intervals, export settings) |

See [docs/configuration.md](docs/configuration.md) for a complete reference of all options.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Quick Start Guide](docs/quickstart.md) | Step-by-step Docker Compose deployment |
| [Configuration Reference](docs/configuration.md) | All config options for `.env` and `cipherflag.toml` |
| [Venafi Export Guide](docs/venafi-export.md) | Setting up Venafi TPP integration |
| [Architecture](docs/architecture.md) | System design, data flow, and data model |

---

## Project Structure

```
cipherflag/
├── cmd/cipherflag/          # CLI entrypoint (serve, migrate, seed)
├── config/                  # Runtime configuration (cipherflag.toml)
├── docker/zeek/             # Zeek sensor container
├── frontend/                # SvelteKit + Cytoscape.js UI
├── internal/
│   ├── analysis/            # Health scoring engine (16 rules)
│   ├── api/                 # HTTP server, handlers, middleware
│   ├── certparse/           # X.509 PEM/DER parser
│   ├── config/              # TOML config loader
│   ├── export/              # CSV, JSON, and Venafi TPP export
│   ├── ingest/              # Zeek log poller and PCAP job manager
│   ├── model/               # Domain types
│   └── store/               # PostgreSQL store and migrations
├── docker-compose.yml       # 3-service deployment (Zeek + CipherFlag + PostgreSQL)
└── docs/                    # Documentation
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code structure, and PR process.

---

## Security Notice

CipherFlag v1 does not include built-in authentication. The API exposes PCAP upload and certificate export capabilities. Protect your deployment with one of:

- Network segmentation (management VLAN only)
- Reverse proxy with authentication (nginx + basic auth, OAuth2 proxy)
- Host firewall rules restricting access to port 8443

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for the full text.
