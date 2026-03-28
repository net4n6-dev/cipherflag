# Venafi Cloud Client

Adds a Venafi Cloud (TLS Protect Cloud / CyberArk Certificate Manager SaaS) client alongside the existing TPP client. Venafi Cloud uses API key authentication and different endpoints from on-prem TPP.

## Problem

The existing Venafi integration targets on-prem TPP only (OAuth2 + `/vedsdk/` endpoints). Most new Venafi customers use the cloud SaaS platform, which has a different auth model (API key) and different API surface (`api.venafi.cloud`).

## Architecture

### Unified Venafi Interface

A Go interface that both TPP and Cloud clients implement, so the push scheduler doesn't care which platform it's talking to:

```go
type VenafiClient interface {
    ImportCertificates(ctx context.Context, certs []CertImport) (*ImportResult, error)
    ValidateConnection(ctx context.Context) error
}
```

The existing TPP `Client` and the new Cloud `CloudClient` both implement this interface. The pusher accepts `VenafiClient` instead of `*Client`.

### Venafi Cloud API

**Base URL:** `https://api.venafi.cloud` (US) or `https://api.venafi.eu` (EU)

**Authentication:** API key in header:
```
tppl-api-key: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
Content-Type: application/json
```

**Certificate Import Endpoint:**

`POST /outagedetection/v1/certificates`

Request:
```json
{
  "certificates": [
    {
      "certificate": "MIIEKDCCAxCg...",
      "apiClientInformation": {
        "type": "CipherFlag",
        "identifier": "10.20.30.40"
      }
    }
  ]
}
```

- `certificate`: Base64-encoded PEM (strip headers/footers/newlines)
- `apiClientInformation`: Optional metadata identifying the import source
- Supports batch import (multiple certs in one call)
- No private key needed — CipherFlag only discovers certs from network traffic

Response (HTTP 201):
```json
{
  "certificateInformations": [
    {
      "id": "9ce02b90-...",
      "fingerprint": "E63129B8BA38...",
      "certificateSource": "USER_IMPORTED"
    }
  ],
  "statistics": {
    "imported": 3,
    "existed": 1,
    "ignored": 0,
    "failed": 0
  }
}
```

The `statistics` field tells us exactly what happened — no need for our own deduplication logic. Venafi Cloud handles it.

**Connection Validation:**

`GET /outagedetection/v1/certificates?limit=1`

A lightweight call to verify the API key works. Returns 200 if valid, 401 if not.

### Configuration Changes

The existing `[export.venafi]` config section needs a `platform` field to distinguish TPP vs Cloud:

```toml
[export.venafi]
enabled = true
platform = "cloud"              # "cloud" or "tpp"

# Cloud settings (when platform = "cloud")
api_key = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
region = "us"                   # "us" or "eu"

# TPP settings (when platform = "tpp") — existing fields
base_url = ""
client_id = ""
refresh_token = ""

# Common settings
folder = "\\VED\\Policy\\Discovered\\CipherFlag"   # TPP only
push_interval_minutes = 60
```

Environment variable overrides:
- `VENAFI_PLATFORM` → `cloud` or `tpp`
- `VENAFI_API_KEY` → Cloud API key
- `VENAFI_REGION` → `us` or `eu`

### Unified Import Types

Shared types used by both clients:

```go
// CertImport holds a certificate and optional endpoint metadata for import.
type CertImport struct {
    PEM         string
    Fingerprint string
    ServerName  string
    ServerIP    string
    ServerPort  int
    TLSVersion  string
}

// ImportResult holds the outcome of a batch import operation.
type ImportResult struct {
    Imported int
    Updated  int
    Existed  int
    Failed   int
    Warnings []string
}
```

### Cloud Client Implementation

```go
type CloudClient struct {
    baseURL    string
    apiKey     string
    httpClient *http.Client
}

func NewCloudClient(region, apiKey string) *CloudClient
func (c *CloudClient) ImportCertificates(ctx context.Context, certs []CertImport) (*ImportResult, error)
func (c *CloudClient) ValidateConnection(ctx context.Context) error
```

`ImportCertificates` maps `CertImport` to the Cloud API's `certificates` array format. The `apiClientInformation` field is set to `{"type": "CipherFlag", "identifier": serverIP}` for each cert that has observation data.

### TPP Client Adapter

Wrap the existing TPP `Client` to implement `VenafiClient`:

```go
type TPPAdapter struct {
    client *Client
    folder string
}

func NewTPPAdapter(client *Client, folder string) *TPPAdapter
func (a *TPPAdapter) ImportCertificates(ctx context.Context, certs []CertImport) (*ImportResult, error)
func (a *TPPAdapter) ValidateConnection(ctx context.Context) error
```

`ImportCertificates` calls the existing `ImportDiscovery` method, mapping `CertImport` to `DiscoveryImportRequest`.

`ValidateConnection` attempts a token refresh to verify credentials.

### Pusher Changes

The `Pusher` struct changes from holding `*Client` to holding `VenafiClient`:

```go
type Pusher struct {
    client   VenafiClient  // was *Client
    store    store.CertStore
    interval time.Duration
    logger   zerolog.Logger
}
```

The `buildDiscoveryPayload` method is replaced by building `[]CertImport` from certificates + observations, then passing to `client.ImportCertificates`.

### Main.go Client Selection

```go
var venafiClient venafi.VenafiClient
if cfg.Export.Venafi.Platform == "cloud" {
    venafiClient = venafi.NewCloudClient(cfg.Export.Venafi.Region, cfg.Export.Venafi.APIKey)
} else {
    tppClient := venafi.NewClient(sdkBase, authBase, cfg.Export.Venafi.ClientID, cfg.Export.Venafi.RefreshToken)
    venafiClient = venafi.NewTPPAdapter(tppClient, cfg.Export.Venafi.Folder)
}
pusher := venafi.NewPusher(venafiClient, st, venafiInterval)
```

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `internal/export/venafi/interface.go` | Create | VenafiClient interface, CertImport, ImportResult types |
| `internal/export/venafi/cloud.go` | Create | Venafi Cloud client implementation |
| `internal/export/venafi/tpp_adapter.go` | Create | TPP adapter implementing VenafiClient |
| `internal/export/venafi/pusher.go` | Modify | Use VenafiClient interface instead of *Client |
| `internal/config/config.go` | Modify | Add Platform, APIKey, Region fields |
| `config/cipherflag.toml` | Modify | Add cloud config options |
| `cmd/cipherflag/main.go` | Modify | Client selection based on platform |

## Error Handling

- **Invalid API key (401):** `ValidateConnection` returns clear error. Setup wizard uses this to validate before saving config.
- **Rate limiting (429):** Cloud API may rate-limit. Client respects `Retry-After` header.
- **Batch partial failure:** Cloud returns `statistics.failed > 0`. Log the count, mark affected certs for retry.
- **Region mismatch:** If US key used against EU endpoint (or vice versa), 401 returned. Config validation should catch this.

## Out of Scope

- Venafi Cloud certificate search/pull (Phase 2 delta reconciliation)
- Application/team assignment in Venafi Cloud
- Service account authentication (API key is sufficient for discovery import)
- Certificate request/renewal via Venafi Cloud

Sources:
- [Venafi Cloud REST API](https://docs.venafi.cloud/api/vaas-rest-api/)
- [Importing certificates](https://docs.venafi.cloud/api/importing-certificate-via-api/)
- [Getting API key](https://docs.venafi.cloud/api/obtaining-api-key/)
- [TLS Protect Cloud API Reference](https://developer.venafi.com/tlsprotectcloud/reference/tls-protect-overview)
