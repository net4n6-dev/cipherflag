# Venafi Push Scheduler

Background scheduler that periodically pushes newly discovered certificates to Venafi Trust Protection Platform via the Discovery/Import API, with per-certificate failure tracking and exponential backoff.

## Scope

**In scope:**
- Background push scheduler goroutine
- Upgrade from `Certificates/Import` to `Discovery/Import` endpoint (batch, with observation metadata)
- Per-certificate push tracking (`venafi_pushed_at`, `venafi_push_failures`)
- Exponential backoff for failed certs, dead-lettering at 5 failures
- `GET /api/v1/venafi/status` endpoint for operational visibility

**Out of scope:**
- Frontend UI for Venafi status (future)
- Bidirectional sync (reading from Venafi — Phase 2)
- Policy folder mapping (Phase 3)
- Manual retry controls for dead-lettered certs (future)

## Architecture

### Push Scheduler

A background goroutine started in `cmd/cipherflag/main.go` alongside the existing Zeek poller. Only starts if `cfg.Export.Venafi.Enabled == true`.

**Cycle (every `push_interval_minutes`, default 60):**

1. Query certificates needing push:
   - `venafi_pushed_at IS NULL` (never pushed), OR
   - `last_seen > venafi_pushed_at` (updated since last push)
   - Excluding dead-lettered: `venafi_push_failures >= 5`
   - Excluding backed-off: next retry not yet due (calculated as `last_push_attempt + push_interval * 2^failures`)
2. Batch into groups of up to 100 certificates
3. For each batch, join with observations to get host/IP/port/TLS metadata
4. Call `POST /vedsdk/Discovery/Import` with the batch
5. On success: set `venafi_pushed_at = NOW()`, reset `venafi_push_failures = 0` for all certs in batch
6. On batch failure: increment `venafi_push_failures` for all certs in batch, log error
7. Venafi may return partial success with warnings — log warnings, mark successfully imported certs

**Shutdown:** Respects context cancellation via `ctx.Done()`, stops cleanly.

### Discovery/Import Client

Replace the existing `ImportCertificate` single-cert method with `ImportDiscovery` that uses the batch endpoint.

**Endpoint:** `POST https://{base_url}/vedsdk/Discovery/Import`

**Request body:**
```json
{
  "zoneName": "\\VED\\Policy\\Discovered\\CipherFlag",
  "endpoints": [
    {
      "certificates": [
        {
          "certificate": "MIIEGwUA...",
          "fingerprint": "abc123..."
        }
      ],
      "host": "payments.acme.com",
      "ip": "10.0.1.42",
      "port": 443,
      "protocols": [
        {
          "certificates": ["abc123..."],
          "protocol": "TLSv1.2"
        }
      ]
    }
  ]
}
```

**Response:**
```json
{
  "createdCertificates": 3,
  "createdInstances": 3,
  "updatedCertificates": 1,
  "updatedInstances": 0,
  "warnings": [],
  "zoneName": "\\VED\\Policy\\Discovered\\CipherFlag"
}
```

Certificates without observations (e.g., manual uploads) are sent with empty host/IP/port fields. Venafi handles this — the certificate PEM is the only required field in the endpoints array.

**OAuth2 token management** stays as-is. The existing `refreshAccessToken` method handles automatic token refresh with 60-second buffer before expiry.

**Required token scope:** `Certificate:Discover`

### Schema Changes

New migration `002_venafi_push.sql`:

```sql
ALTER TABLE certificates ADD COLUMN venafi_pushed_at TIMESTAMPTZ NULL;
ALTER TABLE certificates ADD COLUMN venafi_push_failures INT NOT NULL DEFAULT 0;
ALTER TABLE certificates ADD COLUMN venafi_last_push_attempt TIMESTAMPTZ NULL;
```

Three columns:
- `venafi_pushed_at` — timestamp of last successful push (NULL = never pushed)
- `venafi_push_failures` — consecutive failure count (0 = healthy, >= 5 = dead-lettered)
- `venafi_last_push_attempt` — timestamp of last attempt (for backoff calculation)

No index needed — the scheduler query runs at most once per hour.

### Push Tracking Store Methods

```go
// GetCertsForVenafiPush returns certificates that need pushing to Venafi.
// Excludes dead-lettered (failures >= 5) and backed-off certs.
GetCertsForVenafiPush(ctx context.Context, pushInterval time.Duration, limit int) ([]model.Certificate, error)

// MarkVenafiPushSuccess updates pushed_at and resets failure count for given fingerprints.
MarkVenafiPushSuccess(ctx context.Context, fingerprints []string) error

// MarkVenafiPushFailure increments failure count and sets last_push_attempt for given fingerprints.
MarkVenafiPushFailure(ctx context.Context, fingerprints []string) error

// GetVenafiPushStats returns aggregate push status for the status endpoint.
GetVenafiPushStats(ctx context.Context) (*model.VenafiPushStats, error)
```

The `GetCertsForVenafiPush` query:
```sql
SELECT ... FROM certificates
WHERE (venafi_pushed_at IS NULL OR last_seen > venafi_pushed_at)
  AND venafi_push_failures < 5
  AND (
    venafi_last_push_attempt IS NULL
    OR venafi_last_push_attempt + ($1 * power(2, venafi_push_failures)) < NOW()
  )
ORDER BY last_seen DESC
LIMIT $2
```

Where `$1` is the push interval as an interval type for backoff calculation.

### Observation Lookup

When building the Discovery/Import payload, the scheduler needs observation data for each certificate. Use the existing `GetObservations(ctx, fingerprint, 1)` to get the most recent observation per cert (host, IP, port, TLS version).

For batch efficiency, add a new store method:

```go
// GetLatestObservationsForCerts returns the most recent observation per certificate fingerprint.
GetLatestObservationsForCerts(ctx context.Context, fingerprints []string) (map[string]*model.CertificateObservation, error)
```

This uses a single query with `DISTINCT ON (cert_fingerprint)` instead of N+1 queries.

### Status API

**`GET /api/v1/venafi/status`**

Response:
```json
{
  "enabled": true,
  "last_push_at": "2026-03-27T15:00:00Z",
  "pending": 42,
  "pushed": 1094,
  "failed": 3,
  "dead_lettered": 1,
  "next_push_at": "2026-03-27T16:00:00Z"
}
```

Model type:
```go
type VenafiPushStats struct {
    Enabled      bool      `json:"enabled"`
    LastPushAt   *time.Time `json:"last_push_at"`
    Pending      int       `json:"pending"`
    Pushed       int       `json:"pushed"`
    Failed       int       `json:"failed"`
    DeadLettered int       `json:"dead_lettered"`
    NextPushAt   *time.Time `json:"next_push_at"`
}
```

The `pending` count = certs where `venafi_pushed_at IS NULL OR last_seen > venafi_pushed_at` and `venafi_push_failures < 5`. The `failed` count = certs where `venafi_push_failures > 0 AND < 5`. The `dead_lettered` count = certs where `venafi_push_failures >= 5`.

### Pusher Component

New file `internal/export/venafi/pusher.go`:

```go
type Pusher struct {
    client   *Client
    store    store.CertStore
    folder   string
    interval time.Duration
    logger   zerolog.Logger
}

func NewPusher(client *Client, store store.CertStore, folder string, interval time.Duration) *Pusher

// Run starts the push loop. Blocks until ctx is cancelled.
func (p *Pusher) Run(ctx context.Context)

// pushCycle runs one push cycle. Returns number of certs pushed.
func (p *Pusher) pushCycle(ctx context.Context) (int, error)

// buildDiscoveryPayload converts certs + observations into Venafi Discovery/Import request body.
func (p *Pusher) buildDiscoveryPayload(certs []model.Certificate, obs map[string]*model.CertificateObservation) DiscoveryImportRequest
```

### File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `internal/store/migrations/002_venafi_push.sql` | Create | Add 3 columns to certificates |
| `internal/model/analytics.go` | Modify | Add VenafiPushStats type |
| `internal/store/store.go` | Modify | Add 5 new interface methods |
| `internal/store/postgres.go` | Modify | Implement 5 new store methods |
| `internal/export/venafi/client.go` | Modify | Add ImportDiscovery method + request/response types |
| `internal/export/venafi/pusher.go` | Create | Push scheduler goroutine |
| `internal/api/handler/venafi.go` | Create | Status endpoint handler |
| `internal/api/server.go` | Modify | Register venafi status route |
| `cmd/cipherflag/main.go` | Modify | Start pusher goroutine |

## Error Handling

- **Network failure (batch fails):** Increment `venafi_push_failures` for all certs in batch, retry next cycle with backoff
- **Venafi returns warnings:** Log warnings, treat as partial success. Certs not mentioned in warnings are marked successful.
- **OAuth token failure:** Client auto-refreshes. If refresh fails, the entire cycle fails and retries next interval.
- **Dead-lettered certs (5+ failures):** Logged at WARN level, excluded from future cycles. Manual intervention required (reset via direct DB update or future API endpoint).
- **Malformed PEM:** Venafi rejects it in the batch, returns a warning. Other certs in the batch still import.

## Configuration

No new config fields needed. Uses existing `[export.venafi]` section:

```toml
[export.venafi]
enabled = false
base_url = ""
client_id = ""
refresh_token = ""
folder = "\\VED\\Policy\\Discovered\\CipherFlag"
push_interval_minutes = 60
```

## Dependencies

No new Go dependencies. Uses existing `zerolog` for logging, `pgx` for database, `net/http` for Venafi API calls.
