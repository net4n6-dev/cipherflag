# Venafi Integration Guide

CipherFlag integrates with both **Venafi TLS Protect Cloud** (SaaS) and **Venafi Trust Protection Platform** (on-prem TPP) to automatically push discovered certificates.

---

## Venafi Cloud (Recommended)

### Step 1: Get Your API Key

1. Log into [Venafi TLS Protect Cloud](https://ui.venafi.cloud)
2. Click your avatar in the top-right corner
3. Select **Preferences**
4. Navigate to the **API Keys** tab
5. Copy your API key

### Step 2: Configure CipherFlag

Edit `config/cipherflag.toml`:

```toml
[export.venafi]
enabled = true
platform = "cloud"
api_key = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
region = "us"                   # "us" or "eu"
push_interval_minutes = 60
```

Or use environment variables:

```bash
VENAFI_ENABLED=true
VENAFI_PLATFORM=cloud
VENAFI_API_KEY=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
VENAFI_REGION=us
```

Restart CipherFlag:

```bash
docker-compose restart cipherflag
```

### Step 3: Verify

Check the push status:

```bash
curl -s http://localhost:8443/api/v1/venafi/status | python3 -m json.tool
```

Expected response:

```json
{
  "enabled": true,
  "last_push_at": "2026-03-28T10:00:00Z",
  "pending": 0,
  "pushed": 1136,
  "failed": 0,
  "dead_lettered": 0,
  "next_push_at": "2026-03-28T11:00:00Z"
}
```

### Regions

| Region | Base URL | Use when |
|--------|----------|----------|
| `us` (default) | `api.venafi.cloud` | Your Venafi Cloud account is in the US region |
| `eu` | `api.venafi.eu` | Your Venafi Cloud account is in the EU region |

---

## Venafi TPP (On-Prem)

### Step 1: Get TPP API Credentials

CipherFlag authenticates to Venafi TPP using OAuth2 with a refresh token. You need:

- **Client ID** -- An API application integration registered in Venafi
- **Refresh token** -- A long-lived token used to obtain short-lived access tokens

To create these in Venafi TPP:

1. Log into the Venafi TPP web console as an administrator
2. Navigate to **API** > **API Integrations**
3. Create a new API integration:
   - **Name:** CipherFlag
   - **Grant types:** Resource Owner, Refresh Token
   - **Scope:** `certificate:discover` (minimum required)
   - **Token refresh:** Enable (recommended: 90-day refresh token lifetime)
4. Note the **Client ID** displayed after creation
5. Obtain a refresh token using the Venafi OAuth2 token endpoint:
   ```bash
   curl -X POST "https://tpp.example.com/vedauth/authorize/oauth" \
     -H "Content-Type: application/json" \
     -d '{
       "client_id": "your-client-id",
       "username": "your-username",
       "password": "your-password",
       "scope": "certificate:discover"
     }'
   ```
   The response includes `access_token` and `refresh_token`. CipherFlag only needs the `refresh_token`.

### Step 2: Configure CipherFlag

Edit `config/cipherflag.toml`:

```toml
[export.venafi]
enabled = true
platform = "tpp"
base_url = "https://tpp.example.com"
client_id = "your-client-id"
refresh_token = "your-refresh-token"
folder = "\\VED\\Policy\\Discovered\\CipherFlag"
push_interval_minutes = 60
```

Or use environment variables:

```bash
VENAFI_ENABLED=true
VENAFI_PLATFORM=tpp
VENAFI_BASE_URL=https://tpp.example.com
VENAFI_CLIENT_ID=your-client-id
VENAFI_REFRESH_TOKEN=your-refresh-token
VENAFI_FOLDER=\VED\Policy\Discovered\CipherFlag
```

Restart CipherFlag:

```bash
docker-compose restart cipherflag
```

### Step 3: Verify

Same as Cloud — check the push status endpoint:

```bash
curl -s http://localhost:8443/api/v1/venafi/status | python3 -m json.tool
```

---

## What Gets Pushed

Each push cycle sends newly discovered or updated certificates with:

| Field | Source | Cloud | TPP |
|-------|--------|-------|-----|
| Certificate (PEM) | Zeek certificate extraction | Base64-encoded | Base64-encoded |
| Server hostname | CipherFlag ssl.log observations | `apiClientInformation.identifier` | `endpoints[].host` |
| Server IP | CipherFlag ssl.log observations | -- | `endpoints[].ip` |
| Server port | CipherFlag ssl.log observations | -- | `endpoints[].port` |
| TLS version | CipherFlag ssl.log observations | -- | `endpoints[].protocols` |

Venafi Cloud receives certificate data and source metadata. Venafi TPP additionally receives full endpoint context (IP, port, TLS version) via the Discovery/Import API.

Both platforms handle deduplication — pushing an existing certificate is safe and will not create duplicates.

---

## Push Scheduler Behavior

- **Interval:** Configurable (default 60 minutes)
- **Batch size:** Up to 100 certificates per API call
- **Failure handling:** Exponential backoff per certificate. After 5 consecutive failures, a certificate is dead-lettered and excluded from future push cycles.
- **Status endpoint:** `GET /api/v1/venafi/status` returns pending, pushed, failed, and dead-lettered counts

### Status Fields

| Field | Description |
|-------|-------------|
| `enabled` | Whether Venafi integration is active |
| `last_push_at` | Timestamp of the most recent successful push |
| `pending` | Certificates not yet pushed or updated since last push |
| `pushed` | Certificates successfully pushed and up to date |
| `failed` | Certificates with 1-4 consecutive failures (will retry with backoff) |
| `dead_lettered` | Certificates with 5+ failures (excluded from push, requires manual intervention) |
| `next_push_at` | Estimated time of next push cycle |

---

## Manual CSV/JSON Export

For organizations that prefer manual import or use a different CLM platform:

### CSV Export

```bash
curl -o certificates.csv "http://localhost:8443/api/v1/export/certificates?format=csv"
```

The CSV columns are aligned with the Venafi bulk import template.

### JSON Export

```bash
curl -o certificates.json "http://localhost:8443/api/v1/export/certificates?format=json"
```

### Filtering Exports

```bash
# Export only failing certificates
curl -o failing.csv "http://localhost:8443/api/v1/export/certificates?format=csv&grade=D,F"

# Export certificates expiring within 30 days
curl -o expiring.csv "http://localhost:8443/api/v1/export/certificates?format=csv&expiring_within_days=30"
```

The **Export** button on the certificates page in the UI provides the same functionality.

---

## Troubleshooting

### Venafi Cloud

**"401 Unauthorized"**
- Verify your API key is correct and active
- Check that your API key matches the region (`us` vs `eu`)
- API keys can be rotated in Venafi Cloud under **Preferences** > **API Keys**

**Certificates not appearing**
- Check the push status endpoint: `curl http://localhost:8443/api/v1/venafi/status`
- Look for push errors in logs: `docker-compose logs cipherflag | grep venafi`
- Certificates appear in Venafi Cloud under **Inventory** > **Certificates** with source "USER_IMPORTED"

### Venafi TPP

**"connection refused" or timeout errors**
- Verify `base_url` is correct and reachable from the Docker network:
  ```bash
  docker-compose exec cipherflag wget -q -O- https://tpp.example.com/vedsdk/ || echo "unreachable"
  ```
- If TPP is on an internal network, ensure the Docker host has network access

**"401 Unauthorized" or token errors**
- The refresh token may have expired. Obtain a new one using the authorize endpoint (see TPP Step 1)
- Verify the `client_id` matches the API integration registered in Venafi
- Check that the API integration has `certificate:discover` scope

**Certificates not appearing in Venafi**
- Verify the target folder exists in Venafi: `\VED\Policy\Discovered\CipherFlag`
- The service account needs Create permission on the target folder
- Check CipherFlag logs: `docker-compose logs cipherflag | grep venafi`

### General

**Dead-lettered certificates**
- Check status: `curl http://localhost:8443/api/v1/venafi/status` — look at `dead_lettered` count
- These certificates failed 5+ times and are excluded from push. Common causes: malformed PEM data, missing certificate chain in Venafi.
- To retry, reset the failure count directly in the database:
  ```sql
  UPDATE certificates SET venafi_push_failures = 0, venafi_last_push_attempt = NULL WHERE venafi_push_failures >= 5;
  ```
