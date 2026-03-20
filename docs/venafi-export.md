# Venafi Export Guide

CipherFlag can export discovered certificates to Venafi Trust Protection Platform (TPP) in two ways:

1. **Automated push** -- CipherFlag periodically sends new certificates to Venafi via REST API
2. **Manual download** -- Export certificates as CSV or JSON for manual import into Venafi

---

## Automated Push to Venafi TPP

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
   - **Scope:** `certificate:manage` (minimum required)
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
       "scope": "certificate:manage"
     }'
   ```
   The response includes `access_token` and `refresh_token`. CipherFlag only needs the `refresh_token`.

CipherFlag handles access token lifecycle automatically: it uses the refresh token to obtain short-lived access tokens and refreshes them before expiry. No manual token rotation is required.

### Step 2: Configure CipherFlag

Edit `.env`:

```bash
VENAFI_ENABLED=true
VENAFI_BASE_URL=https://tpp.example.com/vedsdk
VENAFI_CLIENT_ID=your-client-id
VENAFI_REFRESH_TOKEN=your-refresh-token
VENAFI_FOLDER=\VED\Policy\Discovered\CipherFlag
```

Or edit `config/cipherflag.toml` directly:

```toml
[export.venafi]
enabled = true
base_url = "https://tpp.example.com/vedsdk"
client_id = "your-client-id"
refresh_token = "your-refresh-token"
folder = "\\VED\\Policy\\Discovered\\CipherFlag"
push_interval_minutes = 60
```

Restart CipherFlag after changing configuration:

```bash
docker-compose restart cipherflag
```

### Step 3: Verify

Check the CipherFlag logs for successful Venafi push activity:

```bash
docker-compose logs -f cipherflag | grep -i venafi
```

Certificates appear in Venafi under the configured policy folder.

### What Gets Pushed

Each certificate push includes:

| Field | Source |
|-------|--------|
| Certificate (PEM) | Zeek certificate extraction |
| Subject DN | Zeek x509.log |
| Issuer DN | Zeek x509.log |
| Serial number | Zeek x509.log |
| Validity dates | Zeek x509.log |
| SANs | Zeek x509.log |
| Key algorithm + size | Zeek x509.log |
| Signature algorithm | Zeek x509.log |
| Discovery source | CipherFlag metadata |
| First/last seen | CipherFlag metadata |
| Observed endpoints | CipherFlag ssl.log observations |
| Health grade | CipherFlag scoring |

CipherFlag only pushes certificates that are new or updated since the last push cycle. Venafi handles deduplication by certificate thumbprint.

---

## Manual CSV/JSON Export

For organizations that prefer manual import or do not use Venafi TPP:

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

All certificate list filters are supported:

```bash
# Export only failing certificates
curl -o failing.csv "http://localhost:8443/api/v1/export/certificates?format=csv&grade=D,F"

# Export certificates expiring within 30 days
curl -o expiring.csv "http://localhost:8443/api/v1/export/certificates?format=csv&expiring_within_days=30"
```

The **Export** button on the certificates page in the UI provides the same functionality.

---

## Troubleshooting

### "connection refused" or timeout errors

- Verify `VENAFI_BASE_URL` is correct and reachable from the Docker network:
  ```bash
  docker-compose exec cipherflag wget -q -O- https://tpp.example.com/vedsdk/ || echo "unreachable"
  ```
- If TPP is on an internal network, ensure the Docker host has network access

### "401 Unauthorized" or token errors

- The refresh token may have expired. Obtain a new one using the authorize endpoint (see Step 1)
- Verify the `client_id` matches the API integration registered in Venafi
- Check that the API integration has `certificate:manage` scope

### Certificates not appearing in Venafi

- Verify the target folder exists in Venafi: `\VED\Policy\Discovered\CipherFlag`
- The service account associated with the API credentials needs Create permission on the target folder
- Check CipherFlag logs for push errors:
  ```bash
  docker-compose logs cipherflag | grep -i "venafi\|export"
  ```

### "certificate does not include PEM"

- PEM data is only available when Zeek's `extract-certs-pem` policy is enabled (it is enabled by default in the CipherFlag Zeek container)
- For certificates discovered without PEM data, CipherFlag sends metadata-only exports to Venafi
