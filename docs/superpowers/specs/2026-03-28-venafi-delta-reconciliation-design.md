# Venafi Delta Reconciliation (Phase 2)

> **Status: Deferred** — Spec written for future implementation. Not scheduled.

Pulls the current Venafi TPP certificate inventory and reconciles it against CipherFlag's discovered certificates, providing a delta view showing what each system knows that the other doesn't.

## Problem

The push scheduler (Phase 1) is a one-way pipe. It sends discovered certs to Venafi but has no visibility into what Venafi already manages. Operators can't answer:

- "What did we find that Venafi doesn't know about?" (discovery gap — CipherFlag's unique value)
- "What does Venafi manage that we haven't seen on the network?" (visibility gap — certs not in active use, or on networks we're not monitoring)
- "How much overlap exists?" (coverage metric)

## Architecture

### Periodic Pull from Venafi

A background job (similar to the push scheduler) that periodically calls `GET /vedsdk/certificates/` to enumerate Venafi's inventory.

**Endpoint:** `GET https://{base_url}/vedsdk/certificates/`

**Key parameters:**
- `Limit` + `Offset` for pagination (default 100 per page)
- `parentdnrecursive` to search within the configured policy folder
- `OptionalFields=KeyAlgorithm,KeySize,Subject,Issuer` for metadata

**Response includes:** DN, GUID, X509 details (CN, Serial, Thumbprint/fingerprint, ValidFrom, ValidTo, SANs), TotalCount, pagination links.

**Reconciliation key:** SHA-256 fingerprint. Venafi returns SHA-1 thumbprint by default — need to verify if SHA-256 is available via `OptionalFields` or if we need to match by serial + issuer DN as fallback.

### Tracking Table

New table `venafi_inventory`:

```sql
CREATE TABLE venafi_inventory (
    fingerprint_sha256  TEXT PRIMARY KEY,
    venafi_dn           TEXT NOT NULL,
    venafi_guid         TEXT NOT NULL,
    subject_cn          TEXT,
    issuer_cn           TEXT,
    not_after           TIMESTAMPTZ,
    serial_number       TEXT,
    last_synced_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

Separate from the `certificates` table — Venafi may know about certs that CipherFlag has never seen (different network segments, pre-existing inventory).

### Delta Computation

Three buckets computed by joining `certificates` and `venafi_inventory` on fingerprint:

| Bucket | Query | Meaning |
|--------|-------|---------|
| **CipherFlag-only** | `certificates LEFT JOIN venafi_inventory WHERE vi.fingerprint IS NULL` | Discovered on network, not in Venafi. These are the push candidates. |
| **Venafi-only** | `venafi_inventory LEFT JOIN certificates WHERE c.fingerprint IS NULL` | Managed by Venafi, not seen on network. May be unused, on unmonitored segments, or pre-provisioned. |
| **Both** | `certificates INNER JOIN venafi_inventory` | Known to both systems. Push scheduler has done its job for these. |

### API Endpoints

**`GET /api/v1/venafi/delta`**

Returns the three buckets with counts and sample certs:

```json
{
  "cipherflag_only": {
    "count": 342,
    "certs": [ { "fingerprint": "...", "subject_cn": "...", "issuer_cn": "...", "not_after": "...", "source": "zeek_passive" } ]
  },
  "venafi_only": {
    "count": 89,
    "certs": [ { "fingerprint": "...", "subject_cn": "...", "venafi_dn": "...", "not_after": "..." } ]
  },
  "both": {
    "count": 1047
  },
  "last_sync_at": "2026-03-28T10:00:00Z",
  "sync_enabled": true
}
```

The `certs` arrays are limited to 50 per bucket. Full lists accessible via filtered certificate search.

**`POST /api/v1/venafi/sync`**

Manually triggers a pull from Venafi (in addition to the periodic schedule). Returns immediately with a job status.

### Frontend

A new "Venafi" tab on the analytics page (or a dedicated page) showing:

- **Three-bucket summary cards** — CipherFlag-only count, Venafi-only count, overlap count
- **Venn diagram or stacked bar** showing the proportions
- **CipherFlag-only list** — these are the certs the push scheduler should send. Link to trigger push.
- **Venafi-only list** — certs Venafi manages that aren't on the monitored network. Useful for identifying unused certs or unmonitored segments.
- **Last sync timestamp** and manual sync button

### Sync Configuration

Extends the existing `[export.venafi]` config:

```toml
[export.venafi]
# ... existing fields ...
sync_enabled = false
sync_interval_minutes = 360    # 6 hours default
sync_folder = "\\VED\\Policy"  # scope of pull (can be broader than push folder)
```

### Fingerprint Matching Challenge

Venafi's `GET /certificates/` returns SHA-1 thumbprint in the `X509.Thumbprint` field. CipherFlag uses SHA-256 fingerprints. Options:

**A) Add SHA-1 to CipherFlag** — Compute and store SHA-1 fingerprint during ingestion. Match on SHA-1 when reconciling with Venafi. Simple but adds a column.

**B) Match by serial + issuer** — Serial number + issuer DN is unique per certificate. No new columns but more complex matching and edge cases with reissued certs.

**C) Retrieve full cert from Venafi** — Use `POST /Certificates/Retrieve/{guid}` to get the PEM, compute SHA-256 locally. Accurate but expensive (one API call per cert).

**Recommended: A** — SHA-1 is fast to compute, one column, reliable matching.

## Dependencies

- Phase 1 (push scheduler) must be complete — ✅ done
- Venafi TPP access with `Certificate` scope for the GET endpoint
- SHA-1 computation during certificate ingestion (if option A)

## Scope Estimate

- 1 new table + migration
- 1 new background sync goroutine (similar to pusher)
- 2 new API endpoints (delta, manual sync)
- 3 new store methods
- 1 new frontend tab/page
- SHA-1 fingerprint addition to ingestion pipeline

## Out of Scope

- Automatic remediation (pushing CipherFlag-only certs without operator review)
- Venafi policy folder mapping
- Certificate lifecycle management (renewal, revocation via Venafi API)
- Multi-Venafi-instance support
