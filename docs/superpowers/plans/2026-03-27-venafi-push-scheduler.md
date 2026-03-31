# Venafi Push Scheduler Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a background scheduler that periodically pushes newly discovered certificates to Venafi TPP via the Discovery/Import API, with per-certificate failure tracking and exponential backoff.

**Architecture:** New migration adds push tracking columns. New store methods query/update push state. The existing Venafi client gets an `ImportDiscovery` batch method. A new `Pusher` goroutine runs alongside the Zeek poller, batching certs and pushing on a configurable interval. A status endpoint exposes operational metrics.

**Tech Stack:** Go 1.24, pgx/PostgreSQL, Venafi TPP REST API (Discovery/Import, OAuth2)

**Spec:** `docs/superpowers/specs/2026-03-27-venafi-push-scheduler-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `internal/store/migrations/004_venafi_push.sql` | Create | Add 3 columns to certificates table |
| `internal/model/analytics.go` | Modify | Add VenafiPushStats type |
| `internal/store/store.go` | Modify | Add 5 new interface methods |
| `internal/store/postgres.go` | Modify | Implement 5 new store methods |
| `internal/export/venafi/client.go` | Modify | Add ImportDiscovery method + types |
| `internal/export/venafi/pusher.go` | Create | Push scheduler goroutine |
| `internal/api/handler/venafi.go` | Create | Status endpoint handler |
| `internal/api/server.go` | Modify | Register venafi routes, accept config |
| `cmd/cipherflag/main.go` | Modify | Start pusher goroutine |

---

## Task 1: Database Migration

**Files:**
- Create: `internal/store/migrations/004_venafi_push.sql`

- [ ] **Step 1: Create migration file**

```sql
-- 004_venafi_push.sql
-- Add Venafi push tracking columns to certificates table.

ALTER TABLE certificates ADD COLUMN IF NOT EXISTS venafi_pushed_at TIMESTAMPTZ NULL;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS venafi_push_failures INT NOT NULL DEFAULT 0;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS venafi_last_push_attempt TIMESTAMPTZ NULL;
```

- [ ] **Step 2: Verify migration runs**

```bash
cd /Users/Erik/projects/cipherflag && go build ./... && bin/cipherflag migrate
```

Expected: "migrations applied successfully"

- [ ] **Step 3: Commit**

```bash
git add internal/store/migrations/004_venafi_push.sql
git commit -m "feat(store): add venafi push tracking columns migration"
```

---

## Task 2: Model Types & Store Interface

**Files:**
- Modify: `internal/model/analytics.go`
- Modify: `internal/store/store.go`

- [ ] **Step 1: Add VenafiPushStats type to analytics.go**

Append at the end of `internal/model/analytics.go`:

```go
// VenafiPushStats holds aggregate push status for the Venafi status endpoint.
type VenafiPushStats struct {
	Enabled      bool       `json:"enabled"`
	LastPushAt   *time.Time `json:"last_push_at"`
	Pending      int        `json:"pending"`
	Pushed       int        `json:"pushed"`
	Failed       int        `json:"failed"`
	DeadLettered int        `json:"dead_lettered"`
	NextPushAt   *time.Time `json:"next_push_at"`
}
```

Add `"time"` to the import block in analytics.go if not already present.

- [ ] **Step 2: Add 5 new methods to CertStore interface in store.go**

Add in a new `// Venafi push` section after the existing analytics methods:

```go
	// Venafi push
	GetCertsForVenafiPush(ctx context.Context, pushInterval time.Duration, limit int) ([]model.Certificate, error)
	GetLatestObservationsForCerts(ctx context.Context, fingerprints []string) (map[string]*model.CertificateObservation, error)
	MarkVenafiPushSuccess(ctx context.Context, fingerprints []string) error
	MarkVenafiPushFailure(ctx context.Context, fingerprints []string) error
	GetVenafiPushStats(ctx context.Context) (*model.VenafiPushStats, error)
```

Add `"time"` to the import block in store.go if not already present.

- [ ] **Step 3: Verify compilation (expect missing method error)**

```bash
cd /Users/Erik/projects/cipherflag && go build ./...
```

Expected: Compile error — PostgresStore missing 5 methods.

- [ ] **Step 4: Commit**

```bash
git add internal/model/analytics.go internal/store/store.go
git commit -m "feat(model): add VenafiPushStats type and store interface methods"
```

---

## Task 3: Store Implementation

**Files:**
- Modify: `internal/store/postgres.go`

- [ ] **Step 1: Implement all 5 store methods**

Add after the existing `GetSourceLineage` method:

```go
// ── Venafi Push ─────────────────────────────────────────────────────────────

func (s *PostgresStore) GetCertsForVenafiPush(ctx context.Context, pushInterval time.Duration, limit int) ([]model.Certificate, error) {
	if limit <= 0 {
		limit = 100
	}

	// Convert pushInterval to PostgreSQL interval string for backoff calculation
	intervalSecs := int(pushInterval.Seconds())

	rows, err := s.pool.Query(ctx, `
		SELECT c.id, c.fingerprint_sha256,
			c.subject_cn, c.subject_org, c.subject_ou, c.subject_country, c.subject_state, c.subject_locality, c.subject_full,
			c.issuer_cn, c.issuer_org, c.issuer_ou, c.issuer_country, c.issuer_full,
			c.serial_number, c.not_before, c.not_after,
			c.key_algorithm, c.key_size_bits, c.signature_algorithm,
			c.subject_alt_names, c.is_ca, c.basic_constraints_path_len,
			c.key_usage, c.extended_key_usage,
			c.ocsp_responder_urls, c.crl_distribution_points, c.scts,
			c.source_discovery, c.first_seen, c.last_seen, c.raw_pem
		FROM certificates c
		WHERE (c.venafi_pushed_at IS NULL OR c.last_seen > c.venafi_pushed_at)
		  AND c.venafi_push_failures < 5
		  AND (
		    c.venafi_last_push_attempt IS NULL
		    OR c.venafi_last_push_attempt + make_interval(secs => $1 * power(2, c.venafi_push_failures)::int) < NOW()
		  )
		  AND c.raw_pem IS NOT NULL AND c.raw_pem != ''
		ORDER BY c.last_seen DESC
		LIMIT $2
	`, intervalSecs, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []model.Certificate
	for rows.Next() {
		c, err := scanCertificateRows(rows)
		if err != nil {
			return nil, err
		}
		certs = append(certs, *c)
	}
	return certs, nil
}

func (s *PostgresStore) GetLatestObservationsForCerts(ctx context.Context, fingerprints []string) (map[string]*model.CertificateObservation, error) {
	if len(fingerprints) == 0 {
		return map[string]*model.CertificateObservation{}, nil
	}

	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT ON (o.cert_fingerprint)
			o.id, o.cert_fingerprint, o.server_ip, o.server_port, o.server_name, o.client_ip,
			o.negotiated_version, o.negotiated_cipher, o.cipher_strength,
			o.ja3_fingerprint, o.ja3s_fingerprint, o.source, o.observed_at
		FROM observations o
		WHERE o.cert_fingerprint = ANY($1)
		ORDER BY o.cert_fingerprint, o.observed_at DESC
	`, fingerprints)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]*model.CertificateObservation)
	for rows.Next() {
		var obs model.CertificateObservation
		if err := rows.Scan(
			&obs.ID, &obs.CertFingerprint, &obs.ServerIP, &obs.ServerPort,
			&obs.ServerName, &obs.ClientIP, &obs.NegotiatedVersion,
			&obs.NegotiatedCipher, &obs.CipherStrength,
			&obs.JA3Fingerprint, &obs.JA3SFingerprint, &obs.Source, &obs.ObservedAt,
		); err != nil {
			return nil, err
		}
		result[obs.CertFingerprint] = &obs
	}
	return result, nil
}

func (s *PostgresStore) MarkVenafiPushSuccess(ctx context.Context, fingerprints []string) error {
	if len(fingerprints) == 0 {
		return nil
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE certificates
		SET venafi_pushed_at = NOW(),
		    venafi_push_failures = 0,
		    venafi_last_push_attempt = NOW()
		WHERE fingerprint_sha256 = ANY($1)
	`, fingerprints)
	return err
}

func (s *PostgresStore) MarkVenafiPushFailure(ctx context.Context, fingerprints []string) error {
	if len(fingerprints) == 0 {
		return nil
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE certificates
		SET venafi_push_failures = venafi_push_failures + 1,
		    venafi_last_push_attempt = NOW()
		WHERE fingerprint_sha256 = ANY($1)
	`, fingerprints)
	return err
}

func (s *PostgresStore) GetVenafiPushStats(ctx context.Context) (*model.VenafiPushStats, error) {
	stats := &model.VenafiPushStats{}

	// Counts
	s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE venafi_pushed_at IS NOT NULL AND (last_seen <= venafi_pushed_at) AND venafi_push_failures = 0),
			COUNT(*) FILTER (WHERE (venafi_pushed_at IS NULL OR last_seen > venafi_pushed_at) AND venafi_push_failures < 5),
			COUNT(*) FILTER (WHERE venafi_push_failures > 0 AND venafi_push_failures < 5),
			COUNT(*) FILTER (WHERE venafi_push_failures >= 5)
		FROM certificates
	`).Scan(&stats.Pushed, &stats.Pending, &stats.Failed, &stats.DeadLettered)

	// Last push time
	var lastPush *time.Time
	s.pool.QueryRow(ctx, "SELECT MAX(venafi_pushed_at) FROM certificates").Scan(&lastPush)
	stats.LastPushAt = lastPush

	return stats, nil
}
```

- [ ] **Step 2: Verify compilation**

```bash
cd /Users/Erik/projects/cipherflag && go build ./...
```

Expected: PASS — all interface methods implemented.

- [ ] **Step 3: Commit**

```bash
git add internal/store/postgres.go
git commit -m "feat(store): implement Venafi push tracking queries"
```

---

## Task 4: Discovery/Import Client Method

**Files:**
- Modify: `internal/export/venafi/client.go`

- [ ] **Step 1: Add Discovery/Import types and method**

Add these types and the `ImportDiscovery` method after the existing `ImportCertificate` method:

```go
// DiscoveryImportRequest is the body for POST /vedsdk/Discovery/Import.
type DiscoveryImportRequest struct {
	ZoneName  string               `json:"zoneName"`
	Endpoints []DiscoveryEndpoint  `json:"endpoints"`
}

// DiscoveryEndpoint represents one certificate + its deployment context.
type DiscoveryEndpoint struct {
	Certificates []DiscoveryCert    `json:"certificates"`
	Host         string             `json:"host,omitempty"`
	IP           string             `json:"ip,omitempty"`
	Port         int                `json:"port,omitempty"`
	Protocols    []DiscoveryProto   `json:"protocols,omitempty"`
}

// DiscoveryCert holds a certificate for the Discovery/Import endpoint.
type DiscoveryCert struct {
	Certificate string `json:"certificate"`
	Fingerprint string `json:"fingerprint"`
}

// DiscoveryProto holds TLS protocol info for a discovered endpoint.
type DiscoveryProto struct {
	Certificates []string `json:"certificates"`
	Protocol     string   `json:"protocol"`
}

// DiscoveryImportResponse is the response from POST /vedsdk/Discovery/Import.
type DiscoveryImportResponse struct {
	CreatedCertificates int      `json:"createdCertificates"`
	CreatedInstances    int      `json:"createdInstances"`
	UpdatedCertificates int      `json:"updatedCertificates"`
	UpdatedInstances    int      `json:"updatedInstances"`
	Warnings            []string `json:"warnings"`
	ZoneName            string   `json:"zoneName"`
}

// ImportDiscovery imports a batch of certificates with endpoint metadata via Discovery/Import.
func (c *Client) ImportDiscovery(ctx context.Context, request *DiscoveryImportRequest) (*DiscoveryImportResponse, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("venafi: obtaining token: %w", err)
	}

	payload, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("venafi: marshalling discovery import: %w", err)
	}

	url := c.sdkBaseURL + "/Discovery/Import"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("venafi: creating discovery import request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("venafi: discovery import request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("venafi: discovery import returned status %d", resp.StatusCode)
	}

	var result DiscoveryImportResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("venafi: decoding discovery import response: %w", err)
	}

	return &result, nil
}
```

- [ ] **Step 2: Verify compilation**

```bash
cd /Users/Erik/projects/cipherflag && go build ./...
```

- [ ] **Step 3: Commit**

```bash
git add internal/export/venafi/client.go
git commit -m "feat(venafi): add ImportDiscovery batch method for Discovery/Import API"
```

---

## Task 5: Push Scheduler Goroutine

**Files:**
- Create: `internal/export/venafi/pusher.go`

- [ ] **Step 1: Create pusher.go**

```go
package venafi

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/rs/zerolog"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

const pushBatchSize = 100

// Pusher periodically pushes new certificates to Venafi TPP.
type Pusher struct {
	client   *Client
	store    store.CertStore
	folder   string
	interval time.Duration
	logger   zerolog.Logger
}

// NewPusher creates a new Venafi push scheduler.
func NewPusher(client *Client, st store.CertStore, folder string, interval time.Duration) *Pusher {
	return &Pusher{
		client:   client,
		store:    st,
		folder:   folder,
		interval: interval,
		logger:   zerolog.New(zerolog.NewConsoleWriter()).With().Str("component", "venafi-pusher").Timestamp().Logger(),
	}
}

// Run starts the push loop. Blocks until ctx is cancelled.
func (p *Pusher) Run(ctx context.Context) {
	p.logger.Info().Dur("interval", p.interval).Msg("venafi push scheduler started")

	// Run immediately on start, then on interval
	p.runCycle(ctx)

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.logger.Info().Msg("venafi push scheduler stopped")
			return
		case <-ticker.C:
			p.runCycle(ctx)
		}
	}
}

func (p *Pusher) runCycle(ctx context.Context) {
	total := 0
	for {
		certs, err := p.store.GetCertsForVenafiPush(ctx, p.interval, pushBatchSize)
		if err != nil {
			p.logger.Error().Err(err).Msg("failed to query certs for push")
			return
		}
		if len(certs) == 0 {
			break
		}

		pushed, err := p.pushBatch(ctx, certs)
		total += pushed
		if err != nil {
			p.logger.Error().Err(err).Int("batch_size", len(certs)).Msg("batch push failed")
			// Mark all certs in batch as failed
			fps := make([]string, len(certs))
			for i, c := range certs {
				fps[i] = c.FingerprintSHA256
			}
			if markErr := p.store.MarkVenafiPushFailure(ctx, fps); markErr != nil {
				p.logger.Error().Err(markErr).Msg("failed to mark push failures")
			}
			return
		}

		// If we got fewer than batch size, we're done
		if len(certs) < pushBatchSize {
			break
		}
	}

	if total > 0 {
		p.logger.Info().Int("pushed", total).Msg("venafi push cycle complete")
	}
}

func (p *Pusher) pushBatch(ctx context.Context, certs []model.Certificate) (int, error) {
	// Get observations for endpoint metadata
	fps := make([]string, len(certs))
	for i, c := range certs {
		fps[i] = c.FingerprintSHA256
	}

	observations, err := p.store.GetLatestObservationsForCerts(ctx, fps)
	if err != nil {
		p.logger.Warn().Err(err).Msg("failed to get observations, pushing without endpoint metadata")
		observations = map[string]*model.CertificateObservation{}
	}

	// Build Discovery/Import request
	request := p.buildDiscoveryPayload(certs, observations)

	// Call Venafi
	resp, err := p.client.ImportDiscovery(ctx, request)
	if err != nil {
		return 0, err
	}

	// Log warnings
	for _, w := range resp.Warnings {
		p.logger.Warn().Str("warning", w).Msg("venafi import warning")
	}

	// Mark all as success (Venafi processes the whole batch or returns error)
	if markErr := p.store.MarkVenafiPushSuccess(ctx, fps); markErr != nil {
		p.logger.Error().Err(markErr).Msg("failed to mark push success")
	}

	p.logger.Debug().
		Int("created_certs", resp.CreatedCertificates).
		Int("updated_certs", resp.UpdatedCertificates).
		Int("created_instances", resp.CreatedInstances).
		Int("warnings", len(resp.Warnings)).
		Msg("batch pushed to venafi")

	return len(certs), nil
}

func (p *Pusher) buildDiscoveryPayload(certs []model.Certificate, observations map[string]*model.CertificateObservation) *DiscoveryImportRequest {
	request := &DiscoveryImportRequest{
		ZoneName:  p.folder,
		Endpoints: make([]DiscoveryEndpoint, 0, len(certs)),
	}

	for _, cert := range certs {
		// Base64-encode the PEM for Venafi (strip PEM headers, use raw base64)
		certData := cert.RawPEM
		// If already PEM-encoded, Venafi accepts it as-is in base64
		encoded := base64.StdEncoding.EncodeToString([]byte(certData))

		endpoint := DiscoveryEndpoint{
			Certificates: []DiscoveryCert{
				{
					Certificate: encoded,
					Fingerprint: cert.FingerprintSHA256,
				},
			},
		}

		// Add observation metadata if available
		if obs, ok := observations[cert.FingerprintSHA256]; ok {
			endpoint.Host = obs.ServerName
			if endpoint.Host == "" {
				endpoint.Host = obs.ServerIP
			}
			endpoint.IP = obs.ServerIP
			endpoint.Port = obs.ServerPort
			endpoint.Protocols = []DiscoveryProto{
				{
					Certificates: []string{cert.FingerprintSHA256},
					Protocol:     string(obs.NegotiatedVersion),
				},
			}
		}

		request.Endpoints = append(request.Endpoints, endpoint)
	}

	return request
}
```

- [ ] **Step 2: Verify compilation**

```bash
cd /Users/Erik/projects/cipherflag && go build ./...
```

- [ ] **Step 3: Commit**

```bash
git add internal/export/venafi/pusher.go
git commit -m "feat(venafi): add push scheduler goroutine with batch Discovery/Import"
```

---

## Task 6: Status Endpoint

**Files:**
- Create: `internal/api/handler/venafi.go`
- Modify: `internal/api/server.go`

- [ ] **Step 1: Create venafi.go handler**

```go
package handler

import (
	"net/http"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/store"
)

type VenafiHandler struct {
	store         store.CertStore
	enabled       bool
	pushInterval  time.Duration
}

func NewVenafiHandler(s store.CertStore, enabled bool, pushInterval time.Duration) *VenafiHandler {
	return &VenafiHandler{
		store:        s,
		enabled:      enabled,
		pushInterval: pushInterval,
	}
}

func (h *VenafiHandler) Status(w http.ResponseWriter, r *http.Request) {
	stats, err := h.store.GetVenafiPushStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	stats.Enabled = h.enabled

	// Calculate next push time
	if stats.LastPushAt != nil && h.enabled {
		next := stats.LastPushAt.Add(h.pushInterval)
		stats.NextPushAt = &next
	}

	writeJSON(w, http.StatusOK, stats)
}
```

- [ ] **Step 2: Update server.go to accept config and register the venafi route**

In `internal/api/server.go`, update the `NewRouter` function signature to accept Venafi config parameters, create the handler, and register the route.

Add these parameters to the `NewRouter` function:

```go
func NewRouter(st store.CertStore, frontendURL string, pcapInputDir string, pcapMaxSizeMB int, venafiEnabled bool, venafiPushInterval time.Duration) http.Handler {
```

Add the import for `"time"` if not present.

Create the handler and register the route inside `NewRouter`, after the existing PCAP routes:

```go
	venafiH := handler.NewVenafiHandler(st, venafiEnabled, venafiPushInterval)

	// ...inside r.Route("/api/v1", func(r chi.Router) {

		// Venafi
		r.Get("/venafi/status", venafiH.Status)
```

- [ ] **Step 3: Update the NewRouter call in main.go**

In `cmd/cipherflag/main.go`, update the `api.NewRouter` call in `runServe` to pass the new parameters:

```go
	venafiInterval := time.Duration(cfg.Export.Venafi.PushIntervalMinutes) * time.Minute
	router := api.NewRouter(st, cfg.Server.FrontendURL, cfg.PCAP.InputDir, cfg.PCAP.MaxFileSizeMB, cfg.Export.Venafi.Enabled, venafiInterval)
```

- [ ] **Step 4: Verify compilation**

```bash
cd /Users/Erik/projects/cipherflag && go build ./...
```

- [ ] **Step 5: Commit**

```bash
git add internal/api/handler/venafi.go internal/api/server.go cmd/cipherflag/main.go
git commit -m "feat(api): add Venafi status endpoint and wire config to router"
```

---

## Task 7: Start Pusher in main.go

**Files:**
- Modify: `cmd/cipherflag/main.go`

- [ ] **Step 1: Add the Venafi pusher startup to runServe**

Add the import for the venafi package:

```go
	"github.com/net4n6-dev/cipherflag/internal/export/venafi"
```

Add this block after the Zeek poller startup (after the `if cfg.Sources.ZeekFile.Enabled` block), before the router creation:

```go
	// Venafi push scheduler
	if cfg.Export.Venafi.Enabled {
		pushCtx, pushCancel := context.WithCancel(ctx)
		defer pushCancel()

		authBase := cfg.Export.Venafi.BaseURL
		sdkBase := cfg.Export.Venafi.BaseURL
		// Venafi uses /vedauth for auth and /vedsdk for API
		// If base_url includes /vedsdk, derive auth URL; otherwise construct both
		if len(authBase) > 6 && authBase[len(authBase)-6:] == "vedsdk" {
			authBase = authBase[:len(authBase)-6] + "vedauth"
		} else {
			sdkBase = authBase + "/vedsdk"
			authBase = authBase + "/vedauth"
		}

		venafiClient := venafi.NewClient(sdkBase, authBase, cfg.Export.Venafi.ClientID, cfg.Export.Venafi.RefreshToken)
		pusher := venafi.NewPusher(venafiClient, st, cfg.Export.Venafi.Folder, venafiInterval)
		go pusher.Run(pushCtx)
		log.Info().
			Str("folder", cfg.Export.Venafi.Folder).
			Int("interval_min", cfg.Export.Venafi.PushIntervalMinutes).
			Msg("venafi push scheduler started")
	}
```

Note: The `venafiInterval` variable was already defined in Task 6 Step 3.

- [ ] **Step 2: Verify full compilation**

```bash
cd /Users/Erik/projects/cipherflag && go build ./...
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add cmd/cipherflag/main.go
git commit -m "feat: start Venafi push scheduler in serve command"
```

---

## Task 8: Integration Verification

**Files:** None (verification only)

- [ ] **Step 1: Verify Go build**

```bash
cd /Users/Erik/projects/cipherflag && go build ./...
```

Expected: Clean compile.

- [ ] **Step 2: Run migration**

```bash
cd /Users/Erik/projects/cipherflag && bin/cipherflag migrate
```

Expected: "migrations applied successfully" (004_venafi_push.sql applied).

- [ ] **Step 3: Test status endpoint**

```bash
curl -s http://localhost:8443/api/v1/venafi/status | python3 -m json.tool
```

Expected: JSON with `enabled`, `pending`, `pushed`, `failed`, `dead_lettered` fields.

- [ ] **Step 4: Verify pusher doesn't start when disabled**

Check server logs — with `venafi.enabled = false` in config, the pusher should not appear in logs.

- [ ] **Step 5: Final commit if needed**

```bash
git status
```
