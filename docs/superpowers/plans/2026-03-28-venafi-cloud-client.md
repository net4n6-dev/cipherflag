# Venafi Cloud Client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Venafi Cloud (SaaS) support alongside the existing TPP client via a unified `VenafiClient` interface, so the push scheduler works with either platform.

**Architecture:** A `VenafiClient` interface with `ImportCertificates` and `ValidateConnection` methods. Two implementations: `CloudClient` (API key auth, `api.venafi.cloud`) and `TPPAdapter` (wraps existing OAuth2 client). The pusher is refactored to use the interface. Config adds `platform`, `api_key`, and `region` fields. `main.go` selects the right client based on config.

**Tech Stack:** Go 1.24, Venafi Cloud REST API, Venafi TPP REST API

**Spec:** `docs/superpowers/specs/2026-03-28-venafi-cloud-client-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `internal/export/venafi/interface.go` | Create | VenafiClient interface, CertImport, ImportResult types |
| `internal/export/venafi/cloud.go` | Create | Venafi Cloud client (API key auth, POST /outagedetection/v1/certificates) |
| `internal/export/venafi/tpp_adapter.go` | Create | TPP adapter wrapping existing Client to implement VenafiClient |
| `internal/export/venafi/pusher.go` | Modify | Use VenafiClient interface, remove buildDiscoveryPayload |
| `internal/config/config.go` | Modify | Add Platform, APIKey, Region fields to VenafiExportConfig |
| `config/cipherflag.toml` | Modify | Add cloud config options with comments |
| `cmd/cipherflag/main.go` | Modify | Client selection based on platform config |

---

## Task 1: VenafiClient Interface & Shared Types

**Files:**
- Create: `internal/export/venafi/interface.go`

- [ ] **Step 1: Create interface.go**

```go
package venafi

import "context"

// VenafiClient is the interface for importing certificates into Venafi (Cloud or TPP).
type VenafiClient interface {
	// ImportCertificates imports a batch of certificates. Returns aggregate results.
	ImportCertificates(ctx context.Context, certs []CertImport) (*ImportResult, error)
	// ValidateConnection checks that credentials are valid.
	ValidateConnection(ctx context.Context) error
}

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

- [ ] **Step 2: Verify compilation**

```bash
cd /Users/Erik/projects/cipherflag && go build ./internal/export/venafi/...
```

Expected: PASS (interface and types compile standalone).

- [ ] **Step 3: Commit**

```bash
git add internal/export/venafi/interface.go
git commit -m "feat(venafi): add VenafiClient interface and shared import types"
```

---

## Task 2: Venafi Cloud Client

**Files:**
- Create: `internal/export/venafi/cloud.go`

- [ ] **Step 1: Create cloud.go**

```go
package venafi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// CloudClient is a Venafi Cloud (TLS Protect Cloud) REST API client.
type CloudClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewCloudClient creates a new Venafi Cloud client.
// region should be "us" or "eu".
func NewCloudClient(region, apiKey string) *CloudClient {
	baseURL := "https://api.venafi.cloud"
	if strings.EqualFold(region, "eu") {
		baseURL = "https://api.venafi.eu"
	}
	return &CloudClient{
		baseURL:    baseURL,
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

// cloudImportRequest is the request body for POST /outagedetection/v1/certificates.
type cloudImportRequest struct {
	Certificates []cloudCertEntry `json:"certificates"`
}

type cloudCertEntry struct {
	Certificate          string                `json:"certificate"`
	APIClientInformation *cloudAPIClientInfo   `json:"apiClientInformation,omitempty"`
}

type cloudAPIClientInfo struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

// cloudImportResponse is the response from POST /outagedetection/v1/certificates.
type cloudImportResponse struct {
	CertificateInformations []cloudCertInfo `json:"certificateInformations"`
	Statistics              cloudStats      `json:"statistics"`
}

type cloudCertInfo struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
}

type cloudStats struct {
	Imported int `json:"imported"`
	Existed  int `json:"existed"`
	Ignored  int `json:"ignored"`
	Failed   int `json:"failed"`
}

// ImportCertificates imports a batch of certificates into Venafi Cloud.
func (c *CloudClient) ImportCertificates(ctx context.Context, certs []CertImport) (*ImportResult, error) {
	entries := make([]cloudCertEntry, 0, len(certs))
	for _, cert := range certs {
		// Strip PEM headers/footers and newlines, base64-encode raw DER
		pemClean := stripPEMHeaders(cert.PEM)
		entry := cloudCertEntry{
			Certificate: pemClean,
		}
		// Add source metadata if we have observation data
		if cert.ServerIP != "" || cert.ServerName != "" {
			identifier := cert.ServerName
			if identifier == "" {
				identifier = cert.ServerIP
			}
			entry.APIClientInformation = &cloudAPIClientInfo{
				Type:       "CipherFlag",
				Identifier: identifier,
			}
		}
		entries = append(entries, entry)
	}

	reqBody := cloudImportRequest{Certificates: entries}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("venafi cloud: marshalling import request: %w", err)
	}

	url := c.baseURL + "/outagedetection/v1/certificates"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("venafi cloud: creating import request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("tppl-api-key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("venafi cloud: import request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("venafi cloud: invalid API key (401 Unauthorized)")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("venafi cloud: import returned status %d", resp.StatusCode)
	}

	var cloudResp cloudImportResponse
	if err := json.NewDecoder(resp.Body).Decode(&cloudResp); err != nil {
		return nil, fmt.Errorf("venafi cloud: decoding import response: %w", err)
	}

	return &ImportResult{
		Imported: cloudResp.Statistics.Imported,
		Existed:  cloudResp.Statistics.Existed,
		Failed:   cloudResp.Statistics.Failed,
	}, nil
}

// ValidateConnection checks that the API key is valid by making a lightweight API call.
func (c *CloudClient) ValidateConnection(ctx context.Context) error {
	url := c.baseURL + "/outagedetection/v1/certificates?limit=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("venafi cloud: creating validation request: %w", err)
	}

	req.Header.Set("tppl-api-key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("venafi cloud: connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("venafi cloud: invalid API key")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("venafi cloud: validation returned status %d", resp.StatusCode)
	}

	return nil
}

// stripPEMHeaders removes PEM header/footer lines and newlines,
// returning just the base64-encoded certificate data.
func stripPEMHeaders(pem string) string {
	lines := strings.Split(pem, "\n")
	var b64Lines []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		b64Lines = append(b64Lines, line)
	}
	result := strings.Join(b64Lines, "")
	// Verify it's valid base64 — if not, encode the whole PEM
	if _, err := base64.StdEncoding.DecodeString(result); err != nil {
		return base64.StdEncoding.EncodeToString([]byte(pem))
	}
	return result
}
```

- [ ] **Step 2: Verify compilation**

```bash
cd /Users/Erik/projects/cipherflag && go build ./internal/export/venafi/...
```

- [ ] **Step 3: Commit**

```bash
git add internal/export/venafi/cloud.go
git commit -m "feat(venafi): add Venafi Cloud client with API key auth and batch import"
```

---

## Task 3: TPP Adapter

**Files:**
- Create: `internal/export/venafi/tpp_adapter.go`

- [ ] **Step 1: Create tpp_adapter.go**

This wraps the existing `*Client` (TPP) to implement the `VenafiClient` interface. It maps `[]CertImport` to the TPP-specific `DiscoveryImportRequest` format.

```go
package venafi

import (
	"context"
	"encoding/base64"
	"fmt"
)

// TPPAdapter wraps the existing TPP Client to implement VenafiClient.
type TPPAdapter struct {
	client *Client
	folder string
}

// NewTPPAdapter creates a VenafiClient adapter for TPP.
func NewTPPAdapter(client *Client, folder string) *TPPAdapter {
	return &TPPAdapter{client: client, folder: folder}
}

// ImportCertificates imports certificates into TPP via the Discovery/Import endpoint.
func (a *TPPAdapter) ImportCertificates(ctx context.Context, certs []CertImport) (*ImportResult, error) {
	request := &DiscoveryImportRequest{
		ZoneName:  a.folder,
		Endpoints: make([]DiscoveryEndpoint, 0, len(certs)),
	}

	for _, cert := range certs {
		encoded := base64.StdEncoding.EncodeToString([]byte(cert.PEM))

		endpoint := DiscoveryEndpoint{
			Certificates: []DiscoveryCert{
				{
					Certificate: encoded,
					Fingerprint: cert.Fingerprint,
				},
			},
		}

		if cert.ServerIP != "" || cert.ServerName != "" {
			endpoint.Host = cert.ServerName
			if endpoint.Host == "" {
				endpoint.Host = cert.ServerIP
			}
			endpoint.IP = cert.ServerIP
			endpoint.Port = cert.ServerPort
			if cert.TLSVersion != "" {
				endpoint.Protocols = []DiscoveryProto{
					{
						Certificates: []string{cert.Fingerprint},
						Protocol:     cert.TLSVersion,
					},
				}
			}
		}

		request.Endpoints = append(request.Endpoints, endpoint)
	}

	resp, err := a.client.ImportDiscovery(ctx, request)
	if err != nil {
		return nil, err
	}

	return &ImportResult{
		Imported: resp.CreatedCertificates,
		Updated:  resp.UpdatedCertificates,
		Warnings: resp.Warnings,
	}, nil
}

// ValidateConnection checks that TPP credentials are valid by attempting a token refresh.
func (a *TPPAdapter) ValidateConnection(ctx context.Context) error {
	_, err := a.client.getToken(ctx)
	if err != nil {
		return fmt.Errorf("venafi tpp: %w", err)
	}
	return nil
}
```

- [ ] **Step 2: Verify compilation**

```bash
cd /Users/Erik/projects/cipherflag && go build ./internal/export/venafi/...
```

- [ ] **Step 3: Commit**

```bash
git add internal/export/venafi/tpp_adapter.go
git commit -m "feat(venafi): add TPP adapter implementing VenafiClient interface"
```

---

## Task 4: Refactor Pusher to Use VenafiClient Interface

**Files:**
- Modify: `internal/export/venafi/pusher.go`

- [ ] **Step 1: Replace pusher.go with interface-based version**

The pusher currently uses `*Client` directly and has `buildDiscoveryPayload`. Replace with `VenafiClient` and build `[]CertImport` instead.

Replace the entire file content:

```go
package venafi

import (
	"context"
	"time"

	"github.com/rs/zerolog"

	"github.com/cyberflag-ai/cipherflag/internal/model"
	"github.com/cyberflag-ai/cipherflag/internal/store"
)

const pushBatchSize = 100

// Pusher periodically pushes new certificates to Venafi (Cloud or TPP).
type Pusher struct {
	client   VenafiClient
	store    store.CertStore
	interval time.Duration
	logger   zerolog.Logger
}

// NewPusher creates a new Venafi push scheduler.
func NewPusher(client VenafiClient, st store.CertStore, interval time.Duration) *Pusher {
	return &Pusher{
		client:   client,
		store:    st,
		interval: interval,
		logger:   zerolog.New(zerolog.NewConsoleWriter()).With().Str("component", "venafi-pusher").Timestamp().Logger(),
	}
}

// Run starts the push loop. Blocks until ctx is cancelled.
func (p *Pusher) Run(ctx context.Context) {
	p.logger.Info().Dur("interval", p.interval).Msg("venafi push scheduler started")

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
			fps := fingerprints(certs)
			if markErr := p.store.MarkVenafiPushFailure(ctx, fps); markErr != nil {
				p.logger.Error().Err(markErr).Msg("failed to mark push failures")
			}
			return
		}

		if len(certs) < pushBatchSize {
			break
		}
	}

	if total > 0 {
		p.logger.Info().Int("pushed", total).Msg("venafi push cycle complete")
	}
}

func (p *Pusher) pushBatch(ctx context.Context, certs []model.Certificate) (int, error) {
	fps := fingerprints(certs)

	observations, err := p.store.GetLatestObservationsForCerts(ctx, fps)
	if err != nil {
		p.logger.Warn().Err(err).Msg("failed to get observations, pushing without endpoint metadata")
		observations = map[string]*model.CertificateObservation{}
	}

	imports := buildCertImports(certs, observations)

	result, err := p.client.ImportCertificates(ctx, imports)
	if err != nil {
		return 0, err
	}

	for _, w := range result.Warnings {
		p.logger.Warn().Str("warning", w).Msg("venafi import warning")
	}

	if markErr := p.store.MarkVenafiPushSuccess(ctx, fps); markErr != nil {
		p.logger.Error().Err(markErr).Msg("failed to mark push success")
	}

	p.logger.Debug().
		Int("imported", result.Imported).
		Int("updated", result.Updated).
		Int("existed", result.Existed).
		Int("failed", result.Failed).
		Msg("batch pushed to venafi")

	return len(certs), nil
}

func buildCertImports(certs []model.Certificate, observations map[string]*model.CertificateObservation) []CertImport {
	imports := make([]CertImport, 0, len(certs))
	for _, cert := range certs {
		ci := CertImport{
			PEM:         cert.RawPEM,
			Fingerprint: cert.FingerprintSHA256,
		}
		if obs, ok := observations[cert.FingerprintSHA256]; ok {
			ci.ServerName = obs.ServerName
			ci.ServerIP = obs.ServerIP
			ci.ServerPort = obs.ServerPort
			ci.TLSVersion = string(obs.NegotiatedVersion)
		}
		imports = append(imports, ci)
	}
	return imports
}

func fingerprints(certs []model.Certificate) []string {
	fps := make([]string, len(certs))
	for i, c := range certs {
		fps[i] = c.FingerprintSHA256
	}
	return fps
}
```

- [ ] **Step 2: Verify compilation**

```bash
cd /Users/Erik/projects/cipherflag && go build ./internal/export/venafi/...
```

Expected: PASS — pusher now uses `VenafiClient` interface.

Note: `cmd/cipherflag/main.go` will temporarily fail to compile because it still calls `NewPusher` with the old signature. This is fixed in Task 6.

- [ ] **Step 3: Commit**

```bash
git add internal/export/venafi/pusher.go
git commit -m "refactor(venafi): pusher uses VenafiClient interface instead of *Client"
```

---

## Task 5: Config Changes

**Files:**
- Modify: `internal/config/config.go`
- Modify: `config/cipherflag.toml`

- [ ] **Step 1: Add Platform, APIKey, Region fields to config.go**

Update the `VenafiExportConfig` struct:

```go
type VenafiExportConfig struct {
	Enabled             bool   `toml:"enabled"`
	Platform            string `toml:"platform"`              // "cloud" or "tpp"
	// Cloud settings
	APIKey              string `toml:"api_key"`
	Region              string `toml:"region"`                // "us" or "eu"
	// TPP settings
	BaseURL             string `toml:"base_url"`
	ClientID            string `toml:"client_id"`
	RefreshToken        string `toml:"refresh_token"`
	// Common
	Folder              string `toml:"folder"`
	PushIntervalMinutes int    `toml:"push_interval_minutes"`
}
```

Add defaults in the `Load` function, after the existing Venafi defaults:

```go
	if cfg.Export.Venafi.Platform == "" {
		cfg.Export.Venafi.Platform = "cloud"
	}
	if cfg.Export.Venafi.Region == "" {
		cfg.Export.Venafi.Region = "us"
	}
```

- [ ] **Step 2: Update config/cipherflag.toml**

Replace the `[export.venafi]` section:

```toml
[export.venafi]
enabled = false
platform = "cloud"              # "cloud" (Venafi TLS Protect Cloud) or "tpp" (on-prem TPP)

# Cloud settings (when platform = "cloud")
api_key = ""                    # Venafi Cloud API key (from Preferences > API Keys)
region = "us"                   # "us" (api.venafi.cloud) or "eu" (api.venafi.eu)

# TPP settings (when platform = "tpp")
base_url = ""                   # e.g., https://tpp.example.com
client_id = ""                  # OAuth2 client ID
refresh_token = ""              # OAuth2 refresh token
folder = "\\VED\\Policy\\Discovered\\CipherFlag"

# Push schedule
push_interval_minutes = 60
```

- [ ] **Step 3: Verify compilation**

```bash
cd /Users/Erik/projects/cipherflag && go build ./internal/config/...
```

- [ ] **Step 4: Commit**

```bash
git add internal/config/config.go config/cipherflag.toml
git commit -m "feat(config): add Venafi Cloud platform, api_key, and region settings"
```

---

## Task 6: Wire Client Selection in main.go

**Files:**
- Modify: `cmd/cipherflag/main.go`

- [ ] **Step 1: Replace the Venafi startup block**

Find the existing Venafi push scheduler block in `runServe` (lines ~83-105) and replace it with platform-aware client selection:

```go
	// Venafi push scheduler
	venafiInterval := time.Duration(cfg.Export.Venafi.PushIntervalMinutes) * time.Minute
	if cfg.Export.Venafi.Enabled {
		pushCtx, pushCancel := context.WithCancel(ctx)
		defer pushCancel()

		var venafiClient venafi.VenafiClient

		if cfg.Export.Venafi.Platform == "cloud" {
			venafiClient = venafi.NewCloudClient(cfg.Export.Venafi.Region, cfg.Export.Venafi.APIKey)
			log.Info().
				Str("platform", "cloud").
				Str("region", cfg.Export.Venafi.Region).
				Msg("venafi cloud client configured")
		} else {
			authBase := cfg.Export.Venafi.BaseURL
			sdkBase := cfg.Export.Venafi.BaseURL
			if len(authBase) > 6 && authBase[len(authBase)-6:] == "vedsdk" {
				authBase = authBase[:len(authBase)-6] + "vedauth"
			} else {
				sdkBase = authBase + "/vedsdk"
				authBase = authBase + "/vedauth"
			}
			tppClient := venafi.NewClient(sdkBase, authBase, cfg.Export.Venafi.ClientID, cfg.Export.Venafi.RefreshToken)
			venafiClient = venafi.NewTPPAdapter(tppClient, cfg.Export.Venafi.Folder)
			log.Info().
				Str("platform", "tpp").
				Str("base_url", cfg.Export.Venafi.BaseURL).
				Msg("venafi tpp client configured")
		}

		pusher := venafi.NewPusher(venafiClient, st, venafiInterval)
		go pusher.Run(pushCtx)
		log.Info().
			Int("interval_min", cfg.Export.Venafi.PushIntervalMinutes).
			Msg("venafi push scheduler started")
	}
```

Note: `NewPusher` now takes `VenafiClient` instead of `*Client`, and no longer takes `folder` (the folder is encapsulated in the TPPAdapter or not needed for Cloud).

- [ ] **Step 2: Verify full compilation**

```bash
cd /Users/Erik/projects/cipherflag && go build ./...
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add cmd/cipherflag/main.go
git commit -m "feat: wire Venafi Cloud/TPP client selection in serve command"
```

---

## Task 7: Integration Verification

**Files:** None (verification only)

- [ ] **Step 1: Verify full Go build**

```bash
cd /Users/Erik/projects/cipherflag && go build ./...
```

Expected: Clean compile.

- [ ] **Step 2: Verify server starts with cloud config**

```bash
cd /Users/Erik/projects/cipherflag && go build -o bin/cipherflag ./cmd/cipherflag && bin/cipherflag serve
```

Expected: Starts without errors. Venafi pusher does NOT start (enabled=false in config).

- [ ] **Step 3: Verify status endpoint still works**

```bash
curl -s http://localhost:8443/api/v1/venafi/status | python3 -m json.tool
```

Expected: JSON response with enabled=false.

- [ ] **Step 4: Final commit if needed**

```bash
git status
```
