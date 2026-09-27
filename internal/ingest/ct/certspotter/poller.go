// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certspotter

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/ingest/ct"
	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

const defaultInterval = time.Hour

// defaultBaseURL is the production SSLMate API root used when the poller
// lazily builds its own Client (client == nil — the normal production
// path from cmd/cipherflag/main.go). A var rather than a const only so
// tests can drive that exact production construction path against an
// httptest server.
var defaultBaseURL = "https://api.certspotter.com"

// Store mirrors crtsh.Store.
type Store interface {
	GetIngestionState(ctx context.Context, sourceName string) (*model.IngestionState, error)
	SetIngestionState(ctx context.Context, state *model.IngestionState) error
}

// Poller drives the ct_certspotter polling cycle across every configured
// domain. Unlike ct/static, which splits Provider/Poller into two types,
// Poller here satisfies both ct.Provider (Name/QueryDomain) and the local
// poll contract (Run) on one type — matching EE's certspotter/poller.go
// structure.
type Poller struct {
	client   *Client
	ingester ingest.Ingester
	store    Store
	cfg      config.CtCertspotterSourceConfig
	interval time.Duration
}

// Compile-time assertion that Poller satisfies ct.Provider — Task 5's
// ct_multi constructs *certspotter.Poller and puts it directly into a
// []ct.Provider slice. If a future refactor drops QueryDomain or Name,
// this fails the build here rather than at ct_multi's call site.
var _ ct.Provider = (*Poller)(nil)

// NewPoller constructs a Poller. client may be nil in production; a
// per-domain production Client is built lazily by certspotterClient().
func NewPoller(client *Client, ing ingest.Ingester, st Store, cfg config.CtCertspotterSourceConfig) *Poller {
	return &Poller{client: client, ingester: ing, store: st, cfg: cfg, interval: defaultInterval}
}

func (p *Poller) Name() string { return "certspotter" }

// QueryDomain implements ct.Provider for ct_multi's fan-out — stateless
// w.r.t. any per-domain cursor (matches EE's certspotter/poller.go:60-76).
func (p *Poller) QueryDomain(ctx context.Context, domain string) ([]ct.CTEntry, error) {
	client := p.client
	if client == nil {
		client = p.certspotterClient(domain, "")
	}
	issuances, _, err := client.QueryDomainAll(ctx, domain, true, "")
	if err != nil {
		return nil, fmt.Errorf("certspotter: QueryDomain(%s): %w", domain, err)
	}
	out := make([]ct.CTEntry, 0, len(issuances))
	for _, iss := range issuances {
		e, err := issuanceToCTEntry(iss)
		if err != nil {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func (p *Poller) certspotterClient(domain string, apiToken string) *Client {
	if p.client != nil {
		return p.client
	}
	return &Client{
		BaseURL:  defaultBaseURL,
		APIToken: apiToken,
		Limiter:  NewRateLimiter(DefaultRequestsPerHour),
	}
}

func (p *Poller) Run(ctx context.Context) {
	p.runOneCycleSafely(ctx)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("ct_certspotter poller stopped")
			return
		case <-ticker.C:
			p.runOneCycleSafely(ctx)
		}
	}
}

func (p *Poller) runOneCycleSafely(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("ct_certspotter poller panic recovered")
		}
	}()
	if err := p.runCycle(ctx); err != nil {
		log.Error().Err(err).Msg("ct_certspotter cycle failed")
	}
}

func (p *Poller) runCycle(ctx context.Context) error {
	for _, d := range p.cfg.Domains {
		if !d.Enabled {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := p.pollDomain(ctx, d); err != nil {
			log.Error().Err(err).Str("domain", d.Domain).Msg("ct_certspotter: domain cycle failed, continuing")
		}
	}
	return nil
}

func (p *Poller) pollDomain(ctx context.Context, d config.CtCertspotterDomainConfig) error {
	sourceName := fmt.Sprintf("ct_certspotter:%s", d.Domain)

	var cursor string
	if p.store != nil {
		state, err := p.store.GetIngestionState(ctx, sourceName)
		if err != nil {
			return fmt.Errorf("get ingestion state: %w", err)
		}
		if state != nil {
			cursor = state.Cursor // bare string; nothing to unmarshal, so no malformed-JSON case here
		}
	}

	requestsPerHour := d.RequestsPerHour
	if requestsPerHour == 0 {
		requestsPerHour = DefaultRequestsPerHour
	}
	client := p.client
	if client == nil {
		// HTTP deliberately left nil: Client.httpClient() supplies the
		// default, so this path cannot reintroduce the nil-client panic.
		client = &Client{BaseURL: defaultBaseURL, APIToken: d.APIToken, Limiter: NewRateLimiter(requestsPerHour)}
	} else if client.Limiter == nil {
		client.Limiter = NewRateLimiter(requestsPerHour)
	}

	issuances, newCursor, err := client.QueryDomainAll(ctx, d.Domain, d.IncludeSubdomains, cursor)
	if err != nil {
		return fmt.Errorf("query domain %s: %w", d.Domain, err)
	}

	// Empty result is a normal ok cycle, not an error (Review Focus).
	if len(issuances) == 0 {
		return nil
	}

	certs := make([]dedup.CertDiscovery, 0, len(issuances))
	for _, iss := range issuances {
		e, cerr := issuanceToCTEntry(iss)
		if cerr != nil {
			continue
		}
		certs = append(certs, dedup.CertDiscovery{
			Source:            "ct_certspotter",
			StoreType:         "ct_log",
			FingerprintSHA256: e.Fingerprint,
			SubjectCN:         e.CommonName,
			IssuerCN:          e.IssuerName,
			NotBefore:         e.NotBefore,
			NotAfter:          e.NotAfter,
			SubjectAltNames:   splitSANs(e.NameValue),
			RawPEM:            string(e.PEM),
			FilePath:          fmt.Sprintf("ct_certspotter:%s", e.Fingerprint),
		})
	}
	if len(certs) > 0 {
		dr := &ingest.DiscoveryResult{
			Source:             "ct_certspotter",
			SkipHostResolution: true,
			Certificates:       certs,
		}
		if _, err := p.ingester.Ingest(ctx, dr); err != nil {
			return fmt.Errorf("ingest: %w", err)
		}
	}

	if p.store != nil {
		newState := &model.IngestionState{SourceName: sourceName, Cursor: newCursor, UpdatedAt: time.Now().UTC()}
		if err := p.store.SetIngestionState(ctx, newState); err != nil {
			log.Warn().Err(err).Str("source", sourceName).Msg("ct_certspotter: failed to persist cursor")
		}
	}
	log.Info().Str("domain", d.Domain).Int("certs", len(certs)).Msg("ct_certspotter: domain cycle complete")
	return nil
}

func splitSANs(nameValue string) []string {
	if nameValue == "" {
		return nil
	}
	parts := strings.Split(nameValue, "\n")
	out := parts[:0]
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func issuanceToCTEntry(iss Issuance) (ct.CTEntry, error) {
	der, err := base64.StdEncoding.DecodeString(iss.Cert.Data)
	if err != nil {
		return ct.CTEntry{}, fmt.Errorf("certspotter: decode cert.data: %w", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return ct.CTEntry{}, fmt.Errorf("certspotter: parse cert: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return ct.CTEntry{
		Fingerprint: strings.ToLower(iss.CertSHA256),
		PEM:         pemBytes,
		CommonName:  parsed.Subject.CommonName,
		NameValue:   strings.Join(iss.DNSNames, "\n"),
		IssuerName:  iss.Issuer.Name,
		NotBefore:   iss.NotBefore,
		NotAfter:    iss.NotAfter,
		Source:      "ct_certspotter",
	}, nil
}
