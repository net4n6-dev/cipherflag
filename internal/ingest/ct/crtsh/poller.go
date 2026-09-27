// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crtsh

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/certparse"
	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/ingest/ct"
	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

// defaultInterval matches every other CE poller's fallback (tanium/poller.go:41).
const defaultInterval = time.Hour

// Store is the subset of CryptoStore the poller uses — mirrors
// tanium/poller.go:35-40.
type Store interface {
	GetIngestionState(ctx context.Context, sourceName string) (*model.IngestionState, error)
	SetIngestionState(ctx context.Context, state *model.IngestionState) error
}

// Poller drives the ct_crtsh polling cycle across every configured domain.
type Poller struct {
	client   *Client
	ingester ingest.Ingester
	store    Store
	cfg      config.CtCrtshSourceConfig
	interval time.Duration

	// overrides is non-nil only under test; production uses the crt.sh
	// production URL and 1s inter-PEM gap.
	overrides *pollerOverrides
}

type pollerOverrides struct {
	client *Client
	pemGap time.Duration
}

// NewPoller constructs a Poller. client may be nil in production; a
// per-domain production Client is built lazily by crtshClient().
func NewPoller(client *Client, ing ingest.Ingester, st Store, cfg config.CtCrtshSourceConfig) *Poller {
	return &Poller{client: client, ingester: ing, store: st, cfg: cfg, interval: defaultInterval}
}

func (p *Poller) crtshClient() *Client {
	if p.overrides != nil && p.overrides.client != nil {
		return p.overrides.client
	}
	if p.client != nil {
		return p.client
	}
	return &Client{
		BaseURL:    "https://crt.sh",
		HTTPClient: &http.Client{Timeout: 2 * time.Minute},
	}
}

func (p *Poller) pemGap() time.Duration {
	if p.overrides != nil && p.overrides.pemGap > 0 {
		return p.overrides.pemGap
	}
	return 1 * time.Second
}

// Run executes runOneCycleSafely on a ticker until ctx is cancelled.
// Matches internal/ingest/tanium/poller.go:71-87.
func (p *Poller) Run(ctx context.Context) {
	p.runOneCycleSafely(ctx)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("ct_crtsh poller stopped")
			return
		case <-ticker.C:
			p.runOneCycleSafely(ctx)
		}
	}
}

func (p *Poller) runOneCycleSafely(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("ct_crtsh poller panic recovered")
		}
	}()
	if err := p.runCycle(ctx); err != nil {
		log.Error().Err(err).Msg("ct_crtsh cycle failed")
	}
}

// runCycle polls every enabled configured domain independently — one
// domain's failure logs and continues rather than aborting the cycle
// (Review Focus: multi-domain isolation).
func (p *Poller) runCycle(ctx context.Context) error {
	for _, d := range p.cfg.Domains {
		if !d.Enabled {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := p.pollDomain(ctx, d); err != nil {
			log.Error().Err(err).Str("domain", d.Domain).Msg("ct_crtsh: domain cycle failed, continuing")
		}
	}
	return nil
}

func (p *Poller) pollDomain(ctx context.Context, d config.CtDomainConfig) error {
	sourceName := fmt.Sprintf("ct_crtsh:%s", d.Domain)

	seen := map[int64]struct{}{}
	if p.store != nil {
		state, err := p.store.GetIngestionState(ctx, sourceName)
		if err != nil {
			return fmt.Errorf("get ingestion state: %w", err)
		}
		if state != nil && state.Cursor != "" {
			var ids []int64
			// A malformed persisted cursor must not panic the cycle
			// (Review Focus: malformed checkpoint) — log and start fresh.
			if err := json.Unmarshal([]byte(state.Cursor), &ids); err != nil {
				log.Warn().Err(err).Str("source", sourceName).Msg("ct_crtsh: malformed cursor, resetting seen-set")
			} else {
				for _, id := range ids {
					seen[id] = struct{}{}
				}
			}
		}
	}

	client := p.crtshClient()
	p.waitForDomainGate()

	entries, err := client.QueryDomain(ctx, d.Domain, d.IncludeSubdomains)
	if err != nil {
		return fmt.Errorf("query domain %s: %w", d.Domain, err)
	}

	scanTime := time.Now().UTC()
	var certs []dedup.CertDiscovery
	for _, e := range entries {
		if _, already := seen[e.ID]; already {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		pemStr, ferr := client.FetchPEM(ctx, e.ID)
		if ferr != nil {
			log.Warn().Err(ferr).Int64("crtsh_id", e.ID).Str("domain", d.Domain).Msg("ct_crtsh: PEM fetch failed; skipping")
			seen[e.ID] = struct{}{}
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(p.pemGap()):
		}
		parsed, perr := parsePEM(pemStr)
		if perr != nil {
			log.Warn().Err(perr).Int64("crtsh_id", e.ID).Msg("ct_crtsh: PEM parse failed; skipping")
			seen[e.ID] = struct{}{}
			continue
		}
		certs = append(certs, dedup.CertDiscovery{
			Source:             "ct_crtsh",
			StoreType:          "ct_log",
			FingerprintSHA256:  parsed.FingerprintSHA256,
			SubjectCN:          parsed.Subject.CommonName,
			IssuerCN:           parsed.Issuer.CommonName,
			SerialNumber:       parsed.SerialNumber,
			NotBefore:          parsed.NotBefore,
			NotAfter:           parsed.NotAfter,
			KeyAlgorithm:       string(parsed.KeyAlgorithm),
			KeySizeBits:        parsed.KeySizeBits,
			SignatureAlgorithm: string(parsed.SignatureAlgorithm),
			SubjectAltNames:    parsed.SubjectAltNames,
			IsCA:               parsed.IsCA,
			RawPEM:             pemStr,
			FilePath:           fmt.Sprintf("crtsh:%d", e.ID),
			RawMetadata: map[string]any{
				"crtsh_id":     e.ID,
				"crtsh_issuer": e.IssuerName,
			},
		})
		seen[e.ID] = struct{}{}
	}

	// Empty result is a normal ok cycle, not an error (Review Focus).
	if len(certs) > 0 {
		dr := &ingest.DiscoveryResult{
			Source:             "ct_crtsh",
			SkipHostResolution: true,
			Certificates:       certs,
			Timestamp:          scanTime,
		}
		if _, ierr := p.ingester.Ingest(ctx, dr); ierr != nil {
			return fmt.Errorf("ingest: %w", ierr)
		}
	}

	if p.store != nil {
		ids := make([]int64, 0, len(seen))
		for id := range seen {
			ids = append(ids, id)
		}
		cursorJSON, merr := json.Marshal(ids)
		if merr != nil {
			return fmt.Errorf("marshal cursor: %w", merr)
		}
		newState := &model.IngestionState{
			SourceName: sourceName,
			Cursor:     string(cursorJSON),
			UpdatedAt:  time.Now().UTC(),
		}
		if err := p.store.SetIngestionState(ctx, newState); err != nil {
			log.Warn().Err(err).Str("source", sourceName).Msg("ct_crtsh: failed to persist cursor")
		}
	}
	log.Info().Str("domain", d.Domain).Int("certs", len(certs)).Msg("ct_crtsh: domain cycle complete")
	return nil
}

// waitForDomainGate calls the shared throttle unless a test override
// disables it (production only; tests skip so the suite stays fast).
func (p *Poller) waitForDomainGate() {
	if p.overrides == nil {
		ct.WaitForDomainGate()
	}
}

func parsePEM(s string) (*model.Certificate, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(s)))
	if block == nil {
		return nil, fmt.Errorf("ct_crtsh: no PEM block in body")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("ct_crtsh: PEM type = %q, want CERTIFICATE", block.Type)
	}
	return certparse.ParseDER(block.Bytes)
}
