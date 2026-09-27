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

package static

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/ingest/ct"
	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

const defaultInterval = time.Hour

// Store mirrors crtsh.Store — internal/ingest/ct/crtsh/poller.go.
type Store interface {
	GetIngestionState(ctx context.Context, sourceName string) (*model.IngestionState, error)
	SetIngestionState(ctx context.Context, state *model.IngestionState) error
}

// Poller drives the ct_static polling cycle across every configured domain.
type Poller struct {
	ingester   ingest.Ingester
	store      Store
	httpClient *http.Client
	cfg        config.CtStaticSourceConfig
	interval   time.Duration
}

func NewPoller(ing ingest.Ingester, st Store, httpClient *http.Client, cfg config.CtStaticSourceConfig) *Poller {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 90 * time.Second}
	}
	return &Poller{ingester: ing, store: st, httpClient: httpClient, cfg: cfg, interval: defaultInterval}
}

func (p *Poller) Run(ctx context.Context) {
	p.runOneCycleSafely(ctx)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("ct_static poller stopped")
			return
		case <-ticker.C:
			p.runOneCycleSafely(ctx)
		}
	}
}

func (p *Poller) runOneCycleSafely(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("ct_static poller panic recovered")
		}
	}()
	if err := p.runCycle(ctx); err != nil {
		log.Error().Err(err).Msg("ct_static cycle failed")
	}
}

// runCycle polls every enabled configured domain independently — one
// domain's failure logs and continues rather than aborting the cycle,
// mirroring crtsh's multi-domain isolation.
func (p *Poller) runCycle(ctx context.Context) error {
	for _, d := range p.cfg.Domains {
		if !d.Enabled {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := p.pollDomain(ctx, d); err != nil {
			log.Error().Err(err).Str("domain", d.Domain).Msg("ct_static: domain cycle failed, continuing")
		}
	}
	return nil
}

func (p *Poller) pollDomain(ctx context.Context, d config.CtStaticDomainConfig) error {
	sourceName := fmt.Sprintf("ct_static:%s", d.Domain)

	var lastTreeSize uint64
	if p.store != nil {
		state, err := p.store.GetIngestionState(ctx, sourceName)
		if err != nil {
			return fmt.Errorf("get ingestion state: %w", err)
		}
		if state != nil && state.Cursor != "" {
			v, perr := strconv.ParseUint(state.Cursor, 10, 64)
			if perr != nil {
				log.Warn().Err(perr).Str("source", sourceName).Msg("ct_static: malformed cursor, resetting tree size")
			} else {
				lastTreeSize = v
			}
		}
	}

	prov := &Provider{
		Cfg: Config{
			Domain:       d.Domain,
			LogURL:       d.LogURL,
			PublicKeyPEM: d.PublicKeyPEM,
			Cache:        &Cache{LastTreeSize: lastTreeSize},
		},
		HTTPClient: p.httpClient,
	}
	entries, err := prov.QueryDomain(ctx, d.Domain)
	if err != nil {
		return fmt.Errorf("query domain %s: %w", d.Domain, err)
	}

	certs := make([]dedup.CertDiscovery, 0, len(entries))
	var parseFailures int
	for _, e := range entries {
		if len(e.PEM) == 0 {
			parseFailures++
			continue
		}
		certs = append(certs, dedup.CertDiscovery{
			Source:            "ct_static",
			StoreType:         "ct_log",
			FingerprintSHA256: e.Fingerprint,
			SubjectCN:         e.CommonName,
			IssuerCN:          e.IssuerName,
			NotBefore:         e.NotBefore,
			NotAfter:          e.NotAfter,
			SubjectAltNames:   splitSANs(e.NameValue),
			RawPEM:            string(e.PEM),
			FilePath:          fmt.Sprintf("ct_static:%s", e.Fingerprint),
		})
	}

	// Empty result is a normal ok cycle, not an error (Review Focus).
	if len(certs) > 0 {
		dr := &ingest.DiscoveryResult{
			Source:             "ct_static",
			SkipHostResolution: true,
			Certificates:       certs,
			Timestamp:          time.Now().UTC(),
		}
		if _, ierr := p.ingester.Ingest(ctx, dr); ierr != nil {
			return fmt.Errorf("ingest: %w", ierr)
		}
	}

	// Persist new tree size only after successful ingest, and only if it
	// actually advanced — mirrors EE's persistCache no-op-on-zero guard.
	if p.store != nil && prov.LastSeenTreeSize > 0 {
		newState := &model.IngestionState{
			SourceName: sourceName,
			Cursor:     strconv.FormatUint(prov.LastSeenTreeSize, 10),
			UpdatedAt:  time.Now().UTC(),
		}
		if err := p.store.SetIngestionState(ctx, newState); err != nil {
			log.Warn().Err(err).Str("source", sourceName).Msg("ct_static: failed to persist cursor")
		}
	}
	log.Info().Str("domain", d.Domain).Int("certs", len(certs)).Int("parse_failures", parseFailures).
		Uint64("tree_size", prov.LastSeenTreeSize).Msg("ct_static: domain cycle complete")
	return nil
}

func splitSANs(nameValue string) []string {
	if nameValue == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i <= len(nameValue); i++ {
		if i == len(nameValue) || nameValue[i] == '\n' {
			if s := nameValue[start:i]; s != "" {
				out = append(out, s)
			}
			start = i + 1
		}
	}
	return out
}

var _ ct.Provider = (*Provider)(nil) // sanity: Provider (ported in Step 3) still satisfies ct.Provider
