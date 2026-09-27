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

package multi

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/ingest/ct"
	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
)

const defaultInterval = time.Hour

// Poller wraps a per-domain Composer with the CE Run/runCycle contract
// plus the load-bearing per-child Ingest dispatch (spec §"Multi-domain
// config"). One Poller drives every configured group; groups are built
// lazily on first use and cached by domain.
type Poller struct {
	Composer   map[string]*Composer // keyed by group domain; test seam — production leaves nil and lazy-builds
	Ingester   ingest.Ingester
	HTTPClient *http.Client
	cfg        config.CtMultiSourceConfig
	interval   time.Duration
}

func NewPoller(ing ingest.Ingester, httpClient *http.Client, cfg config.CtMultiSourceConfig) *Poller {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}
	return &Poller{Composer: map[string]*Composer{}, Ingester: ing, HTTPClient: httpClient, cfg: cfg, interval: defaultInterval}
}

func (p *Poller) Run(ctx context.Context) {
	p.runOneCycleSafely(ctx)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("ct_multi poller stopped")
			return
		case <-ticker.C:
			p.runOneCycleSafely(ctx)
		}
	}
}

func (p *Poller) runOneCycleSafely(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("ct_multi poller panic recovered")
		}
	}()
	for _, group := range p.cfg.Groups {
		if !group.Enabled {
			continue
		}
		if err := ctx.Err(); err != nil {
			return
		}
		if err := p.runCycle(ctx, group.Domain); err != nil {
			log.Error().Err(err).Str("domain", group.Domain).Msg("ct_multi: group cycle failed, continuing")
		}
	}
}

// runCycle fans out via the group's Composer, groups entries by their
// per-entry Source field (LOAD-BEARING — see spec's "Components" section
// on multi/poller.go), and issues one Ingest call per distinct child
// source so asset_provenance.source carries correct per-child attribution.
func (p *Poller) runCycle(ctx context.Context, domain string) error {
	composer := p.Composer[domain]
	if composer == nil {
		group, err := p.groupFor(domain)
		if err != nil {
			return err
		}
		children, err := buildChildren(group, p.HTTPClient)
		if err != nil {
			return err
		}
		composer = &Composer{Domain: domain, Children: children}
		p.Composer[domain] = composer
	}

	entries, err := composer.QueryDomain(ctx, composer.Domain)
	if err != nil {
		// Composer.QueryDomain is documented never to error (per-child
		// failures live in LastChildStatus); surface it if that changes.
		return fmt.Errorf("ct_multi: composer query: %w", err)
	}

	// Per-child failures are otherwise invisible (the composer unions
	// only the successful children), so surface each one, and escalate
	// when the whole group came back empty-handed because every child
	// failed (bad token, bad static key, provider outage, ...).
	failed := 0
	for _, st := range composer.LastChildStatus {
		if st.OK {
			continue
		}
		failed++
		log.Warn().
			Str("domain", domain).
			Str("child", st.Name).
			Str("error", st.Err).
			Dur("latency", st.Latency).
			Msg("ct_multi: child query failed")
	}
	if n := len(composer.LastChildStatus); n > 0 && failed == n {
		// Returned (not just logged) so runOneCycleSafely reports it at
		// Error level; there is nothing to ingest in this case anyway.
		return fmt.Errorf("ct_multi: all %d children failed for this cycle (see per-child warnings)", n)
	}

	byChild := make(map[string][]ct.CTEntry)
	for _, e := range entries {
		byChild[e.Source] = append(byChild[e.Source], e)
	}

	for childSource, childEntries := range byChild {
		certs := make([]dedup.CertDiscovery, 0, len(childEntries))
		for _, e := range childEntries {
			// Full parse via the shared helper so KeyAlgorithm/KeySizeBits/
			// SignatureAlgorithm/SerialNumber/IsCA reach the risk scorer.
			disc, derr := ct.BuildCertDiscovery(e, childSource, "ct_log")
			if derr != nil {
				log.Warn().Err(derr).Str("domain", domain).Str("child_source", childSource).Msg("ct_multi: cert parse failed; skipping")
				continue
			}
			disc.FilePath = fmt.Sprintf("%s:%s", childSource, disc.FingerprintSHA256)
			certs = append(certs, disc)
		}
		if len(certs) == 0 {
			continue
		}
		dr := &ingest.DiscoveryResult{
			Source:             childSource,
			SkipHostResolution: true,
			Certificates:       certs,
		}
		// Per-child ingest failure is logged but does not block other
		// children (Review Focus: multi-domain/multi-child isolation).
		if _, err := p.Ingester.Ingest(ctx, dr); err != nil {
			log.Warn().Err(err).Str("domain", domain).Str("child_source", childSource).Msg("ct_multi: per-child ingest failed")
		}
	}
	log.Info().Str("domain", domain).
		Int("children", len(composer.LastChildStatus)).
		Int("children_failed", failed).
		Int("sources_ingested", len(byChild)).
		Int("entries", len(entries)).
		Msg("ct_multi: group cycle complete")
	return nil
}

func (p *Poller) groupFor(domain string) (config.CtMultiGroupConfig, error) {
	for _, g := range p.cfg.Groups {
		if g.Domain == domain {
			return g, nil
		}
	}
	return config.CtMultiGroupConfig{}, fmt.Errorf("ct_multi: no configured group for domain %q", domain)
}
