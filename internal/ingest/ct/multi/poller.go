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

	entries, _ := composer.QueryDomain(ctx, composer.Domain) // never returns error

	byChild := make(map[string][]ct.CTEntry)
	for _, e := range entries {
		byChild[e.Source] = append(byChild[e.Source], e)
	}

	for childSource, childEntries := range byChild {
		certs := make([]dedup.CertDiscovery, 0, len(childEntries))
		for _, e := range childEntries {
			certs = append(certs, dedup.CertDiscovery{
				Source:            childSource,
				StoreType:         "ct_log",
				FingerprintSHA256: e.Fingerprint,
				SubjectCN:         e.CommonName,
				IssuerCN:          e.IssuerName,
				NotBefore:         e.NotBefore,
				NotAfter:          e.NotAfter,
				SubjectAltNames:   splitSANs(e.NameValue),
				RawPEM:            string(e.PEM),
				FilePath:          fmt.Sprintf("%s:%s", childSource, e.Fingerprint),
			})
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
	log.Info().Str("domain", domain).Int("children", len(byChild)).Int("entries", len(entries)).Msg("ct_multi: group cycle complete")
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
