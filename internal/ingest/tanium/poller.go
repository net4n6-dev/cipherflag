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
package tanium

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

// SourceName is the cursor key used by the poller in ingestion_state.
const SourceName = "tanium"

// defaultInterval is used when the configured poll interval is zero.
const defaultInterval = time.Hour

// Store is the subset of CryptoStore the poller uses. Defined as an
// interface for testability.
type Store interface {
	GetIngestionState(ctx context.Context, sourceName string) (*model.IngestionState, error)
	SetIngestionState(ctx context.Context, state *model.IngestionState) error
}

// Poller drives the Tanium polling cycle.
type Poller struct {
	client   APIClient
	ingester ingest.Ingester
	store    Store
	cfg      config.TaniumSourceConfig
	interval time.Duration

	// authDisabled is set to true after the first 401/403 response.
	// Both future cycles short-circuit while it's set — the operator must
	// rotate the token and restart the process to re-enable.
	authDisabled atomic.Bool
}

// NewPoller constructs a Poller with the configured interval (default 1h).
func NewPoller(client APIClient, ing ingest.Ingester, st Store, cfg config.TaniumSourceConfig) *Poller {
	interval := time.Duration(cfg.PollIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = defaultInterval
	}
	return &Poller{
		client:   client,
		ingester: ing,
		store:    st,
		cfg:      cfg,
		interval: interval,
	}
}

// Run executes runCycle on a ticker until ctx is cancelled.
func (p *Poller) Run(ctx context.Context) {
	p.runOneCycleSafely(ctx)

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("tanium poller stopped")
			return
		case <-ticker.C:
			p.runOneCycleSafely(ctx)
		}
	}
}

func (p *Poller) runOneCycleSafely(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("tanium poller panic recovered")
		}
	}()
	if err := p.runCycle(ctx); err != nil {
		log.Error().Err(err).Msg("tanium cycle failed")
	}
}

// isAuthDisabled returns true once a 401/403 has disabled the adapter.
func (p *Poller) isAuthDisabled() bool { return p.authDisabled.Load() }

// markAuthDisabled flips the flag and logs a one-time error.
func (p *Poller) markAuthDisabled(err error) {
	if p.authDisabled.CompareAndSwap(false, true) {
		log.Error().Err(err).Msg("tanium: auth failure disables adapter until process restart — rotate API token")
	}
}

// runCycle performs one poll cycle: iterate every page of the endpoints
// query, build a DiscoveryResult per endpoint, feed each through the
// UnifiedIngester, advance cursor on success.
//
// Rate-limit responses return nil and preserve the cursor.
// Auth errors disable the adapter and return nil.
// Other query errors propagate so the caller logs them.
// Per-endpoint ingest failures log a warning but do not block the cycle.
func (p *Poller) runCycle(ctx context.Context) error {
	if p.isAuthDisabled() {
		return nil
	}

	cycleStart := time.Now().UTC()
	after := ""
	totalEndpoints := 0

	for {
		page, err := p.client.ListEndpoints(ctx, after)
		if err != nil {
			var rl *RateLimitError
			if errors.As(err, &rl) {
				log.Warn().Dur("retry_after", rl.RetryAfter).Msg("tanium: rate limited, will retry next cycle")
				return nil
			}
			var ae *AuthError
			if errors.As(err, &ae) {
				p.markAuthDisabled(err)
				return nil
			}
			return err
		}

		for _, ep := range page.Endpoints {
			if err := ctx.Err(); err != nil {
				return err
			}
			result := BuildDiscoveryResult(ep)
			if _, err := p.ingester.Ingest(ctx, result); err != nil {
				log.Warn().Err(err).Str("endpoint_id", ep.EndpointID).Msg("tanium: per-endpoint ingest failed, continuing")
			}
		}
		totalEndpoints += len(page.Endpoints)

		if !page.HasNext || page.EndCursor == "" {
			break
		}
		after = page.EndCursor
	}

	newState := &model.IngestionState{
		SourceName: SourceName,
		Cursor:     cycleStart.Format(time.RFC3339Nano),
		UpdatedAt:  time.Now().UTC(),
	}
	if err := p.store.SetIngestionState(ctx, newState); err != nil {
		log.Warn().Err(err).Msg("tanium: failed to persist cursor (next cycle may overlap, dedup handles)")
	}
	log.Info().Int("endpoints", totalEndpoints).Msg("tanium: cycle complete")
	return nil
}
