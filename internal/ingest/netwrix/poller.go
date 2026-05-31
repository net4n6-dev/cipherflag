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
package netwrix

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

// SourceName is the cursor key used by the poller in ingestion_state.
const SourceName = "netwrix:ad_cs"

// Defaults for the poller.
const (
	defaultPollInterval = 5 * time.Minute
	defaultBackfill     = 24 * time.Hour
)

// Cert-related Activity Record fields the poller asks Netwrix to filter on.
var (
	defaultDataSource  = "Active Directory"
	defaultObjectTypes = []string{"Certificate", "Certificate Template"}
	defaultActions     = []string{"Added", "Removed", "Renewed", "Revoked"}
)

// Store is the subset of CryptoStore used by the poller. Defined as an
// interface for testability.
type Store interface {
	BatchRecordADCSEvents(ctx context.Context, events []*model.ADCSEvent) error
	GetIngestionState(ctx context.Context, sourceName string) (*model.IngestionState, error)
	SetIngestionState(ctx context.Context, state *model.IngestionState) error
}

// Poller drives Netwrix polling cycles.
type Poller struct {
	client APIClient
	store  Store
	cfg    config.NetwrixSourceConfig

	interval time.Duration
}

// NewPoller constructs a Poller with the configured interval (default 5 min).
func NewPoller(client APIClient, st Store, cfg config.NetwrixSourceConfig) *Poller {
	return newPoller(client, st, cfg)
}

func newPoller(client APIClient, st Store, cfg config.NetwrixSourceConfig) *Poller {
	interval := time.Duration(cfg.PollIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = defaultPollInterval
	}
	return &Poller{
		client:   client,
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
			log.Info().Msg("netwrix poller stopped")
			return
		case <-ticker.C:
			p.runOneCycleSafely(ctx)
		}
	}
}

func (p *Poller) runOneCycleSafely(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("netwrix poller panic recovered")
		}
	}()

	if err := p.runCycle(ctx); err != nil {
		log.Error().Err(err).Msg("netwrix cycle failed")
	}
}

// runCycle performs a single poll cycle: read cursor, search Netwrix, map
// records, batch insert, advance cursor.
func (p *Poller) runCycle(ctx context.Context) error {
	// 1. Read cursor.
	since, err := p.readCursor(ctx)
	if err != nil {
		return fmt.Errorf("read cursor: %w", err)
	}

	// 2. Search Netwrix.
	records, err := p.client.SearchActivity(ctx, SearchFilter{
		Since:       since,
		DataSource:  defaultDataSource,
		ObjectTypes: defaultObjectTypes,
		Actions:     defaultActions,
	})
	if err != nil {
		return fmt.Errorf("netwrix search: %w", err)
	}

	if len(records) == 0 {
		return nil
	}

	// 3. Map records to ADCSEvents (skip malformed with warning).
	var events []*model.ADCSEvent
	var latestEventTime time.Time
	for _, rec := range records {
		event, mapErr := MapActivityRecord(rec)
		if mapErr != nil {
			log.Warn().Err(mapErr).Msg("skipping malformed netwrix activity record")
			continue
		}
		events = append(events, event)
		if event.EventTimestamp.After(latestEventTime) {
			latestEventTime = event.EventTimestamp
		}
	}

	if len(events) == 0 {
		return nil
	}

	// 4. Batch insert.
	if err := p.store.BatchRecordADCSEvents(ctx, events); err != nil {
		return fmt.Errorf("batch insert: %w", err)
	}

	// 5. Advance cursor (only on insert success).
	if !latestEventTime.IsZero() {
		newState := &model.IngestionState{
			SourceName: SourceName,
			Cursor:     latestEventTime.Add(1 * time.Nanosecond).UTC().Format(time.RFC3339Nano),
			UpdatedAt:  time.Now().UTC(),
		}
		if err := p.store.SetIngestionState(ctx, newState); err != nil {
			log.Warn().Err(err).Msg("netwrix: failed to persist cursor (events were ingested but next cycle may overlap)")
		}
	}

	log.Info().Int("count", len(events)).Msg("netwrix: ingested ad_cs events")
	return nil
}

// readCursor returns the timestamp from which to query Netwrix on this cycle.
// If no cursor exists, defaults to (now - defaultBackfill) so the first run
// doesn't replay long history.
func (p *Poller) readCursor(ctx context.Context) (time.Time, error) {
	state, err := p.store.GetIngestionState(ctx, SourceName)
	if err != nil {
		return time.Time{}, err
	}
	if state == nil || state.Cursor == "" {
		return time.Now().UTC().Add(-defaultBackfill), nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, state.Cursor)
	if err != nil {
		// Fall back to default backfill so a corrupt cursor doesn't block ingestion.
		log.Warn().Err(err).Str("cursor", state.Cursor).Msg("netwrix: corrupt cursor, falling back to default backfill")
		return time.Now().UTC().Add(-defaultBackfill), nil
	}
	return parsed.UTC(), nil
}
