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
package defender

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

// SourceName is the cursor key used by the poller in ingestion_state.
const SourceName = "defender:libraries"

// Defaults for the poller.
const (
	defaultPollInterval = 6 * time.Hour
	defaultBackfill     = 24 * time.Hour
)

// kqlTemplate is the Advanced Hunting query template. The {since} placeholder
// is replaced with the cursor timestamp on each cycle.
//
// Keep the has_any list in sync with mapper.go's defenderToLibraryName map.
const kqlTemplate = `DeviceTvmSoftwareInventory
| where SoftwareName has_any (
    "openssl", "libssl", "libssl3", "libssl1.1",
    "gnutls", "libgnutls",
    "nss", "libnss",
    "libgcrypt",
    "libsodium",
    "wolfssl",
    "bouncycastle", "bouncy castle",
    "libressl",
    "mbedtls",
    "nettle"
)
| where Timestamp > datetime({since})
| project DeviceId, DeviceName, OSPlatform, OSVersion,
          SoftwareName, SoftwareVendor, SoftwareVersion, Timestamp
| limit 100000`

// Store is the subset of CryptoStore used by the poller. Defined as an
// interface for testability.
type Store interface {
	GetIngestionState(ctx context.Context, sourceName string) (*model.IngestionState, error)
	SetIngestionState(ctx context.Context, state *model.IngestionState) error
}

// Poller drives Defender polling cycles.
type Poller struct {
	client   APIClient
	ingester ingest.Ingester
	store    Store
	cfg      config.DefenderSourceConfig
	interval time.Duration
}

// NewPoller constructs a Poller with the configured interval (default 6h).
func NewPoller(client APIClient, ing ingest.Ingester, st Store, cfg config.DefenderSourceConfig) *Poller {
	return newPoller(client, ing, st, cfg)
}

func newPoller(client APIClient, ing ingest.Ingester, st Store, cfg config.DefenderSourceConfig) *Poller {
	interval := time.Duration(cfg.PollIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = defaultPollInterval
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
			log.Info().Msg("defender poller stopped")
			return
		case <-ticker.C:
			p.runOneCycleSafely(ctx)
		}
	}
}

func (p *Poller) runOneCycleSafely(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("defender poller panic recovered")
		}
	}()

	if err := p.runCycle(ctx); err != nil {
		log.Error().Err(err).Msg("defender cycle failed")
	}
}

// runCycle performs a single poll cycle: read cursor, build KQL, query
// Defender, group by device, ingest per-device DiscoveryResults, advance cursor.
//
// On rate-limit error, returns nil and skips cursor advance (next cycle retries).
// On query error, returns the error and skips cursor advance.
// On per-device ingest error, logs warning but advances cursor (single-device
// failures don't block forward progress; dedup handles re-ingest).
func (p *Poller) runCycle(ctx context.Context) error {
	since, err := p.readCursor(ctx)
	if err != nil {
		return fmt.Errorf("read cursor: %w", err)
	}

	kql := strings.Replace(kqlTemplate, "{since}", since.UTC().Format(time.RFC3339Nano), 1)

	cycleStart := time.Now().UTC()
	rows, err := p.client.RunAdvancedQuery(ctx, kql)
	if err != nil {
		var rl *RateLimitError
		if errors.As(err, &rl) {
			log.Warn().Dur("retry_after", rl.RetryAfter).Msg("defender: rate limited, will retry next cycle")
			return nil
		}
		return fmt.Errorf("defender query: %w", err)
	}

	if len(rows) > 0 {
		groups := GroupRowsByDevice(rows)
		for deviceID, deviceRows := range groups {
			if err := p.ingestDevice(ctx, deviceID, deviceRows); err != nil {
				log.Warn().Err(err).Str("device_id", deviceID).Msg("defender: per-device ingest failed, continuing")
			}
		}
	}

	// Advance cursor on successful query (regardless of per-device ingest results).
	newState := &model.IngestionState{
		SourceName: SourceName,
		Cursor:     cycleStart.Format(time.RFC3339Nano),
		UpdatedAt:  time.Now().UTC(),
	}
	if err := p.store.SetIngestionState(ctx, newState); err != nil {
		log.Warn().Err(err).Msg("defender: failed to persist cursor (next cycle may overlap, dedup handles)")
	}

	log.Info().Int("rows", len(rows)).Msg("defender: cycle complete")
	return nil
}

// ingestDevice builds a DiscoveryResult for one device and feeds it through
// the UnifiedIngester.
func (p *Poller) ingestDevice(ctx context.Context, deviceID string, rows []QueryRow) error {
	if len(rows) == 0 {
		return nil
	}

	// Per-device metadata is identical across rows for the same device - use the first.
	meta := ExtractDeviceMetadata(rows[0])

	libs := make([]dedup.LibraryDiscovery, 0, len(rows))
	for _, row := range rows {
		disc, err := MapRow(row)
		if err != nil {
			log.Warn().Err(err).Str("device_id", deviceID).Msg("defender: skipping malformed row")
			continue
		}
		libs = append(libs, disc)
	}
	if len(libs) == 0 {
		return nil
	}

	result := &ingest.DiscoveryResult{
		Source:       "defender",
		SourceHostID: meta.DeviceID,
		Hostname:     meta.DeviceName,
		OSFamily:     meta.OSFamily,
		Timestamp:    time.Now().UTC(),
		Libraries:    libs,
	}

	_, err := p.ingester.Ingest(ctx, result)
	return err
}

// readCursor returns the timestamp from which to query Defender on this cycle.
// If no cursor exists, defaults to (now - defaultBackfill).
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
		// Try plain RFC3339 too in case format drift.
		parsed, err = time.Parse(time.RFC3339, state.Cursor)
		if err != nil {
			log.Warn().Err(err).Str("cursor", state.Cursor).Msg("defender: corrupt cursor, falling back to default backfill")
			return time.Now().UTC().Add(-defaultBackfill), nil
		}
	}
	return parsed.UTC(), nil
}
