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

package absolute

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

// Source names used as keys in the ingestion_state table.
const (
	SourceName          = "absolute"
	SourceNameInventory = "absolute:inventory"
	SourceNameReach     = "absolute:reach"
)

// Default intervals when config leaves them at zero.
const (
	defaultInventoryInterval = time.Hour
	defaultReachInterval     = 24 * time.Hour
	defaultInventoryBackfill = 24 * time.Hour
)

// Sentinel errors returned by NewPoller for unsupported v1 config values.
var (
	ErrUnsupportedReachTrigger = errors.New("absolute: reach.trigger must be \"scheduled\" (v1)")
	ErrUnsupportedReachTarget  = errors.New("absolute: reach.target must be \"all\" (v1)")
)

// Store is the subset of CryptoStore the poller uses.
type Store interface {
	GetIngestionState(ctx context.Context, sourceName string) (*model.IngestionState, error)
	SetIngestionState(ctx context.Context, state *model.IngestionState) error
}

// Poller drives Absolute Inventory and Reach cycles.
type Poller struct {
	client   APIClient
	ingester ingest.Ingester
	store    Store
	cfg      config.AbsoluteSourceConfig

	inventoryInterval time.Duration
	reachInterval     time.Duration

	// authDisabled is set to true after the first 401/403.
	authDisabled atomic.Bool
}

// NewPoller constructs a Poller and validates v1-supported config values.
func NewPoller(client APIClient, ing ingest.Ingester, st Store, cfg config.AbsoluteSourceConfig) (*Poller, error) {
	if cfg.Reach.Enabled {
		if cfg.Reach.Trigger != "" && cfg.Reach.Trigger != "scheduled" {
			return nil, ErrUnsupportedReachTrigger
		}
		if cfg.Reach.Target != "" && cfg.Reach.Target != "all" {
			return nil, ErrUnsupportedReachTarget
		}
	}

	inventoryInterval := time.Duration(cfg.Inventory.PollIntervalSeconds) * time.Second
	if inventoryInterval <= 0 {
		inventoryInterval = defaultInventoryInterval
	}
	reachInterval := time.Duration(cfg.Reach.PollIntervalSeconds) * time.Second
	if reachInterval <= 0 {
		reachInterval = defaultReachInterval
	}

	return &Poller{
		client:            client,
		ingester:          ing,
		store:             st,
		cfg:               cfg,
		inventoryInterval: inventoryInterval,
		reachInterval:     reachInterval,
	}, nil
}

// Run starts the Inventory and Reach cycles as independent goroutines until
// ctx is cancelled. Each mode is gated on its respective Enabled flag.
func (p *Poller) Run(ctx context.Context) {
	if p.cfg.Inventory.Enabled {
		go p.runInventoryLoop(ctx)
	}
	if p.cfg.Reach.Enabled {
		go p.runReachLoop(ctx)
	}
	<-ctx.Done()
	log.Info().Msg("absolute poller stopped")
}

func (p *Poller) runInventoryLoop(ctx context.Context) {
	p.safeInventoryCycle(ctx)
	t := time.NewTicker(p.inventoryInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.safeInventoryCycle(ctx)
		}
	}
}

func (p *Poller) runReachLoop(ctx context.Context) {
	p.safeReachCycle(ctx)
	t := time.NewTicker(p.reachInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.safeReachCycle(ctx)
		}
	}
}

func (p *Poller) safeInventoryCycle(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("absolute inventory cycle panic recovered")
		}
	}()
	if err := p.runInventoryCycle(ctx); err != nil {
		log.Error().Err(err).Msg("absolute inventory cycle failed")
	}
}

func (p *Poller) safeReachCycle(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("absolute reach cycle panic recovered")
		}
	}()
	if err := p.runReachCycle(ctx); err != nil {
		log.Error().Err(err).Msg("absolute reach cycle failed")
	}
}

// isAuthDisabled returns true once a 401/403 has disabled the adapter.
func (p *Poller) isAuthDisabled() bool { return p.authDisabled.Load() }

// markAuthDisabled flips the flag and logs a one-time error.
func (p *Poller) markAuthDisabled(source string, err error) {
	if p.authDisabled.CompareAndSwap(false, true) {
		log.Error().Err(err).Str("source", source).Msg("absolute: auth failure disables adapter until process restart — rotate API token")
	}
}

// runInventoryCycle performs one Inventory poll cycle: read cursor, query
// Absolute for crypto libraries, group by device, ingest per-device
// DiscoveryResults, advance cursor on success.
//
// Rate-limited responses skip cursor advance and return nil so the next
// cycle retries. Auth errors disable the adapter. Other query errors
// propagate so the caller logs them.
func (p *Poller) runInventoryCycle(ctx context.Context) error {
	if p.isAuthDisabled() {
		return nil
	}

	since, err := p.readInventoryCursor(ctx)
	if err != nil {
		return err
	}

	cycleStart := time.Now().UTC()
	apps, err := p.client.ListInstalledApplications(ctx, since, CryptoLibFilters())
	if err != nil {
		var rl *RateLimitError
		if errors.As(err, &rl) {
			log.Warn().Dur("retry_after", rl.RetryAfter).Msg("absolute inventory: rate limited, will retry next cycle")
			return nil
		}
		var ae *AuthError
		if errors.As(err, &ae) {
			p.markAuthDisabled("inventory", err)
			return nil
		}
		return err
	}

	for deviceID, rows := range GroupAppsByDevice(apps) {
		if err := p.ingestInventoryDevice(ctx, deviceID, rows); err != nil {
			log.Warn().Err(err).Str("device_id", deviceID).Msg("absolute inventory: per-device ingest failed, continuing")
		}
	}

	newState := &model.IngestionState{
		SourceName: SourceNameInventory,
		Cursor:     cycleStart.Format(time.RFC3339Nano),
		UpdatedAt:  time.Now().UTC(),
	}
	if err := p.store.SetIngestionState(ctx, newState); err != nil {
		log.Warn().Err(err).Msg("absolute inventory: failed to persist cursor (next cycle may overlap, dedup handles)")
	}
	log.Info().Int("apps", len(apps)).Msg("absolute inventory: cycle complete")
	return nil
}

func (p *Poller) ingestInventoryDevice(ctx context.Context, deviceID string, rows []DeviceApp) error {
	if len(rows) == 0 {
		return nil
	}
	meta := ExtractDeviceMetadata(rows[0])
	libs := make([]dedup.LibraryDiscovery, 0, len(rows))
	for _, row := range rows {
		disc, err := MapDeviceApp(row)
		if err != nil {
			log.Warn().Err(err).Str("device_id", deviceID).Msg("absolute inventory: skipping malformed row")
			continue
		}
		libs = append(libs, disc)
	}
	if len(libs) == 0 {
		return nil
	}
	result := &ingest.DiscoveryResult{
		Source:       SourceName,
		SourceHostID: meta.DeviceID,
		Hostname:     meta.DeviceName,
		OSFamily:     meta.OSFamily,
		Timestamp:    time.Now().UTC(),
		Libraries:    libs,
	}
	_, err := p.ingester.Ingest(ctx, result)
	return err
}

func (p *Poller) readInventoryCursor(ctx context.Context) (time.Time, error) {
	state, err := p.store.GetIngestionState(ctx, SourceNameInventory)
	if err != nil {
		return time.Time{}, err
	}
	if state == nil || state.Cursor == "" {
		return time.Now().UTC().Add(-defaultInventoryBackfill), nil
	}
	t, err := time.Parse(time.RFC3339Nano, state.Cursor)
	if err != nil {
		if t2, err2 := time.Parse(time.RFC3339, state.Cursor); err2 == nil {
			return t2.UTC(), nil
		}
		log.Warn().Err(err).Str("cursor", state.Cursor).Msg("absolute: corrupt inventory cursor, falling back to default backfill")
		return time.Now().UTC().Add(-defaultInventoryBackfill), nil
	}
	return t.UTC(), nil
}

// runReachCycle progresses the Reach state machine.
//
// Behaviour:
//   - Short-circuit if auth-disabled.
//   - If no active executions AND (LastLaunchAt zero OR interval elapsed),
//     launch all configured scripts in parallel (goroutines + WaitGroup +
//     mutex-guarded append), record execution IDs, persist cursor, return.
//   - If active executions exist, iterate and progress each: Running /
//     Pending keep; Completed fetch results, parse NDJSON, ingest, remove;
//     Failed / Expired log and remove.
//   - Persist cursor at end.
func (p *Poller) runReachCycle(ctx context.Context) error {
	if p.isAuthDisabled() {
		return nil
	}

	stateRow, err := p.store.GetIngestionState(ctx, SourceNameReach)
	if err != nil {
		return err
	}
	raw := ""
	if stateRow != nil {
		raw = stateRow.Cursor
	}
	cursor, err := UnmarshalReachCursor(raw)
	if err != nil {
		log.Warn().Err(err).Str("cursor", raw).Msg("absolute reach: corrupt cursor, resetting")
		cursor = &ReachCursor{}
	}

	if len(cursor.ActiveExecutions) == 0 {
		if cursor.LastLaunchAt.IsZero() || time.Since(cursor.LastLaunchAt) >= p.reachInterval {
			p.launchAllReachScripts(ctx, cursor)
			return p.persistReachCursor(ctx, cursor)
		}
		return nil
	}

	p.progressActiveReachTasks(ctx, cursor)
	return p.persistReachCursor(ctx, cursor)
}

func (p *Poller) launchAllReachScripts(ctx context.Context, cursor *ReachCursor) {
	scripts := p.configuredReachScripts()
	var wg sync.WaitGroup
	var mu sync.Mutex
	launched := 0
	for _, s := range scripts {
		if s.scriptID == "" {
			continue
		}
		s := s
		wg.Add(1)
		go func() {
			defer wg.Done()
			executionID, err := p.client.ExecuteReachScript(ctx, s.scriptID, "all")
			if err != nil {
				var rl *RateLimitError
				if errors.As(err, &rl) {
					log.Warn().Str("script_id", s.scriptID).Dur("retry_after", rl.RetryAfter).Msg("absolute reach: rate limited on launch, will retry next cycle")
					return
				}
				var ae *AuthError
				if errors.As(err, &ae) {
					p.markAuthDisabled("reach_launch", err)
					return
				}
				log.Warn().Err(err).Str("script_id", s.scriptID).Msg("absolute reach: launch failed")
				return
			}
			mu.Lock()
			cursor.ActiveExecutions = append(cursor.ActiveExecutions, ReachActiveExecution{
				ScriptID:    s.scriptID,
				ExecutionID: executionID,
				LaunchedAt:  time.Now().UTC(),
			})
			launched++
			mu.Unlock()
			log.Info().Str("script_id", s.scriptID).Str("execution_id", executionID).Msg("absolute reach: launched")
		}()
	}
	wg.Wait()
	// Only mark LastLaunchAt on any successful launch so a cycle where
	// every launch failed (API down, auth rejected, etc.) retries on the
	// next tick instead of going dark for an entire reachInterval.
	if launched > 0 {
		cursor.LastLaunchAt = time.Now().UTC()
	}
}

func (p *Poller) progressActiveReachTasks(ctx context.Context, cursor *ReachCursor) {
	tasks := append([]ReachActiveExecution(nil), cursor.ActiveExecutions...)
	for _, t := range tasks {
		if err := ctx.Err(); err != nil {
			return
		}
		status, err := p.client.GetReachExecutionStatus(ctx, t.ExecutionID)
		if err != nil {
			var rl *RateLimitError
			if errors.As(err, &rl) {
				log.Warn().Str("execution_id", t.ExecutionID).Dur("retry_after", rl.RetryAfter).Msg("absolute reach: rate limited on status, will retry next cycle")
				continue
			}
			var ae *AuthError
			if errors.As(err, &ae) {
				p.markAuthDisabled("reach_status", err)
				return
			}
			log.Warn().Err(err).Str("execution_id", t.ExecutionID).Msg("absolute reach: status query failed, keeping task active")
			continue
		}
		switch status.State {
		case ReachTaskStateRunning, ReachTaskStatePending:
			// keep active
		case ReachTaskStateCompleted:
			if err := p.ingestReachResults(ctx, t); err != nil {
				var ae *AuthError
				if errors.As(err, &ae) {
					p.markAuthDisabled("reach_results", err)
					return
				}
				log.Warn().Err(err).Str("execution_id", t.ExecutionID).Msg("absolute reach: result ingest failed, task will be retried next cycle")
				continue
			}
			cursor.Remove(t.ExecutionID)
		case ReachTaskStateFailed, ReachTaskStateExpired:
			log.Warn().Str("execution_id", t.ExecutionID).Str("state", string(status.State)).Str("detail", status.Detail).Msg("absolute reach: task ended without results, dropping")
			cursor.Remove(t.ExecutionID)
		default:
			log.Warn().Str("execution_id", t.ExecutionID).Str("state", string(status.State)).Msg("absolute reach: unexpected task state, keeping active")
		}
	}
}

func (p *Poller) ingestReachResults(ctx context.Context, t ReachActiveExecution) error {
	rc, err := p.client.GetReachExecutionResults(ctx, t.ExecutionID)
	if err != nil {
		return err
	}
	defer rc.Close()

	parsed, parseErrs, err := MapReachOutput(rc, SourceName, "")
	if err != nil {
		return err
	}
	for _, pe := range parseErrs {
		log.Warn().Int("line", pe.Line).Str("reason", pe.Reason).Str("execution_id", t.ExecutionID).Msg("absolute reach: skipped malformed NDJSON line")
	}
	parsed.SourceHostID = t.ExecutionID
	parsed.Timestamp = time.Now().UTC()
	if _, err := p.ingester.Ingest(ctx, parsed); err != nil {
		return err
	}
	return nil
}

func (p *Poller) persistReachCursor(ctx context.Context, cursor *ReachCursor) error {
	raw, err := cursor.Marshal()
	if err != nil {
		return err
	}
	return p.store.SetIngestionState(ctx, &model.IngestionState{
		SourceName: SourceNameReach,
		Cursor:     raw,
		UpdatedAt:  time.Now().UTC(),
	})
}

type reachScript struct {
	name     string
	scriptID string
}

func (p *Poller) configuredReachScripts() []reachScript {
	return []reachScript{
		{"certificates", p.cfg.Reach.CertScriptID},
		{"ssh_keys", p.cfg.Reach.SSHKeysScriptID},
		{"libraries", p.cfg.Reach.LibrariesScriptID},
		{"configs", p.cfg.Reach.ConfigsScriptID},
	}
}
