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
package sentinelone

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
	SourceName             = "sentinelone"
	SourceNameAppInventory = "sentinelone:app_inventory"
	SourceNameRSO          = "sentinelone:rso"
)

// Default intervals when config leaves them at zero.
const (
	defaultAppInventoryInterval = time.Hour
	defaultRSOInterval          = 24 * time.Hour
	defaultAppInventoryBackfill = 24 * time.Hour
)

// Sentinel errors returned by NewPoller for unsupported v1 config values.
var (
	ErrUnsupportedRSOTrigger = errors.New("sentinelone: rso.trigger must be \"scheduled\" (v1)")
	ErrUnsupportedRSOTarget  = errors.New("sentinelone: rso.target must be \"all\" (v1)")
)

// Store is the subset of CryptoStore the poller uses. Defined as an
// interface for testability.
type Store interface {
	GetIngestionState(ctx context.Context, sourceName string) (*model.IngestionState, error)
	SetIngestionState(ctx context.Context, state *model.IngestionState) error
}

// Poller drives SentinelOne App Inventory and RSO cycles.
type Poller struct {
	client   APIClient
	ingester ingest.Ingester
	store    Store
	cfg      config.SentinelOneSourceConfig

	appInterval time.Duration
	rsoInterval time.Duration

	// authDisabled is set to 1 after the first 401/403 response from
	// SentinelOne. Both cycles short-circuit while it's set — the operator
	// must rotate the token and restart the process to re-enable.
	authDisabled atomic.Bool
}

// NewPoller constructs a Poller and validates v1-supported config values.
func NewPoller(client APIClient, ing ingest.Ingester, st Store, cfg config.SentinelOneSourceConfig) (*Poller, error) {
	if cfg.RSO.Enabled {
		if cfg.RSO.Trigger != "" && cfg.RSO.Trigger != "scheduled" {
			return nil, ErrUnsupportedRSOTrigger
		}
		if cfg.RSO.Target != "" && cfg.RSO.Target != "all" {
			return nil, ErrUnsupportedRSOTarget
		}
	}

	appInterval := time.Duration(cfg.AppInventory.PollIntervalSeconds) * time.Second
	if appInterval <= 0 {
		appInterval = defaultAppInventoryInterval
	}
	rsoInterval := time.Duration(cfg.RSO.PollIntervalSeconds) * time.Second
	if rsoInterval <= 0 {
		rsoInterval = defaultRSOInterval
	}

	return &Poller{
		client:      client,
		ingester:    ing,
		store:       st,
		cfg:         cfg,
		appInterval: appInterval,
		rsoInterval: rsoInterval,
	}, nil
}

// isAuthDisabled returns true once a 401/403 has disabled the adapter.
func (p *Poller) isAuthDisabled() bool {
	return p.authDisabled.Load()
}

// markAuthDisabled flips the flag and logs a one-time error.
func (p *Poller) markAuthDisabled(source string, err error) {
	if p.authDisabled.CompareAndSwap(false, true) {
		log.Error().Err(err).Str("source", source).Msg("sentinelone: auth failure disables adapter until process restart — rotate API token")
	}
}

// Run starts the App Inventory and RSO cycles as independent tickers until
// ctx is cancelled. App Inventory and RSO cycles are gated on their
// respective Enabled flags.
func (p *Poller) Run(ctx context.Context) {
	if p.cfg.AppInventory.Enabled {
		go p.runAppInventoryLoop(ctx)
	}
	if p.cfg.RSO.Enabled {
		go p.runRSOLoop(ctx)
	}
	<-ctx.Done()
	log.Info().Msg("sentinelone poller stopped")
}

func (p *Poller) runAppInventoryLoop(ctx context.Context) {
	p.safeAppInventoryCycle(ctx)
	t := time.NewTicker(p.appInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.safeAppInventoryCycle(ctx)
		}
	}
}

func (p *Poller) runRSOLoop(ctx context.Context) {
	p.safeRSOCycle(ctx)
	t := time.NewTicker(p.rsoInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.safeRSOCycle(ctx)
		}
	}
}

func (p *Poller) safeAppInventoryCycle(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("sentinelone app-inventory cycle panic recovered")
		}
	}()
	if err := p.runAppInventoryCycle(ctx); err != nil {
		log.Error().Err(err).Msg("sentinelone app-inventory cycle failed")
	}
}

func (p *Poller) safeRSOCycle(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("sentinelone rso cycle panic recovered")
		}
	}()
	if err := p.runRSOCycle(ctx); err != nil {
		log.Error().Err(err).Msg("sentinelone rso cycle failed")
	}
}

// runAppInventoryCycle performs one App Inventory poll cycle: read cursor,
// query SentinelOne for crypto libraries, group by agent, ingest per-agent
// DiscoveryResults, advance cursor on success.
//
// Rate-limited responses skip cursor advance and return nil so the next
// cycle retries. Other query errors skip cursor advance and return the error
// so the caller logs it.
func (p *Poller) runAppInventoryCycle(ctx context.Context) error {
	if p.isAuthDisabled() {
		return nil
	}

	since, err := p.readAppInventoryCursor(ctx)
	if err != nil {
		return err
	}

	cycleStart := time.Now().UTC()
	apps, err := p.client.ListInstalledApplications(ctx, since, CryptoLibFilters())
	if err != nil {
		var rl *RateLimitError
		if errors.As(err, &rl) {
			log.Warn().Dur("retry_after", rl.RetryAfter).Msg("sentinelone app-inventory: rate limited, will retry next cycle")
			return nil
		}
		var ae *AuthError
		if errors.As(err, &ae) {
			p.markAuthDisabled("app_inventory", err)
			return nil
		}
		return err
	}

	for agentUUID, records := range GroupAppsByAgent(apps) {
		if err := p.ingestAppInventoryAgent(ctx, agentUUID, records); err != nil {
			log.Warn().Err(err).Str("agent_uuid", agentUUID).Msg("sentinelone app-inventory: per-agent ingest failed, continuing")
		}
	}

	newState := &model.IngestionState{
		SourceName: SourceNameAppInventory,
		Cursor:     cycleStart.Format(time.RFC3339Nano),
		UpdatedAt:  time.Now().UTC(),
	}
	if err := p.store.SetIngestionState(ctx, newState); err != nil {
		log.Warn().Err(err).Msg("sentinelone app-inventory: failed to persist cursor (next cycle may overlap, dedup handles)")
	}
	log.Info().Int("apps", len(apps)).Msg("sentinelone app-inventory: cycle complete")
	return nil
}

func (p *Poller) ingestAppInventoryAgent(ctx context.Context, agentUUID string, records []AppRecord) error {
	if len(records) == 0 {
		return nil
	}
	meta := ExtractAgentMetadata(records[0])
	libs := make([]dedup.LibraryDiscovery, 0, len(records))
	for _, rec := range records {
		disc, err := MapAppRecord(rec)
		if err != nil {
			log.Warn().Err(err).Str("agent_uuid", agentUUID).Msg("sentinelone app-inventory: skipping malformed record")
			continue
		}
		libs = append(libs, disc)
	}
	if len(libs) == 0 {
		return nil
	}
	result := &ingest.DiscoveryResult{
		Source:       SourceName,
		SourceHostID: meta.AgentUUID,
		Hostname:     meta.AgentName,
		OSFamily:     meta.OSFamily,
		Timestamp:    time.Now().UTC(),
		Libraries:    libs,
	}
	_, err := p.ingester.Ingest(ctx, result)
	return err
}

func (p *Poller) readAppInventoryCursor(ctx context.Context) (time.Time, error) {
	state, err := p.store.GetIngestionState(ctx, SourceNameAppInventory)
	if err != nil {
		return time.Time{}, err
	}
	if state == nil || state.Cursor == "" {
		return time.Now().UTC().Add(-defaultAppInventoryBackfill), nil
	}
	t, err := time.Parse(time.RFC3339Nano, state.Cursor)
	if err != nil {
		if t2, err2 := time.Parse(time.RFC3339, state.Cursor); err2 == nil {
			return t2.UTC(), nil
		}
		log.Warn().Err(err).Str("cursor", state.Cursor).Msg("sentinelone: corrupt app-inventory cursor, falling back to default backfill")
		return time.Now().UTC().Add(-defaultAppInventoryBackfill), nil
	}
	return t.UTC(), nil
}

// runRSOCycle progresses the RSO state machine.
//
// Behaviour:
//   - If no active tasks AND (LastLaunchAt is zero OR rsoInterval has elapsed
//     since LastLaunchAt), launch all configured scripts with target=all,
//     record their parent task IDs in the cursor, persist, and return.
//   - If active tasks exist, poll each one's status. Running/pending tasks
//     remain. Completed tasks have their NDJSON output fetched, parsed via
//     MapRSOOutput, and ingested; then removed from the cursor.
//     Failed/expired tasks are logged and removed.
//   - Persist the updated cursor at the end.
func (p *Poller) runRSOCycle(ctx context.Context) error {
	if p.isAuthDisabled() {
		return nil
	}

	stateRow, err := p.store.GetIngestionState(ctx, SourceNameRSO)
	if err != nil {
		return err
	}
	raw := ""
	if stateRow != nil {
		raw = stateRow.Cursor
	}
	cursor, err := UnmarshalRSOCursor(raw)
	if err != nil {
		log.Warn().Err(err).Str("cursor", raw).Msg("sentinelone rso: corrupt cursor, resetting")
		cursor = &RSOCursor{}
	}

	if len(cursor.ActiveTasks) == 0 {
		if cursor.LastLaunchAt.IsZero() || time.Since(cursor.LastLaunchAt) >= p.rsoInterval {
			p.launchAllRSOScripts(ctx, cursor)
			return p.persistRSOCursor(ctx, cursor)
		}
		return nil // nothing to do this tick
	}

	p.progressActiveRSOTasks(ctx, cursor)
	return p.persistRSOCursor(ctx, cursor)
}

func (p *Poller) launchAllRSOScripts(ctx context.Context, cursor *RSOCursor) {
	scripts := p.configuredRSOScripts()
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, s := range scripts {
		if s.scriptID == "" {
			continue
		}
		s := s // capture
		wg.Add(1)
		go func() {
			defer wg.Done()
			taskID, err := p.client.ExecuteRemoteScript(ctx, s.scriptID, "all")
			if err != nil {
				var rl *RateLimitError
				if errors.As(err, &rl) {
					log.Warn().Str("script_id", s.scriptID).Dur("retry_after", rl.RetryAfter).Msg("sentinelone rso: rate limited on launch, will retry next cycle")
					return
				}
				var ae *AuthError
				if errors.As(err, &ae) {
					p.markAuthDisabled("rso_launch", err)
					return
				}
				log.Warn().Err(err).Str("script_id", s.scriptID).Msg("sentinelone rso: launch failed")
				return
			}
			mu.Lock()
			cursor.ActiveTasks = append(cursor.ActiveTasks, RSOActiveTask{
				ScriptID:   s.scriptID,
				TaskID:     taskID,
				LaunchedAt: time.Now().UTC(),
			})
			mu.Unlock()
			log.Info().Str("script_id", s.scriptID).Str("task_id", taskID).Msg("sentinelone rso: launched")
		}()
	}
	wg.Wait()
	cursor.LastLaunchAt = time.Now().UTC()
}

func (p *Poller) progressActiveRSOTasks(ctx context.Context, cursor *RSOCursor) {
	// Copy for iteration — we mutate cursor.ActiveTasks via Remove.
	tasks := append([]RSOActiveTask(nil), cursor.ActiveTasks...)
	for _, t := range tasks {
		status, err := p.client.GetRemoteScriptStatus(ctx, t.TaskID)
		if err != nil {
			var rl *RateLimitError
			if errors.As(err, &rl) {
				log.Warn().Str("task_id", t.TaskID).Dur("retry_after", rl.RetryAfter).Msg("sentinelone rso: rate limited on status, will retry next cycle")
				continue
			}
			var ae *AuthError
			if errors.As(err, &ae) {
				p.markAuthDisabled("rso_status", err)
				return
			}
			log.Warn().Err(err).Str("task_id", t.TaskID).Msg("sentinelone rso: status query failed, keeping task active")
			continue
		}
		switch status.State {
		case TaskStateRunning, TaskStatePending:
			// keep active
		case TaskStateCompleted:
			if err := p.ingestRSOResults(ctx, t); err != nil {
				log.Warn().Err(err).Str("task_id", t.TaskID).Msg("sentinelone rso: result ingest failed, task will be retried next cycle")
				continue
			}
			cursor.Remove(t.TaskID)
		case TaskStateFailed, TaskStateExpired:
			log.Warn().Str("task_id", t.TaskID).Str("state", string(status.State)).Str("detail", status.Detail).Msg("sentinelone rso: task ended without results, dropping")
			cursor.Remove(t.TaskID)
		default:
			log.Warn().Str("task_id", t.TaskID).Str("state", string(status.State)).Msg("sentinelone rso: unexpected task state, keeping active")
		}
	}
}

func (p *Poller) ingestRSOResults(ctx context.Context, t RSOActiveTask) error {
	rc, err := p.client.GetRemoteScriptResults(ctx, t.TaskID)
	if err != nil {
		var ae *AuthError
		if errors.As(err, &ae) {
			p.markAuthDisabled("rso_results", err)
		}
		return err
	}
	defer rc.Close()

	parsed, parseErrs, err := MapRSOOutput(rc, SourceName, "")
	if err != nil {
		return err
	}
	for _, pe := range parseErrs {
		log.Warn().Int("line", pe.Line).Str("reason", pe.Reason).Str("task_id", t.TaskID).Msg("sentinelone rso: skipped malformed NDJSON line")
	}

	// RSO aggregates output from many agents. Per-agent split via NDJSON
	// embedded fields is a Future Enhancement; for v1 we ingest as one
	// result keyed by the task ID and let ResolveHost fan out via hostname
	// when scripts include it.
	parsed.SourceHostID = t.TaskID
	parsed.Timestamp = time.Now().UTC()
	if _, err := p.ingester.Ingest(ctx, parsed); err != nil {
		return err
	}
	return nil
}

func (p *Poller) persistRSOCursor(ctx context.Context, cursor *RSOCursor) error {
	raw, err := cursor.Marshal()
	if err != nil {
		return err
	}
	return p.store.SetIngestionState(ctx, &model.IngestionState{
		SourceName: SourceNameRSO,
		Cursor:     raw,
		UpdatedAt:  time.Now().UTC(),
	})
}

type rsoScript struct {
	name     string
	scriptID string
}

func (p *Poller) configuredRSOScripts() []rsoScript {
	return []rsoScript{
		{"certificates", p.cfg.RSO.CertScriptID},
		{"ssh_keys", p.cfg.RSO.SSHKeysScriptID},
		{"libraries", p.cfg.RSO.LibrariesScriptID},
		{"config_files", p.cfg.RSO.ConfigFilesScriptID},
		{"cert_files", p.cfg.RSO.CertFilesScriptID},
	}
}
