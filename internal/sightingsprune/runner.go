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

// Package sightingsprune runs the retention loop for host_ip_sightings.
//
// Ingest records a sighting for every (host, IP, source) it observes, and
// nothing else in CE deletes them, so without this loop the table grows for
// as long as the server runs. One Runner is started from `cipherflag
// serve`. On start it runs a single prune pass (so a restart after a long
// outage cannot leave the table over its retention bound), then ticks at
// an interval (24h in serve). Each pass deletes sightings whose last_seen
// is strictly before now - retainDays (default 7).
//
// Resilience contract:
//
//   - Prune errors are logged and swallowed. Retention is housekeeping; a
//     transient database outage that breaks one pass is corrected by the
//     next, and the affected sightings live one interval longer.
//   - retainDays <= 0 disables pruning (opt-out for operators who want
//     unbounded retention).
//   - Run returns when ctx is cancelled.
//
// Ported from CipherFlag EE (internal/sightingsprune); CE has no
// user_ip_sightings table, so only host_ip_sightings is pruned.
package sightingsprune

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
)

// Store is the narrow interface the runner needs.
type Store interface {
	PruneHostIPSightings(ctx context.Context, cutoff time.Time) (int64, error)
}

// DefaultRetainDays is the sighting retention serve uses. Nothing in CE
// reads sightings older than this.
const DefaultRetainDays = 7

// Runner deletes sightings older than retainDays on a fixed interval.
type Runner struct {
	store      Store
	interval   time.Duration
	retainDays int
	// now is injected by tests that need deterministic cutoff math; nil
	// in production means time.Now.
	now func() time.Time
}

// NewRunner constructs a Runner with the default 7-day retention. An
// interval <= 0 disables the ticker: Run returns after the startup prune.
func NewRunner(s Store, interval time.Duration) *Runner {
	return &Runner{store: s, interval: interval, retainDays: DefaultRetainDays}
}

// WithRetention overrides the 7-day default. Zero or negative disables
// pruning entirely.
func (r *Runner) WithRetention(days int) *Runner {
	r.retainDays = days
	return r
}

// WithClock overrides the clock used for cutoff math (tests only).
func (r *Runner) WithClock(now func() time.Time) *Runner {
	r.now = now
	return r
}

// Run prunes once on start, then at every interval until ctx is cancelled.
func (r *Runner) Run(ctx context.Context) {
	r.Prune(ctx)

	if r.interval <= 0 {
		log.Info().Msg("sightingsprune runner: interval <= 0; startup prune done, no ticker")
		return
	}

	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.Prune(ctx)
		}
	}
}

// Prune is a single retention pass.
func (r *Runner) Prune(ctx context.Context) {
	if r.retainDays <= 0 {
		return
	}
	cutoff := r.clock().Add(-time.Duration(r.retainDays) * 24 * time.Hour)
	deleted, err := r.store.PruneHostIPSightings(ctx, cutoff)
	if err != nil {
		log.Warn().Err(err).
			Int("retain_days", r.retainDays).
			Msg("host_ip_sightings prune failed; will retry next tick")
		return
	}
	if deleted > 0 {
		log.Info().
			Int64("deleted", deleted).
			Int("retain_days", r.retainDays).
			Time("cutoff", cutoff).
			Msg("host_ip_sightings retention applied")
	}
}

func (r *Runner) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}
