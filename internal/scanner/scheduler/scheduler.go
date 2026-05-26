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

// Package scheduler enqueues scan_jobs rows whenever a repo's cron schedule
// fires. Uses robfig/cron parser for schedule evaluation but does not use
// cron.Cron — the lifecycle is simpler with a single polling loop over
// ListScheduledRepos.
package scheduler

import (
	"context"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

type Store interface {
	ListScheduledRepos(ctx context.Context) ([]model.Repository, error)
	EnqueueScanJob(ctx context.Context, j *model.ScanJob) error
	UpdateRepositoryLastScheduledAt(ctx context.Context, id string, when time.Time) error
	HasActiveScanJob(ctx context.Context, repoID string) (bool, error)
}

type Scheduler struct {
	Store    Store
	Interval time.Duration // how often RunOnce fires; default 30s
	Now      func() time.Time
}

var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

func (s *Scheduler) Run(ctx context.Context) {
	interval := s.Interval
	if interval == 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.RunOnce(ctx); err != nil {
				log.Warn().Err(err).Msg("scheduler runonce")
			}
		}
	}
}

// RunOnce lists all scheduled repos, computes their next-fire time from
// last_scheduled_at (or first_seen if never fired), and enqueues any that
// are due. Skips repos that already have a queued/running job.
func (s *Scheduler) RunOnce(ctx context.Context) error {
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	repos, err := s.Store.ListScheduledRepos(ctx)
	if err != nil {
		return err
	}
	for _, r := range repos {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		sched, err := cronParser.Parse(r.ScheduleCron)
		if err != nil {
			log.Warn().Str("repo_id", r.ID).Str("cron", r.ScheduleCron).Err(err).Msg("invalid cron; skipping")
			continue
		}
		anchor := r.FirstSeen
		if r.LastScheduledAt != nil {
			anchor = *r.LastScheduledAt
		}
		next := sched.Next(anchor)
		if next.After(now) {
			continue
		}
		active, err := s.Store.HasActiveScanJob(ctx, r.ID)
		if err != nil {
			log.Warn().Err(err).Str("repo_id", r.ID).Msg("active-job check")
			continue
		}
		if active {
			continue
		}
		// Schedule a deterministic_only scan — LLM modes gated to 6.1d.
		mode := r.DefaultScanMode
		if mode != model.ScanModeDeterministicOnly {
			mode = model.ScanModeDeterministicOnly
		}
		if err := s.Store.EnqueueScanJob(ctx, &model.ScanJob{
			RepoID:    r.ID,
			ScanMode:  mode,
			Trigger:   model.TriggerScheduled,
			BranchRef: r.DefaultBranch,
		}); err != nil {
			log.Warn().Err(err).Str("repo_id", r.ID).Msg("enqueue scheduled")
			continue
		}
		if err := s.Store.UpdateRepositoryLastScheduledAt(ctx, r.ID, now); err != nil {
			log.Warn().Err(err).Str("repo_id", r.ID).Msg("update last_scheduled_at")
		}
	}
	return nil
}
