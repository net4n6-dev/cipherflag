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

// Package cachegc garbage-collects repo_scan_cache rows that are both stale
// (older than 30 days by default) AND no longer match the current rule/prompt
// versions. Rows that still match are kept regardless of age because they
// accelerate re-scans.
package cachegc

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

type Store interface {
	SweepCache(ctx context.Context, assetType, activeRuleVersion, activePromptContentHash string, olderThan time.Time) (int, error)
}

type Sweeper struct {
	Store             Store
	RuleVersion       string
	PromptContentHash string        // "" for deterministic-only
	Interval          time.Duration // how often Run ticks; default 6h
	Age               time.Duration // rows older than Now - Age are candidates; default 30d
	Now               func() time.Time
}

func (s *Sweeper) Run(ctx context.Context) {
	interval := s.Interval
	if interval == 0 {
		interval = 6 * time.Hour
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := s.RunOnce(ctx); err != nil {
				log.Warn().Err(err).Msg("cachegc runonce")
			} else if n > 0 {
				log.Info().Int("deleted", n).Msg("cachegc sweep")
			}
		}
	}
}

func (s *Sweeper) RunOnce(ctx context.Context) (int, error) {
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	age := s.Age
	if age == 0 {
		age = 30 * 24 * time.Hour
	}
	return s.Store.SweepCache(ctx, model.AssetTypeRepository, s.RuleVersion, s.PromptContentHash, now.Add(-age))
}
