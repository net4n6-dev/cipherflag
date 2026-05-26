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

package scoring

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/store"
)

// Sweeper runs the cron rule-sweep that rescores assets whose
// rule_engine_version is stale and bootstraps assets that have never
// been scored.
type Sweeper struct {
	store     store.CryptoStore
	scorer    Scorer
	interval  time.Duration
	batchSize int
}

// NewSweeper constructs a Sweeper. Interval comes from
// config.Analysis.RecheckIntervalHours; batchSize from
// config.Analysis.RuleSweepBatchSize.
func NewSweeper(st store.CryptoStore, sc Scorer, interval time.Duration, batchSize int) *Sweeper {
	if interval <= 0 {
		interval = time.Hour
	}
	if batchSize <= 0 {
		batchSize = 1000
	}
	return &Sweeper{store: st, scorer: sc, interval: interval, batchSize: batchSize}
}

// Run starts the sweep loop. Runs once immediately, then on the interval
// ticker until ctx is cancelled.
func (s *Sweeper) Run(ctx context.Context) {
	s.runOnce(ctx)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("scoring sweeper stopped")
			return
		case <-ticker.C:
			s.runOnce(ctx)
		}
	}
}

func (s *Sweeper) runOnce(ctx context.Context) {
	// 1. Rescore rows whose rule_engine_version is stale.
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		rows, err := s.store.ListStaleAssetHealthRows(ctx, CurrentRuleEngineVersion, s.batchSize)
		if err != nil {
			log.Warn().Err(err).Msg("sweep: stale query failed")
			break
		}
		if len(rows) == 0 {
			break
		}
		for _, row := range rows {
			if err := ctx.Err(); err != nil {
				return
			}
			if err := s.scorer.ScoreAsset(ctx, row.AssetType, row.AssetID); err != nil {
				log.Warn().Err(err).
					Str("asset_type", row.AssetType).
					Str("asset_id", row.AssetID).
					Msg("sweep: rescore failed")
			}
		}
	}

	// 2. Score assets that have never been scored (bootstrap / drift).
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		rows, err := s.store.ListUnscoredAssets(ctx, s.batchSize)
		if err != nil {
			log.Warn().Err(err).Msg("sweep: unscored query failed")
			return
		}
		if len(rows) == 0 {
			return
		}
		for _, row := range rows {
			if err := ctx.Err(); err != nil {
				return
			}
			if err := s.scorer.ScoreAsset(ctx, row.AssetType, row.AssetID); err != nil {
				log.Warn().Err(err).
					Str("asset_type", row.AssetType).
					Str("asset_id", row.AssetID).
					Msg("sweep: initial scoring failed")
			}
		}
	}
}
