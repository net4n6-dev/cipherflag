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

package attrition

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/store"
)

type Manager struct {
	store    store.CryptoStore
	config   store.AttritionConfig
	interval time.Duration
}

func NewManager(st store.CryptoStore, cfg store.AttritionConfig, interval time.Duration) *Manager {
	return &Manager{
		store:    st,
		config:   cfg,
		interval: interval,
	}
}

func (m *Manager) Run(ctx context.Context) {
	m.sweep(ctx)

	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("attrition manager stopped")
			return
		case <-ticker.C:
			m.sweep(ctx)
		}
	}
}

func (m *Manager) sweep(ctx context.Context) {
	summary, err := m.store.MarkStaleAssets(ctx, m.config)
	if err != nil {
		log.Error().Err(err).Msg("attrition sweep failed")
		return
	}
	if summary.MarkedStale > 0 || summary.MarkedRemoved > 0 {
		log.Info().
			Int("stale", summary.MarkedStale).
			Int("removed", summary.MarkedRemoved).
			Msg("attrition sweep complete")
	}
}
