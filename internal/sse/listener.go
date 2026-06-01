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

package sse

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
)

// StartListener connects to PostgreSQL, LISTENs on cipherflag_events,
// and publishes received notifications to the hub. Blocks until ctx is cancelled.
// Reconnects with exponential backoff on connection loss.
func StartListener(ctx context.Context, connString string, hub *Hub, logger zerolog.Logger) {
	backoff := time.Second
	maxBackoff := 30 * time.Second

	for {
		err := listenLoop(ctx, connString, hub, logger)
		if ctx.Err() != nil {
			return // context cancelled, shut down
		}
		logger.Warn().Err(err).Dur("backoff", backoff).Msg("SSE listener disconnected, reconnecting")
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

func listenLoop(ctx context.Context, connString string, hub *Hub, logger zerolog.Logger) error {
	conn, err := pgx.Connect(ctx, connString)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	_, err = conn.Exec(ctx, "LISTEN cipherflag_events")
	if err != nil {
		return err
	}
	logger.Info().Msg("SSE listener connected, listening on cipherflag_events")

	for {
		notification, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}

		var evt Event
		if err := json.Unmarshal([]byte(notification.Payload), &evt); err != nil {
			logger.Warn().Err(err).Str("payload", notification.Payload).Msg("invalid SSE event payload")
			continue
		}
		hub.Publish(evt)
	}
}
