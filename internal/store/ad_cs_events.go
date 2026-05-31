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

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// ADCSEventQuery defines filters for ListADCSEvents.
type ADCSEventQuery struct {
	EventTypes   []string
	CANames      []string
	SerialNumber string
	Since        time.Time
	Until        time.Time
	Limit        int
	Offset       int
}

// ADCSEventResult is a paginated result from ListADCSEvents.
type ADCSEventResult struct {
	Events []model.ADCSEvent `json:"events"`
	Total  int               `json:"total"`
}

// BatchRecordADCSEvents inserts multiple events in a single transaction.
// Each insert is idempotent via ON CONFLICT (id) DO NOTHING.
func (s *PostgresStore) BatchRecordADCSEvents(ctx context.Context, events []*model.ADCSEvent) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	for _, event := range events {
		raw, err := json.Marshal(event.RawEvent)
		if err != nil {
			return fmt.Errorf("marshal raw_event for %s: %w", event.ID, err)
		}
		if event.IngestedAt.IsZero() {
			event.IngestedAt = time.Now().UTC()
		}
		source := event.Source
		if source == "" {
			source = "netwrix"
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO ad_cs_events (
				id, event_type, event_timestamp, ingested_at,
				ca_name, template_name, requested_by,
				serial_number, issuer_dn, subject_dn,
				source, raw_event
			) VALUES (
				$1, $2, $3, $4,
				$5, NULLIF($6, ''), NULLIF($7, ''),
				$8, $9, NULLIF($10, ''),
				$11, $12::jsonb
			) ON CONFLICT (id) DO NOTHING
		`,
			event.ID, event.EventType, event.EventTimestamp.UTC(), event.IngestedAt.UTC(),
			event.CAName, event.TemplateName, event.RequestedBy,
			event.SerialNumber, event.IssuerDN, event.SubjectDN,
			source, string(raw),
		)
		if err != nil {
			return fmt.Errorf("insert ad_cs_event %s: %w", event.ID, err)
		}
	}

	return tx.Commit(ctx)
}

// ListADCSEvents queries events with optional filters.
func (s *PostgresStore) ListADCSEvents(ctx context.Context, query ADCSEventQuery) (*ADCSEventResult, error) {
	limit := query.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}

	var (
		conditions []string
		args       []any
		argIdx     = 1
	)

	if len(query.EventTypes) > 0 {
		conditions = append(conditions, fmt.Sprintf("event_type = ANY($%d)", argIdx))
		args = append(args, query.EventTypes)
		argIdx++
	}
	if len(query.CANames) > 0 {
		conditions = append(conditions, fmt.Sprintf("ca_name = ANY($%d)", argIdx))
		args = append(args, query.CANames)
		argIdx++
	}
	if query.SerialNumber != "" {
		conditions = append(conditions, fmt.Sprintf("serial_number = $%d", argIdx))
		args = append(args, query.SerialNumber)
		argIdx++
	}
	if !query.Since.IsZero() {
		conditions = append(conditions, fmt.Sprintf("event_timestamp >= $%d", argIdx))
		args = append(args, query.Since.UTC())
		argIdx++
	}
	if !query.Until.IsZero() {
		conditions = append(conditions, fmt.Sprintf("event_timestamp < $%d", argIdx))
		args = append(args, query.Until.UTC())
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Total count.
	var total int
	countQuery := "SELECT COUNT(*) FROM ad_cs_events " + whereClause
	if err := s.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count ad_cs_events: %w", err)
	}

	// Page query.
	pageArgs := append([]any{}, args...)
	pageArgs = append(pageArgs, limit, query.Offset)
	pageQuery := fmt.Sprintf(`
		SELECT id, event_type, event_timestamp, ingested_at,
		       ca_name, COALESCE(template_name, ''), COALESCE(requested_by, ''),
		       serial_number, issuer_dn, COALESCE(subject_dn, ''),
		       source, raw_event
		FROM ad_cs_events
		%s
		ORDER BY event_timestamp DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)

	rows, err := s.pool.Query(ctx, pageQuery, pageArgs...)
	if err != nil {
		return nil, fmt.Errorf("query ad_cs_events: %w", err)
	}
	defer rows.Close()

	var events []model.ADCSEvent
	for rows.Next() {
		var e model.ADCSEvent
		var rawJSON []byte
		if err := rows.Scan(
			&e.ID, &e.EventType, &e.EventTimestamp, &e.IngestedAt,
			&e.CAName, &e.TemplateName, &e.RequestedBy,
			&e.SerialNumber, &e.IssuerDN, &e.SubjectDN,
			&e.Source, &rawJSON,
		); err != nil {
			return nil, fmt.Errorf("scan ad_cs_event: %w", err)
		}
		if len(rawJSON) > 0 {
			_ = json.Unmarshal(rawJSON, &e.RawEvent)
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iter ad_cs_events: %w", err)
	}

	return &ADCSEventResult{Events: events, Total: total}, nil
}
