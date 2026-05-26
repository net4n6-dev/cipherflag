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

// Package splunk implements the Layer 5.3 Splunk HEC sink. Batches events
// up to a configured size or interval, then POSTs as newline-delimited JSON
// HEC records (one record per line).
package splunk

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom/sinks/types"
	"github.com/rs/zerolog/log"
)

// Sink posts per-asset or per-finding events to a Splunk HEC endpoint.
// Batches up to BatchSize events or flushes every BatchFlushInterval.
type Sink struct {
	cfg        config.SplunkSinkConfig
	common     config.SinkConfig
	client     *http.Client
	sourcetype string // resolved at construction
}

// New constructs a SplunkSink with the configured HTTP client.
// `granularity` is the effective granularity ("asset" or "finding"), used to
// populate the default sourcetype when cfg.Sourcetype is empty.
func New(cfg config.SplunkSinkConfig, common config.SinkConfig, granularity string) *Sink {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.TLSInsecure},
	}
	client := &http.Client{Timeout: common.Timeout, Transport: transport}

	sourcetype := cfg.Sourcetype
	if sourcetype == "" {
		sourcetype = "cipherflag:" + granularity
	}

	return &Sink{cfg: cfg, common: common, client: client, sourcetype: sourcetype}
}

// Send batches events into HEC records and POSTs them. A single Send call
// may produce multiple HTTP requests if events exceeds BatchSize.
func (s *Sink) Send(ctx context.Context, payload *types.SinkPayload) error {
	if payload == nil || payload.Events == nil {
		return fmt.Errorf("cbom splunksink: events payload required")
	}
	if len(payload.Events) == 0 {
		return nil
	}
	batchSize := s.cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 100
	}

	for i := 0; i < len(payload.Events); i += batchSize {
		end := i + batchSize
		if end > len(payload.Events) {
			end = len(payload.Events)
		}
		body, err := s.encodeBatch(payload.Events[i:end])
		if err != nil {
			return fmt.Errorf("cbom splunksink: encode batch: %w", err)
		}
		if err := s.sendBatch(ctx, body); err != nil {
			return err
		}
	}
	return nil
}

// encodeBatch builds the HEC newline-delimited JSON body for a slice of events.
func (s *Sink) encodeBatch(events []types.SinkEvent) ([]byte, error) {
	var buf bytes.Buffer
	for i := range events {
		rec := map[string]interface{}{
			"time":       events[i].Timestamp.Unix(),
			"source":     nonEmpty(s.cfg.Source, "cipherflag"),
			"sourcetype": s.sourcetype,
			"event":      events[i].Payload,
		}
		if s.cfg.Index != "" {
			rec["index"] = s.cfg.Index
		}
		if err := json.NewEncoder(&buf).Encode(rec); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func (s *Sink) sendBatch(ctx context.Context, body []byte) error {
	maxAttempts := s.common.Retries + 1
	if maxAttempts <= 0 {
		maxAttempts = 1
	}
	backoff := time.Second

	for attempt := 0; attempt < maxAttempts; attempt++ {
		err := s.doPost(ctx, body)
		if err == nil {
			return nil
		}
		if _, retry := err.(*types.RetryableError); !retry {
			return err
		}
		if attempt < maxAttempts-1 {
			log.Warn().Err(err).Int("attempt", attempt+1).Str("url", s.cfg.URL).Msg("cbom: splunk sink retrying")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
		} else {
			return err
		}
	}
	return nil
}

func (s *Sink) doPost(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return &types.RetryableError{Err: err}
	}
	token := os.Getenv(s.cfg.TokenRef)
	if token == "" {
		log.Warn().Str("token_ref", s.cfg.TokenRef).Msg("cbom: splunk sink token_ref env var is empty")
	}
	req.Header.Set("Authorization", "Splunk "+token)
	req.Header.Set("Content-Type", "application/x-ndjson")

	resp, err := s.client.Do(req)
	if err != nil {
		return &types.RetryableError{Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 503 {
		return &types.RetryableError{Err: fmt.Errorf("hec 503 (retry-after %s)", resp.Header.Get("Retry-After"))}
	}
	if resp.StatusCode >= 500 {
		return &types.RetryableError{Err: fmt.Errorf("hec server error %d", resp.StatusCode)}
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("cbom splunksink: client error %d (no retry)", resp.StatusCode)
	}
	return nil
}

func nonEmpty(s, fallback string) string {
	if s != "" {
		return s
	}
	return fallback
}
