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

package cbom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom/sinks/types"
	"github.com/rs/zerolog/log"
)

const cycloneDXContentType = "application/vnd.cyclonedx+json; version=1.6"

// SinkPayload, Sink, and RetryableError are re-exported from sinks/types
// to avoid circular imports. SinkEvent is re-exported from events.go.
type SinkPayload = types.SinkPayload
type Sink = types.Sink
type RetryableError = types.RetryableError

// encodeBOM encodes a *cdx.BOM to JSON bytes.
//
// When bom.Signature is non-nil we use MarshalSignedBOM instead of the
// CycloneDX encoder so that the JSF signature block (Algorithm/Value/PublicKey)
// is preserved in the output. The CycloneDX library's BOMEncoder routes through
// json.Marshal, which silently drops the embedded *JSFSigner fields because they
// carry json:"-" in cdx.JSFSignature — see the note in cbom_sign.go and
// signing.go for the full explanation.
func encodeBOM(bom *cdx.BOM) ([]byte, error) {
	if bom.Signature != nil && bom.Signature.JSFSigner != nil {
		return MarshalSignedBOM(bom)
	}
	var buf bytes.Buffer
	enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	enc.SetPretty(false)
	if err := enc.Encode(bom); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// encodeEventsNDJSON encodes a slice of SinkEvents as newline-delimited JSON,
// writing event.Payload as each line. Returns empty byte slice for empty input.
func encodeEventsNDJSON(events []SinkEvent) ([]byte, error) {
	if len(events) == 0 {
		return nil, nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for i := range events {
		if err := enc.Encode(events[i].Payload); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// ── HTTPSink ─────────────────────────────────────────────────────────────────

// HTTPSink POSTs a payload to an HTTP endpoint.
type HTTPSink struct {
	cfg    config.HTTPSinkConfig // type-specific config
	common config.SinkConfig     // Timeout/Retries/Granularity
}

// Send encodes the payload and POSTs it. Retries on 5xx/network errors up to cfg.Retries.
// Never retries on 4xx — returns error immediately.
func (s *HTTPSink) Send(ctx context.Context, payload *SinkPayload) error {
	body, contentType, err := s.encode(payload)
	if err != nil {
		return fmt.Errorf("cbom httpsink: encode: %w", err)
	}
	client := &http.Client{Timeout: s.common.Timeout}
	maxAttempts := s.common.Retries + 1
	backoff := time.Second

	for attempt := 0; attempt < maxAttempts; attempt++ {
		reqErr := s.doRequest(ctx, client, body, contentType)
		if reqErr == nil {
			return nil
		}
		if _, retryable := reqErr.(*RetryableError); !retryable {
			return reqErr
		}
		if attempt < maxAttempts-1 {
			log.Warn().Err(reqErr).Int("attempt", attempt+1).Str("url", s.cfg.URL).Msg("cbom: http sink retrying")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
		} else {
			return reqErr
		}
	}
	return nil
}

// encode returns the serialized body + Content-Type for the payload.
// BOM → CycloneDX JSON; Events → NDJSON (one event per line).
func (s *HTTPSink) encode(payload *SinkPayload) ([]byte, string, error) {
	if payload == nil {
		return nil, "", fmt.Errorf("nil payload")
	}
	if payload.BOM != nil {
		b, err := encodeBOM(payload.BOM)
		return b, cycloneDXContentType, err
	}
	if payload.Events != nil {
		b, err := encodeEventsNDJSON(payload.Events)
		return b, "application/x-ndjson", err
	}
	return nil, "", fmt.Errorf("cbom httpsink: empty payload")
}

func (s *HTTPSink) doRequest(ctx context.Context, client *http.Client, body []byte, contentType string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return &RetryableError{Err: err}
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "CipherFlag/"+cbomVersion+" CBOM-pusher")
	req.Header.Set("X-Request-ID", uuid.New().String())

	switch s.cfg.Auth {
	case "bearer":
		token := os.Getenv(s.cfg.AuthRef)
		req.Header.Set("Authorization", "Bearer "+token)
	case "header":
		token := os.Getenv(s.cfg.AuthRef)
		req.Header.Set(s.cfg.AuthHeaderName, token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return &RetryableError{Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		return &RetryableError{Err: fmt.Errorf("cbom httpsink: server error %d", resp.StatusCode)}
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("cbom httpsink: client error %d (no retry)", resp.StatusCode)
	}
	return nil
}

// ── FileSink ──────────────────────────────────────────────────────────────────

// FileSink writes a payload to a local file using atomic rename.
type FileSink struct {
	cfg       config.FileSinkConfig
	common    config.SinkConfig
	outputDir string
	scopeName string
}

// Send resolves the path template, encodes the payload, and atomically writes it.
func (s *FileSink) Send(ctx context.Context, payload *SinkPayload) error {
	var body []byte
	var err error
	if payload == nil {
		return fmt.Errorf("cbom filesink: nil payload")
	}
	if payload.BOM != nil {
		body, err = encodeBOM(payload.BOM)
	} else if payload.Events != nil {
		body, err = encodeEventsNDJSON(payload.Events)
	} else {
		return fmt.Errorf("cbom filesink: empty payload")
	}
	if err != nil {
		return fmt.Errorf("cbom filesink: encode: %w", err)
	}

	ts := time.Now().UTC().Format("20060102T150405Z")
	path := strings.NewReplacer(
		"{output_dir}", s.outputDir,
		"{scope}", sanitizeName(s.scopeName),
		"{timestamp}", ts,
	).Replace(s.cfg.PathTemplate)

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("cbom filesink: mkdir %s: %w", dir, err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0640); err != nil {
		return fmt.Errorf("cbom filesink: write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("cbom filesink: rename: %w", err)
	}
	return nil
}

// sanitizeName restricts a scope name to the characters allowed in file paths.
// scope names are already validated to [a-zA-Z0-9._-] by config.CBOMConfig.Validate.
func sanitizeName(name string) string {
	var b strings.Builder
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == '-' {
			b.WriteRune(c)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}
