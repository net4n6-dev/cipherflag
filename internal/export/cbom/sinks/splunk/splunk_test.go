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

package splunk

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom/sinks/types"
)

func TestSplunkSink_Send_SuccessfulBatch(t *testing.T) {
	var captured = &bytes.Buffer{}
	var capturedAuth, capturedCT string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		capturedCT = r.Header.Get("Content-Type")
		io.Copy(captured, r.Body)
		w.WriteHeader(200)
	}))
	defer server.Close()

	os.Setenv("HEC_TOKEN_TEST", "sekrit")
	defer os.Unsetenv("HEC_TOKEN_TEST")

	sink := New(
		config.SplunkSinkConfig{URL: server.URL, TokenRef: "HEC_TOKEN_TEST", BatchSize: 10},
		config.SinkConfig{Timeout: 2 * time.Second, Retries: 0},
		"asset",
	)
	events := []types.SinkEvent{
		{Timestamp: time.Unix(1000, 0), Payload: map[string]interface{}{"asset_id": "a1"}},
		{Timestamp: time.Unix(1001, 0), Payload: map[string]interface{}{"asset_id": "a2"}},
	}
	if err := sink.Send(context.Background(), &types.SinkPayload{Events: events}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if capturedAuth != "Splunk sekrit" {
		t.Errorf("Authorization = %q", capturedAuth)
	}
	if capturedCT != "application/x-ndjson" {
		t.Errorf("Content-Type = %q", capturedCT)
	}
	lines := strings.Split(strings.TrimRight(captured.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("NDJSON record count = %d, want 2", len(lines))
	}
	var rec map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("parse record: %v", err)
	}
	if rec["sourcetype"] != "cipherflag:asset" {
		t.Errorf("sourcetype = %v, want cipherflag:asset", rec["sourcetype"])
	}
	if rec["time"].(float64) != 1000 {
		t.Errorf("time = %v, want 1000", rec["time"])
	}
}

func TestSplunkSink_BatchesLargeInput(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(200)
	}))
	defer server.Close()

	sink := New(
		config.SplunkSinkConfig{URL: server.URL, TokenRef: "", BatchSize: 3},
		config.SinkConfig{Timeout: time.Second},
		"asset",
	)
	var events []types.SinkEvent
	for i := 0; i < 7; i++ {
		events = append(events, types.SinkEvent{Payload: map[string]interface{}{"n": i}})
	}
	if err := sink.Send(context.Background(), &types.SinkPayload{Events: events}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if callCount != 3 {
		t.Errorf("HTTP call count = %d, want 3", callCount)
	}
}

func TestSplunkSink_4xxNoRetry(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(400)
	}))
	defer server.Close()

	sink := New(
		config.SplunkSinkConfig{URL: server.URL, TokenRef: "", BatchSize: 10},
		config.SinkConfig{Timeout: time.Second, Retries: 3},
		"asset",
	)
	err := sink.Send(context.Background(), &types.SinkPayload{Events: []types.SinkEvent{{Payload: map[string]interface{}{}}}})
	if err == nil {
		t.Fatal("expected 4xx error")
	}
	if callCount != 1 {
		t.Errorf("HTTP call count = %d, want 1 (no retry on 4xx)", callCount)
	}
}

func TestSplunkSink_5xxRetries(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(500)
	}))
	defer server.Close()

	sink := New(
		config.SplunkSinkConfig{URL: server.URL, TokenRef: "", BatchSize: 10},
		config.SinkConfig{Timeout: time.Second, Retries: 2},
		"asset",
	)
	err := sink.Send(context.Background(), &types.SinkPayload{Events: []types.SinkEvent{{Payload: map[string]interface{}{}}}})
	if err == nil {
		t.Fatal("expected retryable 5xx error")
	}
	if callCount != 3 {
		t.Errorf("HTTP call count = %d, want 3 (1 initial + 2 retries)", callCount)
	}
}

func TestSplunkSink_SourcetypeOverride(t *testing.T) {
	captured := &bytes.Buffer{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(captured, r.Body)
		w.WriteHeader(200)
	}))
	defer server.Close()

	sink := New(
		config.SplunkSinkConfig{URL: server.URL, Sourcetype: "custom:type", TokenRef: "", BatchSize: 10},
		config.SinkConfig{Timeout: time.Second},
		"asset",
	)
	sink.Send(context.Background(), &types.SinkPayload{Events: []types.SinkEvent{{Payload: map[string]interface{}{}}}})

	if !strings.Contains(captured.String(), `"sourcetype":"custom:type"`) {
		t.Errorf("body does not contain custom sourcetype: %s", captured.String())
	}
}
