// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// Package sentinelone implements the CipherFlag adapter for SentinelOne.
//
// The adapter operates in two complementary modes:
//
//  1. Application Inventory — polls /web/api/v2.1/installed-applications
//     filtered for known crypto libraries. Mirrors the Defender library-
//     discovery pattern (timestamp cursor, per-cycle query).
//
//  2. Remote Script Orchestration (RSO) — launches Layer 1 discovery
//     scripts via /web/api/v2.1/remote-scripts/execute, polls for task
//     completion across cycles, and ingests the NDJSON output.
//
// Both modes feed the UnifiedIngester.
package sentinelone

import (
	"context"
	"fmt"
	"io"
	"time"
)

// APIClient is the abstract interface CipherFlag uses to talk to SentinelOne.
// The real implementation (http_client.go) uses ApiToken HTTP auth.
// Tests use MockClient.
type APIClient interface {
	// ListInstalledApplications returns applications whose name matches any
	// of the provided substring filters. "since" restricts to applications
	// installed/updated after that timestamp.
	// Returns *RateLimitError when the API responds 429.
	ListInstalledApplications(ctx context.Context, since time.Time, nameFilters []string) ([]AppRecord, error)

	// ExecuteRemoteScript launches a remote script execution against the
	// target selector (v1: "all"). Returns the parent task ID assigned by
	// SentinelOne.
	ExecuteRemoteScript(ctx context.Context, scriptID, target string) (taskID string, err error)

	// GetRemoteScriptStatus returns the current state of a previously
	// launched task.
	GetRemoteScriptStatus(ctx context.Context, taskID string) (TaskStatus, error)

	// GetRemoteScriptResults streams the NDJSON output of a completed task.
	// The caller is responsible for closing the returned reader.
	GetRemoteScriptResults(ctx context.Context, taskID string) (io.ReadCloser, error)

	// Close releases idle connections held by the client.
	Close() error
}

// Config holds connection parameters for a real APIClient.
type Config struct {
	APIToken    string
	ConsoleURL  string        // e.g. https://mgmt.sentinelone.net
	HTTPTimeout time.Duration // defaults to 60s when zero
}

// AppRecord is one row from the installed-applications endpoint.
type AppRecord struct {
	AgentUUID   string
	AgentName   string
	OSType      string // SentinelOne's raw value (e.g. "linux", "windows")
	AppName     string
	AppVendor   string
	AppVersion  string
	InstalledAt time.Time
}

// TaskState enumerates the lifecycle of an RSO task.
type TaskState string

const (
	TaskStatePending   TaskState = "pending"
	TaskStateRunning   TaskState = "running"
	TaskStateCompleted TaskState = "completed"
	TaskStateFailed    TaskState = "failed"
	TaskStateExpired   TaskState = "expired"
)

// TaskStatus is the response from GetRemoteScriptStatus.
type TaskStatus struct {
	TaskID string
	State  TaskState
	// Optional human-readable reason populated on failure/expiry.
	Detail string
}

// RateLimitError is returned on HTTP 429 so the poller can skip cursor
// advance without conflating with other failures.
type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("sentinelone: rate limited (retry after %s)", e.RetryAfter)
	}
	return "sentinelone: rate limited"
}

// AuthError is returned on HTTP 401/403 so the poller can disable itself
// for the remainder of the process lifetime (preventing a hot-loop retry
// that could lock out the API token).
type AuthError struct {
	StatusCode int
	Body       string
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("sentinelone: auth failed (HTTP %d): %s", e.StatusCode, e.Body)
}
