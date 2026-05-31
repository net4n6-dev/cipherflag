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

// Package absolute implements the CipherFlag adapter for Absolute Software.
//
// Two discovery modes run in parallel when enabled:
//
//  1. Inventory — polls the installed-applications API filtered for known
//     crypto library names. Available in every Absolute tier. Mirrors the
//     Defender / SentinelOne App Inventory pattern.
//
//  2. Reach — launches Layer 1 discovery scripts via Absolute Reach,
//     persists execution state across cycles, fetches NDJSON Script Query
//     output when executions complete. Resilience tier only.
//
// Both feed the UnifiedIngester.
//
// Request signing uses HMAC-SHA256 (see hmac_signer.go) — isolated from the
// rest of the package so neither the poller nor the mappers see the
// signing mechanics.
package absolute

import (
	"context"
	"fmt"
	"io"
	"time"
)

// APIClient is the abstract interface CipherFlag uses to talk to Absolute.
// The real implementation (http_client.go) wraps a Signer that adds
// HMAC-SHA256 auth to every request. Tests use MockClient.
type APIClient interface {
	// ListInstalledApplications polls the software-inventory endpoint,
	// filtered server-side for names matching any of the provided substrings.
	// "since" restricts to apps installed/updated after that timestamp.
	// Returns *RateLimitError on 429, *AuthError on 401/403.
	ListInstalledApplications(ctx context.Context, since time.Time, nameFilters []string) ([]DeviceApp, error)

	// ExecuteReachScript launches a Reach script execution against the
	// target selector (v1: "all"). Returns the execution ID assigned by
	// Absolute.
	ExecuteReachScript(ctx context.Context, scriptID, target string) (executionID string, err error)

	// GetReachExecutionStatus returns the current state of a previously
	// launched execution.
	GetReachExecutionStatus(ctx context.Context, executionID string) (ReachTaskStatus, error)

	// GetReachExecutionResults streams the Script Query NDJSON output of a
	// completed execution. Caller is responsible for closing the reader.
	GetReachExecutionResults(ctx context.Context, executionID string) (io.ReadCloser, error)

	// Close releases idle connections held by the client.
	Close() error
}

// Config holds connection parameters for a real APIClient.
type Config struct {
	TokenID     string
	SecretKey   string
	ConsoleURL  string        // e.g. https://api.absolute.com
	HTTPTimeout time.Duration // defaults to 60s when zero
}

// DeviceApp is one row from the installed-applications endpoint.
type DeviceApp struct {
	DeviceID    string // Absolute's stable device identifier (ESN / UUID)
	DeviceName  string
	OSPlatform  string // raw value from Absolute (e.g. "Windows", "macOS", "Linux")
	AppName     string
	AppVendor   string
	AppVersion  string
	InstalledAt time.Time
}

// ReachTaskState enumerates the lifecycle of a Reach execution.
type ReachTaskState string

const (
	ReachTaskStatePending   ReachTaskState = "pending"
	ReachTaskStateRunning   ReachTaskState = "running"
	ReachTaskStateCompleted ReachTaskState = "completed"
	ReachTaskStateFailed    ReachTaskState = "failed"
	ReachTaskStateExpired   ReachTaskState = "expired"
)

// ReachTaskStatus is the response from GetReachExecutionStatus.
type ReachTaskStatus struct {
	ExecutionID string
	State       ReachTaskState
	Detail      string // optional human-readable reason populated on failure/expiry
}

// RateLimitError is returned on HTTP 429 so the poller can skip cursor
// advance without conflating with other failures.
type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("absolute: rate limited (retry after %s)", e.RetryAfter)
	}
	return "absolute: rate limited"
}

// AuthError is returned on HTTP 401/403 so the poller can disable itself
// for the remainder of the process lifetime.
type AuthError struct {
	StatusCode int
	Body       string
}

func (e *AuthError) Error() string {
	body := e.Body
	const maxBody = 256
	if len(body) > maxBody {
		body = body[:maxBody] + "...(truncated)"
	}
	return fmt.Sprintf("absolute: auth failed (HTTP %d): %s", e.StatusCode, body)
}
