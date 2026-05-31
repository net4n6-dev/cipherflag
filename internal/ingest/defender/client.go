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
// Package defender implements the CipherFlag adapter for Microsoft Defender
// for Endpoint. The adapter polls Defender's Advanced Hunting API for crypto
// library inventory (DeviceTvmSoftwareInventory filtered for known crypto
// libraries) and feeds the results through the existing UnifiedIngester.
//
// V1 ships library discovery only. Certificate discovery from
// DeviceTvmCertificateInfo is deferred because Defender uses SHA1 thumbprints
// while CipherFlag's certificate model uses SHA256 fingerprints.
package defender

import (
	"context"
	"fmt"
	"time"
)

// APIClient is the abstract interface CipherFlag uses to talk to Defender.
// The real implementation (oauth_client.go) handles Entra ID OAuth + the
// Advanced Hunting API; tests use MockClient.
type APIClient interface {
	// RunAdvancedQuery executes a KQL query against the Advanced Hunting API.
	// Returns the raw row results — caller maps to domain types.
	// Returns *RateLimitError when the API responds 429.
	RunAdvancedQuery(ctx context.Context, kql string) ([]QueryRow, error)

	// Close releases resources held by the client.
	Close() error
}

// Config holds the connection parameters for a real APIClient.
type Config struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	// APIBaseURL defaults to "https://api.security.microsoft.com" if empty.
	// Override for sovereign clouds (GCC High, China cloud, etc.).
	APIBaseURL string
	// TokenURL defaults to "https://login.microsoftonline.com/{TenantID}/oauth2/v2.0/token".
	TokenURL string
	// HTTPTimeout defaults to 60s if zero.
	HTTPTimeout time.Duration
}

// QueryRow is one result row from an Advanced Hunting query.
// Columns are returned as a raw map for the mapper to extract fields tolerantly
// across schema changes.
type QueryRow struct {
	Columns map[string]any
}

// RateLimitError is returned when the API responds 429.
// The poller catches it, logs a warning, and skips cursor advance so the
// next cycle retries from the same window.
type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("defender: rate limited (retry after %s)", e.RetryAfter)
	}
	return "defender: rate limited"
}
