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
// Package netwrix implements the CipherFlag adapter for Netwrix Auditor's
// AD CS change feed. The adapter polls Netwrix's Integration API for
// certificate-related Activity Records (issued, renewed, revoked) and stores
// them in CipherFlag's ad_cs_events table. It does NOT populate the
// certificates table — Netwrix events lack the cryptographic detail
// (SHA256 fingerprint, etc.) required for the cert inventory.
package netwrix

import (
	"context"
	"time"
)

// APIClient is the abstract interface CipherFlag uses to talk to Netwrix.
// The real implementation (ntlm_client.go) is HTTP+NTLM; tests use MockClient.
type APIClient interface {
	// SearchActivity returns AD CS Activity Records matching the filter.
	// Pagination is handled internally — the returned slice contains all
	// records (multiple pages stitched).
	SearchActivity(ctx context.Context, filter SearchFilter) ([]ActivityRecord, error)

	// Close releases resources held by the client.
	Close() error
}

// Config holds the connection parameters for a real APIClient.
type Config struct {
	BaseURL         string        // e.g., "https://netwrix.internal:9699"
	Username        string        // NTLM username (often DOMAIN\user format)
	Password        string        // NTLM password
	InsecureSkipTLS bool          // for self-signed Netwrix certs in test environments only
	HTTPTimeout     time.Duration // 0 = 60s default
}

// SearchFilter narrows the Activity Records returned by SearchActivity.
type SearchFilter struct {
	Since       time.Time // event_timestamp >= Since (zero = no lower bound)
	Until       time.Time // event_timestamp < Until (zero = no upper bound)
	DataSource  string    // e.g., "Active Directory"
	ObjectTypes []string  // e.g., cert-related object types
	Actions     []string  // optional: ["Added", "Modified", "Removed"]
	MaxResults  int       // 0 = default 1000 per page
}

// ActivityRecord is the raw shape Netwrix returns. EventTime is the parsed
// timestamp; Raw preserves the full payload for the mapper to extract from.
type ActivityRecord struct {
	EventTime time.Time
	Raw       map[string]interface{}
}
