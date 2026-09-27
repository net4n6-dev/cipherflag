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

// Package certspotter is the SSLMate CertSpotter hosted-API CT adapter.
package certspotter

import (
	"fmt"
	"regexp"
	"strings"
)

// SourceName is the cursor key prefix used by the poller in ingestion_state
// (full key is "ct_certspotter:<domain>").
const SourceName = "ct_certspotter"

var domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// ValidateDomain checks one configured domain entry plus its
// requests-per-hour override.
func ValidateDomain(domain string, requestsPerHour int) error {
	d := strings.TrimSpace(domain)
	if d == "" {
		return fmt.Errorf("ct_certspotter: domain is required")
	}
	if !domainRE.MatchString(d) {
		return fmt.Errorf("ct_certspotter: domain %q is not a valid lowercase domain", d)
	}
	if requestsPerHour < 0 {
		return fmt.Errorf("ct_certspotter: requests_per_hour must be >= 0 (0 = default)")
	}
	if requestsPerHour > 100000 {
		return fmt.Errorf("ct_certspotter: requests_per_hour must be <= 100000")
	}
	return nil
}

// DefaultRequestsPerHour is applied when a domain entry leaves
// requests_per_hour unset (0).
const DefaultRequestsPerHour = 50
