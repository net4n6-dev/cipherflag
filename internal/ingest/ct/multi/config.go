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

// Package multi is the ct_multi coverage-union composer: fans out
// QueryDomain across N configured child CT providers (crtsh, static,
// certspotter) for one domain and unions their results.
package multi

import (
	"fmt"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest/ct/certspotter"
	"github.com/net4n6-dev/cipherflag/internal/ingest/ct/crtsh"
	"github.com/net4n6-dev/cipherflag/internal/ingest/ct/static"
)

// SourceName is the cursor key prefix used by the poller in ingestion_state
// (full key is "ct_multi:<domain>").
const SourceName = "ct_multi"

// ValidateGroup enforces: >=2 children, exactly one non-nil child kind per
// entry, every child's domain (if set) matches the group's domain, and —
// so a misconfigured child fails fast at startup exactly like the
// equivalent standalone connector would, instead of failing silently at
// runtime every cycle — each child passes its own kind's validator:
//
//   - crtsh:       crtsh.ValidateDomain(group domain)
//   - static:      static.ValidateDomainConfig(group domain, log_url, public_key_pem)
//     (https-only, trailing slash, parseable Ed25519 key)
//   - certspotter: certspotter.ValidateDomain(group domain, requests_per_hour)
//
// A child's domain always equals the group's (checked first), so the
// group domain is what every child actually queries.
//
// Mirrors EE's multi/config.go ValidateJSON (rm:0256 domain-match check).
func ValidateGroup(group config.CtMultiGroupConfig) error {
	if group.Domain == "" {
		return fmt.Errorf("ct_multi: domain is required")
	}
	if len(group.Children) < 2 {
		return fmt.Errorf("ct_multi: group %q: children must have at least 2 entries (got %d)", group.Domain, len(group.Children))
	}
	for i, child := range group.Children {
		nonNil := 0
		if child.Crtsh != nil {
			nonNil++
		}
		if child.Static != nil {
			nonNil++
			if child.Static.Domain != "" && child.Static.Domain != group.Domain {
				return fmt.Errorf("ct_multi: group %q children[%d]: static domain (%q) must match group domain", group.Domain, i, child.Static.Domain)
			}
		}
		if child.Certspotter != nil {
			nonNil++
			if child.Certspotter.Domain != "" && child.Certspotter.Domain != group.Domain {
				return fmt.Errorf("ct_multi: group %q children[%d]: certspotter domain (%q) must match group domain", group.Domain, i, child.Certspotter.Domain)
			}
		}
		if nonNil != 1 {
			return fmt.Errorf("ct_multi: group %q children[%d]: must have exactly one of crtsh/static/certspotter (got %d)", group.Domain, i, nonNil)
		}
		if err := validateChild(group.Domain, child); err != nil {
			return fmt.Errorf("ct_multi: group %q children[%d]: %w", group.Domain, i, err)
		}
	}
	return nil
}

// validateChild delegates to the per-kind validator for exactly-one-kind
// child (the caller has already enforced exactly one non-nil kind).
func validateChild(domain string, child config.CtMultiChildConfig) error {
	switch {
	case child.Crtsh != nil:
		return crtsh.ValidateDomain(domain)
	case child.Static != nil:
		return static.ValidateDomainConfig(domain, child.Static.LogURL, child.Static.PublicKeyPEM)
	case child.Certspotter != nil:
		return certspotter.ValidateDomain(domain, child.Certspotter.RequestsPerHour)
	}
	return nil
}
