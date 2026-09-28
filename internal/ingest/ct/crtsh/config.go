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

// Package crtsh is the Certificate Transparency crt.sh adapter.
package crtsh

import (
	"fmt"
	"regexp"
	"strings"
)

// SourceName is the cursor key prefix used by the poller in ingestion_state
// (full key is "ct_crtsh:<domain>").
const SourceName = "ct_crtsh"

// domainRE enforces lowercase RFC 1035-style domains with at least one dot.
var domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// ValidateDomain checks one configured domain entry. Returns an error on
// any rejected value; nil means safe to poll.
func ValidateDomain(domain string) error {
	d := strings.TrimSpace(domain)
	if d == "" {
		return fmt.Errorf("ct_crtsh: domain is required")
	}
	if !domainRE.MatchString(d) {
		return fmt.Errorf("ct_crtsh: domain %q is not a valid lowercase domain", d)
	}
	return nil
}
