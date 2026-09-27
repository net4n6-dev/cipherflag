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

// Package static is the Static CT API (Sunlight) log consumer.
package static

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
)

// SourceName is the cursor key prefix used by the poller in ingestion_state
// (full key is "ct_static:<domain>").
const SourceName = "ct_static"

// ValidateDomainConfig checks one configured domain entry's static-log
// fields (log_url, public_key_pem). Mirrors crtsh.ValidateDomain's role
// but validates the wider field set static needs.
func ValidateDomainConfig(domain, logURL, publicKeyPEM string) error {
	if strings.TrimSpace(domain) == "" {
		return fmt.Errorf("ct_static: domain is required")
	}
	if logURL == "" {
		return fmt.Errorf("ct_static: log_url is required")
	}
	u, err := url.Parse(logURL)
	if err != nil {
		return fmt.Errorf("ct_static: log_url parse: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("ct_static: log_url must be https (got %q)", u.Scheme)
	}
	if !strings.HasSuffix(u.Path, "/") {
		return fmt.Errorf("ct_static: log_url must end with /")
	}
	if publicKeyPEM == "" {
		return fmt.Errorf("ct_static: public_key_pem is required")
	}
	if _, err := ParseEd25519PublicKeyPEM(publicKeyPEM); err != nil {
		return err
	}
	return nil
}

// ParseEd25519PublicKeyPEM decodes the operator-supplied PEM and asserts
// the wrapped key is Ed25519. Exported (unlike EE's private
// parseEd25519PublicKeyPEM) so main.go's startup validation and Provider
// construction can share it without re-parsing.
func ParseEd25519PublicKeyPEM(pemStr string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("ct_static: public_key_pem: PEM decode failed")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ct_static: public_key_pem: PKIX parse: %w", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("ct_static: public_key_pem: not Ed25519 (got %T)", pub)
	}
	return edPub, nil
}
