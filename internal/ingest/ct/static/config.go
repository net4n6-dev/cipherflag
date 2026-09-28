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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
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
// fields (log_url, origin, public_key_pem). Mirrors crtsh.ValidateDomain's
// role but validates the wider field set static needs.
//
// All three log fields come straight from the log's entry in Google's
// log_list.json (tiled_logs):
//
//   - log_url        = monitoring_url (where checkpoint + tiles are read)
//   - origin         = submission_url without "https://" and without the
//     trailing "/" (the checkpoint's first line and signature key name)
//   - public_key_pem = key (base64 DER SPKI) wrapped in a PUBLIC KEY PEM
//
// origin is deliberately explicit rather than derived from log_url: for
// most production logs the monitoring and submission hosts differ (e.g.
// mon.sycamore… vs log.sycamore…, …skylight… vs …sunlight…).
func ValidateDomainConfig(domain, logURL, origin, publicKeyPEM string) error {
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
	if err := ValidateOrigin(origin); err != nil {
		return err
	}
	if publicKeyPEM == "" {
		return fmt.Errorf("ct_static: public_key_pem is required")
	}
	if _, err := ParseLogPublicKeyPEM(publicKeyPEM); err != nil {
		return err
	}
	return nil
}

// ValidateOrigin checks the operator-supplied checkpoint origin: required,
// a valid signed-note key name (no whitespace, no '+'), and in the
// schema-less, no-trailing-slash form static-ct-api prescribes.
func ValidateOrigin(origin string) error {
	if origin == "" {
		return fmt.Errorf("ct_static: origin is required (the log's submission URL without https:// and without the trailing /, e.g. %q)", "log.sycamore.ct.letsencrypt.org/2026h2")
	}
	if strings.Contains(origin, "://") {
		return fmt.Errorf("ct_static: origin %q must not include a URL scheme", origin)
	}
	if strings.HasSuffix(origin, "/") {
		return fmt.Errorf("ct_static: origin %q must not end with /", origin)
	}
	if !isValidNoteName(origin) {
		return fmt.Errorf("ct_static: origin %q is not a valid checkpoint key name (no whitespace or '+')", origin)
	}
	return nil
}

// LogPublicKey is a parsed Static CT log public key.
type LogPublicKey struct {
	// SPKI is the DER SubjectPublicKeyInfo exactly as supplied. The
	// RFC6962NoteSignature key ID hashes these bytes, so they are kept
	// verbatim rather than re-marshalled from Key.
	SPKI []byte
	// Key is *ecdsa.PublicKey (P-256) or ed25519.PublicKey.
	Key crypto.PublicKey
}

// ParseLogPublicKeyPEM decodes the operator-supplied PEM (a PUBLIC KEY
// block wrapping a DER SubjectPublicKeyInfo) and accepts either an ECDSA
// P-256 key — what every production Static CT log uses, verified with
// RFC6962NoteSignature — or an Ed25519 key (plain signed-note Ed25519).
// Exported so main.go's startup validation and Provider construction
// share one parser.
func ParseLogPublicKeyPEM(pemStr string) (*LogPublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("ct_static: public_key_pem: PEM decode failed")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ct_static: public_key_pem: PKIX parse: %w", err)
	}
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("ct_static: public_key_pem: ECDSA curve %s not supported (want P-256)", k.Curve.Params().Name)
		}
	case ed25519.PublicKey:
	default:
		return nil, fmt.Errorf("ct_static: public_key_pem: unsupported key type %T (want ECDSA P-256 or Ed25519)", pub)
	}
	return &LogPublicKey{SPKI: block.Bytes, Key: pub}, nil
}
