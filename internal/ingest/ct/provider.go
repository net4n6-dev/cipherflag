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
// Package ct hosts the multi-provider Certificate Transparency ingest
// machinery. Each per-provider implementation lives in a subpackage
// (crtsh/, static/, certspotter/, multi/) and registers its own
// externalsource kind. The top-level package exposes the shared
// Provider interface + normalised CTEntry shape both per-provider
// adapters and ct_multi consume.
//
// Spec: docs/superpowers/specs/2026-09-27-ct-multi-provider-port-design.md §Provider interface
package ct

import (
	"context"
	"time"
)

// Provider abstracts a single CT data source. Each per-kind subpkg's
// poller is a thin externalsource.Poller wrapper around a Provider
// implementation; ct_multi (Plan B) runs Provider.QueryDomain
// concurrently across N children and merges by Fingerprint.
//
// Implementations:
//   - internal/ingest/ct/crtsh.Provider     (crt.sh JSON API)
//   - internal/ingest/ct/static.Provider    (Static CT API / Sunlight)
//   - internal/ingest/ct/certspotter.Provider (Plan B)
type Provider interface {
	// QueryDomain returns the certs visible to this provider for the
	// given domain at this moment. Implementations handle their own
	// pagination, rate-limit handling, and per-call retries — the
	// returned slice is the complete result set for this domain.
	QueryDomain(ctx context.Context, domain string) ([]CTEntry, error)

	// Name returns the stable provider identifier ("crtsh",
	// "certspotter", "static") used for asset_provenance.source
	// attribution after ingest. Must be stable across releases.
	Name() string
}

// CTEntry is the normalised result row across providers. Each
// per-provider adapter converts its native response into this shape
// before returning. The fields mirror the existing v1.11 ct_domain
// crt.sh ingest schema so the existing dedup + Ingester pipeline
// consumes it unchanged.
type CTEntry struct {
	// Fingerprint is the hex-encoded lowercase SHA-256 of the DER
	// encoding of the certificate. Used by ct_multi as the dedup key.
	Fingerprint string

	// PEM is the PEM-encoded certificate (single "CERTIFICATE" block).
	PEM []byte

	// CommonName is the certificate subject CN. May be empty.
	CommonName string

	// NameValue is the newline-separated SAN list, matching the
	// existing schema used by crtsh.CrtShEntry.
	NameValue string

	// IssuerName is the issuer DN (free-form string).
	IssuerName string

	// NotBefore is the certificate's validity period start.
	NotBefore time.Time

	// NotAfter is the certificate's validity period end (expiry).
	NotAfter time.Time

	// Source MUST equal the Provider.Name() of the producing adapter.
	// Used by ct_multi to stamp asset_provenance.source per ingested
	// cert so the v1.14 Insights tab can drill down by provider.
	Source string
}
