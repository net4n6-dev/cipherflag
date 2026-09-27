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
// machinery. Each connector lives in a subpackage (crtsh/, static/,
// certspotter/, multi/) and exposes its own Poller, which
// cmd/cipherflag/main.go constructs directly from the TOML config
// (config.Sources.Ct*) and runs on its own goroutine — there is no
// source registry in CE. The top-level package holds what those
// connectors share: the Provider interface + normalised CTEntry shape
// (ct_multi fans out over Providers), BuildCertDiscovery (CTEntry →
// dedup.CertDiscovery), and the crt.sh request throttle.
//
// Spec: docs/superpowers/specs/2026-09-27-ct-multi-provider-port-design.md §Provider interface
package ct

import (
	"context"
	"time"
)

// Provider abstracts a single CT data source for a one-shot domain
// query. ct_multi's Composer runs Provider.QueryDomain concurrently
// across its configured children and unions the results. The
// standalone pollers do not go through this interface for their own
// cycles (they have per-domain cursors and ingest directly); the
// interface exists so ct_multi can compose them.
//
// Implementations:
//   - internal/ingest/ct/crtsh.Poller       (crt.sh JSON API)
//   - internal/ingest/ct/static.Provider    (Static CT API / Sunlight)
//   - internal/ingest/ct/certspotter.Poller (SSLMate CertSpotter API)
//   - internal/ingest/ct/multi.Composer     (the ct_multi fan-out itself)
type Provider interface {
	// QueryDomain returns the certs visible to this provider for the
	// given domain at this moment. Implementations handle their own
	// pagination, rate-limit handling, and per-call retries — the
	// returned slice is the complete result set for this call (for
	// static.Provider that means new leaves since its last position;
	// see its forward-watching note).
	QueryDomain(ctx context.Context, domain string) ([]CTEntry, error)

	// Name returns a short identifier ("crtsh", "static",
	// "certspotter", "ct_multi") used for logging and for ct_multi's
	// per-child ChildStatus. It is NOT the provenance string: ingest
	// attribution comes from CTEntry.Source, which uses the prefixed
	// connector name (e.g. "ct_crtsh").
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

	// Source is the canonical provenance string of the producing
	// connector — "ct_crtsh", "ct_static" or "ct_certspotter" — and is
	// deliberately NOT equal to Provider.Name() (the bare "crtsh" etc.).
	// ct_multi groups its union by Source and stamps it as
	// DiscoveryResult.Source (and so asset_provenance.source) on the
	// per-child Ingest call. It must equal the DiscoveryResult.Source the
	// corresponding standalone poller uses, so a cert found by ct_crtsh
	// alone and by ct_multi's crtsh child is attributed identically.
	Source string
}
