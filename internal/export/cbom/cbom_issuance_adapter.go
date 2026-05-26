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

// Package cbom — CE OVERLAY for cbom_issuance_adapter.go.
//
// The EE-original references internal/analysis/hostdeps (Layer 4.4
// SP-1.6) to derive cert→cert issuance edges for the CBOM emit path.
// In CE the PKI edge engine is excluded; this overlay short-circuits
// the adapter to always return noopIssuanceLookup{} so the CBOM emit
// path degrades gracefully (BOM is still produced; cert→cert
// dependency edges are omitted).
//
// Source: scripts/ce-port/overlays/cbom_issuance_adapter.go (EE repo).
// Vendored into the staging tree by scripts/ce-port/extract.sh.
package cbom

import (
	"context"

	"github.com/net4n6-dev/cipherflag/internal/store"
)

// issuanceLookupForStore — CE always returns noopIssuanceLookup{} (PKI
// edge engine is EE-only Layer 4.4 SP-1.6). The signature matches the
// EE-original so generator.go and application.go continue to compile.
func issuanceLookupForStore(_ context.Context, _ store.CryptoStore) IssuanceLookupForCBOM {
	return noopIssuanceLookup{}
}

// noopIssuanceLookup is the only IssuanceLookupForCBOM in CE — there is
// no PKI lookup to fall back from. Matches EE shape so test doubles in
// dependencies_test.go remain valid.
type noopIssuanceLookup struct{}

func (noopIssuanceLookup) ListParentsForCertCBOM(string) []ParentLinkForCBOM {
	return nil
}
