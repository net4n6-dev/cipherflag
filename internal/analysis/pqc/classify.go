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

package pqc

import "strings"

// Classify resolves raw into its Classification. Never returns an error.
//
// Lookup order:
//  1. Normalise raw: strings.TrimSpace + strings.ToLower.
//  2. If normalised string is a synonym, replace with the canonical name.
//  3. Look up in the canonical map.
//  4. On miss, return Classification{Status: QuantumUnknown}.
//
// Empty or whitespace-only input returns Unknown.
func Classify(raw string) Classification {
	key := normalize(raw)
	if key == "" {
		return Classification{Status: QuantumUnknown}
	}
	if canonicalName, ok := synonyms[key]; ok {
		key = canonicalName
	}
	if c, ok := canonical[key]; ok {
		return c
	}
	return Classification{Status: QuantumUnknown}
}

// StatusOf is a convenience wrapper for callers that only need the
// quantum status.
func StatusOf(raw string) QuantumStatus {
	return Classify(raw).Status
}

// Canonical resolves raw to its catalog-canonical spelling. Returns
// ("", false) when the input is not recognised — neither canonical
// nor synonym. Useful for callers that want to detect taxonomy drift
// (e.g. CBOM emitters flagging uncatalogued algorithm names) without
// committing to a QuantumStatus lookup.
//
// Semantics match Classify's resolution path: whitespace-trimmed,
// lowercased, synonym-normalised.
func Canonical(raw string) (string, bool) {
	key := normalize(raw)
	if key == "" {
		return "", false
	}
	if canonicalName, ok := synonyms[key]; ok {
		key = canonicalName
	}
	if _, ok := canonical[key]; ok {
		return key, true
	}
	return "", false
}

// normalize lowercases and trims whitespace. No active prefix/suffix
// stripping — variants are recognised via explicit synonym entries.
func normalize(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}
