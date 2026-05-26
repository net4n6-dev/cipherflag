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

// Package observcache provides an in-process observation cache that lets
// the UnifiedIngester skip redundant per-asset database writes when
// third-party collectors re-emit identical observations.
//
// The cache is safety-first: any field change in an observation produces
// a different cache key (full-content SHA-256 hash), so the cache never
// masks a real content update. Mark-after-success semantics ensure
// transient failures retry naturally. Disabled mode (Noop) is byte-
// identical to the pre-cache code path — an instant rollback escape hatch.
package observcache

// ObservationCache is the contract the UnifiedIngester uses to
// short-circuit redundant asset writes.
//
// Implementations MUST be safe for concurrent use.
type ObservationCache interface {
	// Seen returns true if the key is cached and within TTL.
	// Does not modify the cache.
	Seen(key string) bool

	// Mark records the key with now() + TTL as expiry.
	// Called after successful persistence so transient failures retry.
	Mark(key string)

	// SeenAndMark returns true if the key was already present and marks
	// it otherwise. Convenience for callers that don't need mark-after-
	// success failure semantics. The UnifiedIngester primary path uses
	// separate Seen + Mark instead.
	SeenAndMark(key string) bool

	// Size returns the current number of entries held in the cache.
	Size() int
}

// Noop is the no-op implementation of ObservationCache. Used when dedup
// is disabled in config; produces byte-identical behaviour to pre-cache
// ingestion.
type Noop struct{}

// NewNoop constructs a no-op cache.
func NewNoop() *Noop { return &Noop{} }

// Seen always returns false.
func (Noop) Seen(string) bool { return false }

// Mark is a no-op.
func (Noop) Mark(string) {}

// SeenAndMark always returns false.
func (Noop) SeenAndMark(string) bool { return false }

// Size always returns 0.
func (Noop) Size() int { return 0 }
