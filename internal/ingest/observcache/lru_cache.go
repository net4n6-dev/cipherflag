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

package observcache

import (
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
)

const (
	minLRUSize = 100
	minLRUTTL  = time.Second
)

// LRUCache is the production ObservationCache. Backed by an expirable
// LRU from hashicorp/golang-lru/v2 — thread-safe, bounded size, TTL-based
// expiry.
type LRUCache struct {
	inner *lru.LRU[string, struct{}]
}

// NewLRU constructs an LRUCache with the given max size and TTL.
// Zero or negative size clamps to minLRUSize.
// Zero or negative TTL clamps to minLRUTTL (so a zero-TTL misconfiguration
// can't silently make every entry expire immediately).
func NewLRU(maxEntries int, ttl time.Duration) *LRUCache {
	if maxEntries <= 0 {
		maxEntries = minLRUSize
	}
	if ttl <= 0 {
		ttl = minLRUTTL
	}
	return &LRUCache{
		inner: lru.NewLRU[string, struct{}](maxEntries, nil, ttl),
	}
}

// Seen returns true if the key is cached and still within TTL.
// Does not mutate.
func (c *LRUCache) Seen(key string) bool {
	_, ok := c.inner.Peek(key)
	return ok
}

// Mark records the key with current time + TTL as expiry.
func (c *LRUCache) Mark(key string) {
	c.inner.Add(key, struct{}{})
}

// SeenAndMark returns true if the key was already present and marks it
// otherwise.
func (c *LRUCache) SeenAndMark(key string) bool {
	if _, ok := c.inner.Peek(key); ok {
		return true
	}
	c.inner.Add(key, struct{}{})
	return false
}

// Size returns the current number of live entries.
func (c *LRUCache) Size() int {
	return c.inner.Len()
}
