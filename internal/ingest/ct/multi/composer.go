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

package multi

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/ingest/ct"
)

// Composer fans out QueryDomain across N inline-configured CT children.
// One Composer per ct_multi source; constructed by the Poller from
// Config.Children (Task 2.3).
type Composer struct {
	Domain   string
	Children []ct.Provider

	// LastChildStatus is set by every QueryDomain call (one entry per
	// child, in Children order). Poller.runCycle reads it after each call
	// to log a Warn per failed child and an Error when every child in the
	// group failed. Not safe for concurrent QueryDomain calls on the same
	// Composer; the Poller calls it sequentially.
	LastChildStatus []ChildStatus
}

// ChildStatus records the outcome of one child's QueryDomain call within
// a Composer fan-out. Index in LastChildStatus matches the input-order
// index in Children so the Poller can correlate by position.
type ChildStatus struct {
	Name    string
	OK      bool
	Err     string
	Latency time.Duration
	Entries int
}

// Compile-time assertion that Composer satisfies ct.Provider.
var _ ct.Provider = (*Composer)(nil)

// Name returns the stable provider identifier for ct_multi.
func (c *Composer) Name() string { return "ct_multi" }

// QueryDomain runs every child's QueryDomain in parallel and returns the
// union of successful children's results. Never returns an error —
// per-child failure is encoded in LastChildStatus; the caller (Poller)
// decides escalation. Within-child fingerprint dedup is defensive only
// (well-behaved children shouldn't emit duplicates). Cross-child
// fingerprint dedup is intentionally NOT done — overlapping certs get
// one CTEntry per source so the downstream Ingester writes one
// asset_provenance row per (cert, child) pair.
//
// A panic inside a child's QueryDomain is recovered in that child's own
// goroutine and recorded as that child's failure (ChildStatus.Err). This
// is load-bearing: the Poller's runOneCycleSafely recover() cannot catch
// a panic on these fan-out goroutines (they are not on its call stack),
// and an unrecovered goroutine panic terminates the whole cipherflag
// process, not just the CT poller.
func (c *Composer) QueryDomain(ctx context.Context, domain string) ([]ct.CTEntry, error) {
	type childResult struct {
		entries []ct.CTEntry
		err     error
		latency time.Duration
	}

	// Allocate results slice indexed by input order. Each goroutine writes
	// only to its own index — no mutex needed.
	results := make([]childResult, len(c.Children))
	var wg sync.WaitGroup
	for i, child := range c.Children {
		wg.Add(1)
		go func(i int, p ct.Provider) {
			defer wg.Done()
			start := time.Now()
			// Runs before wg.Done (LIFO), so results[i] is written before
			// the parent's wg.Wait returns.
			defer func() {
				if r := recover(); r != nil {
					log.Error().
						Interface("panic", r).
						Str("domain", domain).
						Int("child_index", i).
						Str("stack", string(debug.Stack())).
						Msg("ct_multi: child provider panicked; recovered and marked failed")
					results[i] = childResult{err: fmt.Errorf("child panicked: %v", r), latency: time.Since(start)}
				}
			}()
			entries, err := p.QueryDomain(ctx, domain)
			results[i] = childResult{entries: entries, err: err, latency: time.Since(start)}
		}(i, child)
	}
	wg.Wait()

	statuses := make([]ChildStatus, len(c.Children))
	var out []ct.CTEntry
	for i, r := range results {
		name := c.Children[i].Name()
		statuses[i] = ChildStatus{Name: name, Latency: r.latency}
		if r.err != nil {
			statuses[i].Err = r.err.Error()
			// OK remains false; entries skipped
			continue
		}
		statuses[i].OK = true
		// Defensive within-child dedup: skip repeated fingerprints from
		// a misbehaving child. Cross-child dedup is intentionally absent.
		seen := make(map[string]bool, len(r.entries))
		appended := 0
		for _, e := range r.entries {
			if seen[e.Fingerprint] {
				continue
			}
			seen[e.Fingerprint] = true
			out = append(out, e) // Source preserved from child; never overwritten
			appended++
		}
		statuses[i].Entries = appended
	}
	c.LastChildStatus = statuses
	return out, nil
}
