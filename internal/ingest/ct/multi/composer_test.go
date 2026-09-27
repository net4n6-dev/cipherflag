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
	"errors"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/ingest/ct"
)

// fakeChild lets a test drive a Provider's behavior deterministically.
type fakeChild struct {
	name    string
	entries []ct.CTEntry
	err     error
	delay   time.Duration
}

func (f *fakeChild) Name() string { return f.name }
func (f *fakeChild) QueryDomain(ctx context.Context, domain string) ([]ct.CTEntry, error) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.entries, nil
}

func entry(fp, source string) ct.CTEntry {
	return ct.CTEntry{Fingerprint: fp, Source: source}
}

func TestComposer_FanOut_AllSucceed_ReturnsUnion(t *testing.T) {
	c := &Composer{
		Domain: "x.com",
		Children: []ct.Provider{
			&fakeChild{name: "crtsh", entries: []ct.CTEntry{entry("AA", "ct_crtsh"), entry("BB", "ct_crtsh")}},
			&fakeChild{name: "static", entries: []ct.CTEntry{entry("CC", "ct_static")}},
		},
	}
	out, err := c.QueryDomain(context.Background(), "x.com")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(out) != 3 {
		t.Errorf("len = %d, want 3 (union)", len(out))
	}
	if len(c.LastChildStatus) != 2 {
		t.Errorf("LastChildStatus len = %d, want 2", len(c.LastChildStatus))
	}
	for _, s := range c.LastChildStatus {
		if !s.OK {
			t.Errorf("child %s not OK: %v", s.Name, s.Err)
		}
	}
}

func TestComposer_FanOut_PartialFailure_SkipsErroredChild(t *testing.T) {
	c := &Composer{
		Domain: "x.com",
		Children: []ct.Provider{
			&fakeChild{name: "crtsh", entries: []ct.CTEntry{entry("AA", "ct_crtsh")}},
			&fakeChild{name: "certspotter", err: errors.New("rate limited")},
		},
	}
	out, err := c.QueryDomain(context.Background(), "x.com")
	if err != nil {
		t.Fatalf("Composer.QueryDomain should never return err: %v", err)
	}
	if len(out) != 1 {
		t.Errorf("len = %d, want 1 (only succeeding child contributed)", len(out))
	}
	okCount := 0
	for _, s := range c.LastChildStatus {
		if s.OK {
			okCount++
		}
	}
	if okCount != 1 {
		t.Errorf("OK count = %d, want 1", okCount)
	}
}

func TestComposer_FanOut_AllFail_ReturnsEmptyNoError(t *testing.T) {
	c := &Composer{
		Domain: "x.com",
		Children: []ct.Provider{
			&fakeChild{name: "crtsh", err: errors.New("net down")},
			&fakeChild{name: "static", err: errors.New("403")},
		},
	}
	out, err := c.QueryDomain(context.Background(), "x.com")
	if err != nil {
		t.Errorf("err = %v, want nil (composer never returns err)", err)
	}
	if len(out) != 0 {
		t.Errorf("len = %d, want 0", len(out))
	}
	for _, s := range c.LastChildStatus {
		if s.OK {
			t.Errorf("child %s should not be OK", s.Name)
		}
	}
}

func TestComposer_FanOut_CertOverlap_OneEntryPerChild(t *testing.T) {
	// Same fingerprint reported by 2 children → 2 entries with different Source.
	c := &Composer{
		Domain: "x.com",
		Children: []ct.Provider{
			&fakeChild{name: "crtsh", entries: []ct.CTEntry{entry("SAME", "ct_crtsh")}},
			&fakeChild{name: "static", entries: []ct.CTEntry{entry("SAME", "ct_static")}},
		},
	}
	out, _ := c.QueryDomain(context.Background(), "x.com")
	if len(out) != 2 {
		t.Fatalf("len = %d, want 2 (no cross-child dedup)", len(out))
	}
	sources := map[string]int{}
	for _, e := range out {
		sources[e.Source]++
	}
	if sources["ct_crtsh"] != 1 || sources["ct_static"] != 1 {
		t.Errorf("sources = %v, want {ct_crtsh:1, ct_static:1}", sources)
	}
}

func TestComposer_DefensiveWithinChildDedup(t *testing.T) {
	// A misbehaving child returns the same fingerprint twice; composer
	// emits only one. (Should be a no-op for well-behaved children.)
	c := &Composer{
		Domain: "x.com",
		Children: []ct.Provider{
			&fakeChild{name: "crtsh", entries: []ct.CTEntry{
				entry("DUP", "ct_crtsh"),
				entry("DUP", "ct_crtsh"),
				entry("UNIQUE", "ct_crtsh"),
			}},
			&fakeChild{name: "static", entries: []ct.CTEntry{entry("S", "ct_static")}},
		},
	}
	out, _ := c.QueryDomain(context.Background(), "x.com")
	if len(out) != 3 {
		t.Errorf("len = %d, want 3 (DUP deduped within child)", len(out))
	}
}

func TestComposer_NeverOverwritesSource(t *testing.T) {
	c := &Composer{
		Domain: "x.com",
		Children: []ct.Provider{
			&fakeChild{name: "crtsh", entries: []ct.CTEntry{entry("AA", "ct_crtsh")}},
			&fakeChild{name: "static", entries: []ct.CTEntry{entry("BB", "ct_static")}},
		},
	}
	out, _ := c.QueryDomain(context.Background(), "x.com")
	for _, e := range out {
		if e.Source == "ct_multi" {
			t.Errorf("composer overwrote Source with ct_multi (cert fp=%s)", e.Fingerprint)
		}
	}
}

func TestComposer_FanOut_ParallelLatency(t *testing.T) {
	// 3 children each sleep 100ms. Sequential would be 300ms; parallel < 250ms.
	c := &Composer{
		Domain: "x.com",
		Children: []ct.Provider{
			&fakeChild{name: "a", delay: 100 * time.Millisecond, entries: []ct.CTEntry{entry("A", "ct_crtsh")}},
			&fakeChild{name: "b", delay: 100 * time.Millisecond, entries: []ct.CTEntry{entry("B", "ct_static")}},
			&fakeChild{name: "c", delay: 100 * time.Millisecond, entries: []ct.CTEntry{entry("C", "ct_certspotter")}},
		},
	}
	start := time.Now()
	_, _ = c.QueryDomain(context.Background(), "x.com")
	elapsed := time.Since(start)
	if elapsed >= 250*time.Millisecond {
		t.Errorf("elapsed = %v, want <250ms (parallel fan-out regression)", elapsed)
	}
}

func TestComposer_ContextCancellation_AllChildrenAbort(t *testing.T) {
	makeChild := func(name string) ct.Provider {
		return &fakeChild{
			name: name,
			// Long delay; ctx cancellation should preempt.
			delay: 5 * time.Second,
		}
	}
	c := &Composer{
		Domain: "x.com",
		Children: []ct.Provider{
			makeChild("a"),
			makeChild("b"),
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	c.QueryDomain(ctx, "x.com")
	if elapsed := time.Since(start); elapsed >= time.Second {
		t.Errorf("ctx cancel did not preempt children: elapsed=%v", elapsed)
	}
}
