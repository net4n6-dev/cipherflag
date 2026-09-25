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

package cbom

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// panicOnceSink panics on its first Send and succeeds afterwards.
type panicOnceSink struct {
	calls int64
}

func (s *panicOnceSink) Send(_ context.Context, _ *SinkPayload) error {
	if atomic.AddInt64(&s.calls, 1) == 1 {
		panic("sink exploded")
	}
	return nil
}

// A panic inside sink.Send runs on the push scheduler's background goroutine,
// which has no recover, so it would terminate the whole process. emitScope must
// contain it and still deliver to the remaining sinks in the scope.
func TestRuntime_EmitScope_SinkPanicIsContained(t *testing.T) {
	fileSink := config.SinkConfig{Type: "file", File: &config.FileSinkConfig{PathTemplate: "/tmp/x.json"}}
	cfg := &config.CBOMConfig{
		Enabled: true,
		Scopes:  []config.ScopeConfig{{Name: "prod", Sinks: []config.SinkConfig{fileSink, fileSink}}},
	}
	rt := NewRuntime(&fakeSchedStore{}, cfg)
	rt.generator = &fakeGenForScheduler{bom: cdx.NewBOM()}
	snk := &panicOnceSink{}
	rt.sinkOverride = snk

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("emitScope panicked when a sink panicked: %v", r)
		}
	}()
	rt.emitScope(context.Background(), &rt.scopes[0])

	if got := atomic.LoadInt64(&snk.calls); got != 2 {
		t.Errorf("expected both sinks to be attempted after the first panicked, got %d Send calls", got)
	}
}

// panicGen panics from Generate, as the 2.2.2 nil-FIPS-lookup bug did.
type panicGen struct{ fakeGenForScheduler }

func (*panicGen) Generate(_ context.Context, _ store.CryptoStore, _ *Scope) (*cdx.BOM, error) {
	panic("generate exploded")
}

// Generate runs in emitScope's frame on the same recover-less goroutines as
// sink.Send, so a panic there must also be contained.
func TestRuntime_EmitScope_GeneratePanicIsContained(t *testing.T) {
	cfg := &config.CBOMConfig{
		Enabled: true,
		Scopes: []config.ScopeConfig{{Name: "prod", Sinks: []config.SinkConfig{
			{Type: "file", File: &config.FileSinkConfig{PathTemplate: "/tmp/x.json"}},
		}}},
	}
	rt := NewRuntime(&fakeSchedStore{}, cfg)
	rt.generator = &panicGen{}
	snk := &fakeSinkForScheduler{}
	rt.sinkOverride = snk

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("emitScope panicked when Generate panicked: %v", r)
		}
	}()
	rt.emitScope(context.Background(), &rt.scopes[0])

	if got := atomic.LoadInt64(&snk.sendCalls); got != 0 {
		t.Errorf("sink must not be called when Generate panicked, got %d Send calls", got)
	}
}

// panicOnceProvStore panics on the first GetProvenanceHostIDs call, then
// resolves every asset to host h1.
type panicOnceProvStore struct {
	fakeSchedStore
	calls int64
}

func (s *panicOnceProvStore) GetProvenanceHostIDs(_ context.Context, _, _ string) ([]string, error) {
	if atomic.AddInt64(&s.calls, 1) == 1 {
		panic("store exploded")
	}
	return []string{"h1"}, nil
}

// notifyWorker is a long-lived goroutine: one bad event must not kill it, or
// event-driven pushes silently stop (or the process dies) until restart.
func TestRuntime_NotifyWorker_PanicIsContained(t *testing.T) {
	cfg := &config.CBOMConfig{
		Enabled:          true,
		EventPushEnabled: true,
		Scopes:           []config.ScopeConfig{{Name: "prod", HostIDs: []string{"h1"}}},
	}
	rt := NewRuntime(&panicOnceProvStore{}, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rt.notifyWorker(ctx)

	rt.NotifyAssetScored("certificate", "poison") // store panics on this one
	rt.NotifyAssetScored("certificate", "fp1")    // worker must survive to handle this

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, name := range rt.dirty.Drain() {
			if name == "prod" {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("scope \"prod\" was never marked dirty: notifyWorker did not survive the panicking event")
}
