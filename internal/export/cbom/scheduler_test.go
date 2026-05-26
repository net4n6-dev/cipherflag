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
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// fakeGenForScheduler satisfies the generatorIface used by the runtime.
type fakeGenForScheduler struct {
	generateCalls int64
	bom           *cdx.BOM
	err           error
}

func (f *fakeGenForScheduler) Generate(_ context.Context, _ store.CryptoStore, _ *Scope) (*cdx.BOM, error) {
	atomic.AddInt64(&f.generateCalls, 1)
	return f.bom, f.err
}

func (f *fakeGenForScheduler) GenerateEvents(_ context.Context, _ store.CryptoStore, _ *Scope, _ string) ([]SinkEvent, error) {
	return nil, nil
}

// fakeSinkForScheduler records how many times Send was called.
type fakeSinkForScheduler struct {
	sendCalls int64
	err       error
}

func (f *fakeSinkForScheduler) Send(_ context.Context, _ *SinkPayload) error {
	atomic.AddInt64(&f.sendCalls, 1)
	return f.err
}

// fakeSchedStore is a minimal store for Runtime construction.
type fakeSchedStore struct {
	store.CryptoStore
}

func (f *fakeSchedStore) GetHostIDsByPatterns(_ context.Context, _ []string) ([]string, error) {
	return nil, nil
}
func (f *fakeSchedStore) GetProvenanceHostIDs(_ context.Context, _, _ string) ([]string, error) {
	return nil, nil
}
func (f *fakeSchedStore) ListScopeAssets(_ context.Context, _ store.ScopeAssetQuery) ([]store.ScopeAssetRow, error) {
	return nil, nil
}

func TestRuntime_NotifyAssetScored_NonBlocking(t *testing.T) {
	cfg := &config.CBOMConfig{
		Enabled:          true,
		EventPushEnabled: true,
		MinEmitInterval:  time.Minute,
		Scopes: []config.ScopeConfig{
			{Name: "prod", HostIDs: []string{"h1"}},
		},
	}
	rt := NewRuntime(&fakeSchedStore{}, cfg)
	// Fill the channel to capacity and beyond — must never block
	for i := 0; i < cap(rt.notifyCh)+10; i++ {
		rt.NotifyAssetScored("certificate", "fp1")
	}
}

func TestRuntime_EmitScope_CallsGenerateAndSink(t *testing.T) {
	gen := &fakeGenForScheduler{bom: cdx.NewBOM()}
	snk := &fakeSinkForScheduler{}
	fakeSinkCfg := config.SinkConfig{Type: "file", File: &config.FileSinkConfig{PathTemplate: "/tmp/test.cdx.json"}}

	cfg := &config.CBOMConfig{
		Enabled: true,
		Scopes: []config.ScopeConfig{{
			Name:  "prod",
			Sinks: []config.SinkConfig{fakeSinkCfg},
		}},
	}
	rt := NewRuntime(&fakeSchedStore{}, cfg)
	rt.generator = gen

	scope := &rt.scopes[0]
	rt.sinkOverride = snk // test hook: override sink creation

	rt.emitScope(context.Background(), scope)

	if atomic.LoadInt64(&gen.generateCalls) != 1 {
		t.Errorf("expected 1 generate call, got %d", atomic.LoadInt64(&gen.generateCalls))
	}
	if atomic.LoadInt64(&snk.sendCalls) != 1 {
		t.Errorf("expected 1 sink send call, got %d", atomic.LoadInt64(&snk.sendCalls))
	}
}

func TestRuntime_EmitScope_GenerateErrorSkipsSink(t *testing.T) {
	gen := &fakeGenForScheduler{err: fmt.Errorf("db error")}
	snk := &fakeSinkForScheduler{}

	cfg := &config.CBOMConfig{
		Enabled: true,
		Scopes:  []config.ScopeConfig{{Name: "prod", Sinks: []config.SinkConfig{{Type: "file", File: &config.FileSinkConfig{PathTemplate: "/tmp/x.json"}}}}},
	}
	rt := NewRuntime(&fakeSchedStore{}, cfg)
	rt.generator = gen
	rt.sinkOverride = snk

	rt.emitScope(context.Background(), &rt.scopes[0])

	if atomic.LoadInt64(&snk.sendCalls) != 0 {
		t.Errorf("sink should not be called when generate fails")
	}
}

func TestRuntime_EmitScope_NoSinksSkipsGenerate(t *testing.T) {
	gen := &fakeGenForScheduler{bom: cdx.NewBOM()}
	cfg := &config.CBOMConfig{
		Enabled: true,
		Scopes:  []config.ScopeConfig{{Name: "dmz"}}, // no sinks
	}
	rt := NewRuntime(&fakeSchedStore{}, cfg)
	rt.generator = gen

	rt.emitScope(context.Background(), &rt.scopes[0])
	if atomic.LoadInt64(&gen.generateCalls) != 0 {
		t.Errorf("generate should not be called for scope with no sinks")
	}
}

func TestDirtySet_IntegrationWithDrainLoop(t *testing.T) {
	cfg := &config.CBOMConfig{
		Enabled:         true,
		MinEmitInterval: 50 * time.Millisecond,
		Scopes: []config.ScopeConfig{{
			Name:  "prod",
			Sinks: []config.SinkConfig{{Type: "file", File: &config.FileSinkConfig{PathTemplate: "/tmp/prod.cdx.json"}}},
		}},
	}
	gen := &fakeGenForScheduler{bom: cdx.NewBOM()}
	snk := &fakeSinkForScheduler{}

	rt := NewRuntime(&fakeSchedStore{}, cfg)
	rt.generator = gen
	rt.sinkOverride = snk

	rt.dirty.Mark("prod")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	go rt.drainLoop(ctx)

	time.Sleep(120 * time.Millisecond)
	if atomic.LoadInt64(&snk.sendCalls) == 0 {
		t.Error("expected drain loop to emit the dirty scope")
	}
}

func TestRuntime_ScopeByName(t *testing.T) {
	cfg := &config.CBOMConfig{
		Scopes: []config.ScopeConfig{
			{Name: "a"}, {Name: "b"},
		},
	}
	rt := NewRuntime(&fakeSchedStore{}, cfg)
	if rt.scopeByName["a"] == nil || rt.scopeByName["b"] == nil {
		t.Error("scopeByName should index both scopes")
	}
	if rt.scopeByName["c"] != nil {
		t.Error("scopeByName should not contain unknown scope")
	}
}

func TestEmitScope_MixedGranularitySinks(t *testing.T) {
	fakeGen := &mixedGenFake{
		bom:           &cdx.BOM{SerialNumber: "urn:uuid:test"},
		assetEvents:   []SinkEvent{{EventType: "asset", AssetID: "a1"}},
		findingEvents: []SinkEvent{{EventType: "finding", AssetID: "a1"}},
	}
	captures := &captureSink{}
	rt := &Runtime{
		generator:    fakeGen,
		sinkOverride: captures,
		cfg:          &config.CBOMConfig{},
	}
	scope := &Scope{
		Name: "test",
		Sinks: []config.SinkConfig{
			{Type: "file", Granularity: "cbom", File: &config.FileSinkConfig{PathTemplate: "x"}},
			{Type: "splunk", Granularity: "asset", Splunk: &config.SplunkSinkConfig{URL: "x", TokenRef: "T"}},
			{Type: "syslog", Granularity: "finding", Syslog: &config.SyslogSinkConfig{Protocol: "udp", Address: "x", Format: "rfc5424"}},
		},
	}
	rt.emitScope(context.Background(), scope)

	if len(captures.payloads) != 3 {
		t.Fatalf("payload count = %d, want 3", len(captures.payloads))
	}
	if captures.payloads[0].BOM == nil {
		t.Error("payload[0] should be BOM (cbom granularity)")
	}
	if captures.payloads[1].Events == nil || captures.payloads[1].Events[0].EventType != "asset" {
		t.Error("payload[1] should be asset events")
	}
	if captures.payloads[2].Events == nil || captures.payloads[2].Events[0].EventType != "finding" {
		t.Error("payload[2] should be finding events")
	}
}

type mixedGenFake struct {
	bom           *cdx.BOM
	assetEvents   []SinkEvent
	findingEvents []SinkEvent
}

func (f *mixedGenFake) Generate(_ context.Context, _ store.CryptoStore, _ *Scope) (*cdx.BOM, error) {
	return f.bom, nil
}
func (f *mixedGenFake) GenerateEvents(_ context.Context, _ store.CryptoStore, _ *Scope, granularity string) ([]SinkEvent, error) {
	if granularity == "finding" {
		return f.findingEvents, nil
	}
	return f.assetEvents, nil
}

type captureSink struct {
	payloads []*SinkPayload
}

func (c *captureSink) Send(_ context.Context, p *SinkPayload) error {
	c.payloads = append(c.payloads, p)
	return nil
}
