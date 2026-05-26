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
	"io"
	"strconv"
	"sync"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom/sinks/s3"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom/sinks/splunk"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom/sinks/syslog"
	"github.com/net4n6-dev/cipherflag/internal/store"
	"github.com/rs/zerolog/log"
)

// generatorIface is the minimal interface the Runtime needs. *Generator and
// test fakes both implement it.
type generatorIface interface {
	Generate(ctx context.Context, st store.CryptoStore, scope *Scope) (*cdx.BOM, error)
	GenerateEvents(ctx context.Context, st store.CryptoStore, scope *Scope, granularity string) ([]SinkEvent, error)
}

// Runtime manages CBOM push background goroutines. Create with NewRuntime;
// start with Start(ctx).
type Runtime struct {
	store        store.CryptoStore
	generator    generatorIface
	scopes       []Scope
	scopeByName  map[string]*Scope
	dirty        *dirtySet
	cfg          *config.CBOMConfig
	notifyCh     chan notifyEvent
	sinkOverride Sink // non-nil in tests; bypasses real sink construction

	sinkMu    sync.Mutex
	sinkCache map[string]Sink // key: scope.Name + "|" + fmt.Sprintf("%d", sinkIndex)
}

// Start launches the scheduled push loop, drain loop, and notify worker.
// All goroutines stop when ctx is cancelled.
func (rt *Runtime) Start(ctx context.Context) {
	if rt.cfg.PushInterval > 0 {
		go rt.scheduledPushLoop(ctx)
	}
	if rt.cfg.EventPushEnabled {
		go rt.drainLoop(ctx)
		go rt.notifyWorker(ctx)
	}
}

// scheduledPushLoop emits all scopes that have sinks on every PushInterval tick.
func (rt *Runtime) scheduledPushLoop(ctx context.Context) {
	ticker := time.NewTicker(rt.cfg.PushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for i := range rt.scopes {
				rt.emitScope(ctx, &rt.scopes[i])
			}
		}
	}
}

// drainLoop emits dirty scopes on every MinEmitInterval tick.
func (rt *Runtime) drainLoop(ctx context.Context) {
	ticker := time.NewTicker(rt.cfg.MinEmitInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, name := range rt.dirty.Drain() {
				scope, ok := rt.scopeByName[name]
				if !ok {
					continue
				}
				rt.emitScope(ctx, scope)
			}
		}
	}
}

// emitScope generates and dispatches to sinks for one scope.
// A scope with no sinks is skipped silently.
// Payloads are lazily generated once per emit call and shared across sinks
// with the same granularity. Generate failure logs and skips affected sinks.
// Sink failure logs and continues to the next sink.
func (rt *Runtime) emitScope(ctx context.Context, scope *Scope) {
	if len(scope.Sinks) == 0 {
		return
	}
	// Lazily generate each payload type the first time a sink in the scope needs it.
	var bom *cdx.BOM
	var bomErr error
	var bomGenerated bool
	eventsByGranularity := map[string][]SinkEvent{}
	eventsErrByGranularity := map[string]error{}

	for i, sc := range scope.Sinks {
		sink := rt.getCachedSink(scope, &sc, i)
		if sink == nil {
			log.Error().Str("scope", scope.Name).Str("sink_type", sc.Type).Msg("cbom: resolveSink returned nil")
			continue
		}
		gran := sc.EffectiveGranularity()
		var payload *SinkPayload
		switch gran {
		case "cbom":
			if !bomGenerated {
				bom, bomErr = rt.generator.Generate(ctx, rt.store, scope)
				bomGenerated = true
				if bomErr != nil {
					log.Error().Err(bomErr).Str("scope", scope.Name).Msg("cbom: generate failed")
				}
			}
			if bomErr != nil {
				continue
			}
			payload = &SinkPayload{BOM: bom}
		case "asset", "finding":
			events, ok := eventsByGranularity[gran]
			if !ok {
				var genErr error
				events, genErr = rt.generator.GenerateEvents(ctx, rt.store, scope, gran)
				if genErr != nil {
					log.Error().Err(genErr).Str("scope", scope.Name).Str("granularity", gran).Msg("cbom: generate events failed")
					eventsErrByGranularity[gran] = genErr
					eventsByGranularity[gran] = nil
					continue
				}
				eventsByGranularity[gran] = events
			}
			if eventsErrByGranularity[gran] != nil {
				continue
			}
			payload = &SinkPayload{Events: events}
		default:
			log.Error().Str("scope", scope.Name).Str("granularity", gran).Msg("cbom: unknown granularity")
			continue
		}

		if err := sink.Send(ctx, payload); err != nil {
			log.Error().Err(err).Str("scope", scope.Name).Str("sink_type", sc.Type).Msg("cbom: sink send failed")
		}
	}
}

// resolveSink returns the Sink to use. In tests, sinkOverride is returned for
// all sink configs (allows a single fake sink to cover all scopes).
func (rt *Runtime) resolveSink(scope *Scope, sc config.SinkConfig) Sink {
	if rt.sinkOverride != nil {
		return rt.sinkOverride
	}
	switch sc.Type {
	case "file":
		return &FileSink{cfg: *sc.File, common: sc, outputDir: rt.cfg.OutputDir, scopeName: scope.Name}
	case "http":
		return &HTTPSink{cfg: *sc.HTTP, common: sc}
	case "s3":
		sink, err := s3.New(context.Background(), *sc.S3, sc, scope.Name)
		if err != nil {
			log.Error().Err(err).Str("scope", scope.Name).Msg("cbom: s3 sink init failed")
			return nil
		}
		return sink
	case "splunk":
		return splunk.New(*sc.Splunk, sc, sc.EffectiveGranularity())
	case "syslog":
		sink, err := syslog.New(*sc.Syslog, sc, scope.Name)
		if err != nil {
			log.Error().Err(err).Str("scope", scope.Name).Msg("cbom: syslog sink init failed")
			return nil
		}
		return sink
	}
	return nil
}

// getCachedSink returns the cached Sink for (scope, index), constructing it
// on first access. Persistent resources (connections, connection pools,
// credential caches) survive across emit ticks.
func (rt *Runtime) getCachedSink(scope *Scope, sc *config.SinkConfig, index int) Sink {
	if rt.sinkOverride != nil {
		return rt.sinkOverride
	}
	key := scope.Name + "|" + strconv.Itoa(index)
	rt.sinkMu.Lock()
	defer rt.sinkMu.Unlock()
	if s, ok := rt.sinkCache[key]; ok {
		return s
	}
	s := rt.resolveSink(scope, *sc)
	if s != nil {
		rt.sinkCache[key] = s
	}
	return s
}

// Stop closes all cached sinks that implement io.Closer. Call after
// cancelling the runtime context to flush/drain in-flight work. Safe to
// call multiple times.
func (rt *Runtime) Stop() {
	rt.sinkMu.Lock()
	defer rt.sinkMu.Unlock()
	for _, s := range rt.sinkCache {
		if c, ok := s.(io.Closer); ok {
			if err := c.Close(); err != nil {
				log.Warn().Err(err).Msg("cbom: sink close failed")
			}
		}
	}
	rt.sinkCache = nil
}
