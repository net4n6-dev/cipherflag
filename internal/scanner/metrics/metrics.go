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

// Package metrics defines the Prometheus counters/histograms/gauges
// exposed by cipherflag-scanner when [scanner.metrics].enabled=true.
package metrics

import (
	"context"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
)

var (
	RegistryPullsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "scanner_registry_pulls_total",
			Help: "Total image pulls attempted, by registry and status.",
		},
		[]string{"registry", "status"},
	)
	Registry429Total = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "scanner_registry_429_total",
			Help: "Total rate-limit responses from registries.",
		},
		[]string{"registry"},
	)
	ExtractionRejectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "scanner_extraction_rejections_total",
			Help: "Total extractor security rejections, by reason.",
		},
		[]string{"reason"},
	)
	LayerExtractDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "scanner_layer_extract_duration_seconds",
			Help:    "Layer extraction duration, by media type.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"layer_media_type"},
	)
	LayerCacheBytes = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "scanner_layer_cache_bytes_on_disk",
		Help: "Current layer cache size in bytes.",
	})
	LayerCacheHitRatio = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "scanner_layer_cache_hit_ratio",
		Help: "Rolling layer-cache hit ratio (0..1).",
	})
	LLMCallsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "scanner_llm_calls_total",
			Help: "LLM call outcomes, by bucket and status.",
		},
		[]string{"bucket", "status"},
	)
)

func init() {
	prometheus.MustRegister(
		RegistryPullsTotal, Registry429Total, ExtractionRejectionsTotal,
		LayerExtractDuration, LayerCacheBytes, LayerCacheHitRatio, LLMCallsTotal,
	)
}

// StartServer starts the /metrics HTTP server on listen. Returns a shutdown
// function. Logs and returns nil shutdown if startup fails (non-fatal for
// scanner boot).
func StartServer(listen string) func(context.Context) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	srv := &http.Server{Addr: listen, Handler: mux}
	go func() {
		log.Info().Str("listen", listen).Msg("metrics server starting")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Warn().Err(err).Msg("metrics server")
		}
	}()
	return srv.Shutdown
}
