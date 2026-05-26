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

package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestMetricsEndpoint_ExposesOurMetrics(t *testing.T) {
	RegistryPullsTotal.WithLabelValues("docker.io", "ok").Inc()
	Registry429Total.WithLabelValues("docker.io").Inc()
	ExtractionRejectionsTotal.WithLabelValues("path_traversal").Inc()

	ts := httptest.NewServer(promhttp.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	b := string(body)

	for _, want := range []string{
		"scanner_registry_pulls_total",
		"scanner_registry_429_total",
		"scanner_extraction_rejections_total",
	} {
		if !strings.Contains(b, want) {
			t.Errorf("metric %q missing from /metrics output", want)
		}
	}
}
