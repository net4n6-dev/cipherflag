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

package truststore

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverRuntimeBundles_PythonCertifi(t *testing.T) {
	dir := t.TempDir()
	cacertPath := filepath.Join(dir, "cacert.pem")
	payload := []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")
	if err := os.WriteFile(cacertPath, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	runner := &fakeRunner{responses: map[string][]byte{
		"python -c import certifi; print(certifi.where())": []byte(cacertPath + "\n"),
	}}
	s := &Scanner{runner: runner}

	got, _ := discoverRuntimeBundles(context.Background(), s)
	var found bool
	for _, b := range got {
		if strings.HasPrefix(b.SourceDetail, "python:certifi:") && b.Source == "lang_runtime" {
			found = true
		}
	}
	if !found {
		t.Errorf("missing python:certifi bundle; got %+v", got)
	}
}

func TestDiscoverRuntimeBundles_NodeExtraCACerts(t *testing.T) {
	dir := t.TempDir()
	nodeCAs := filepath.Join(dir, "node-ca.pem")
	payload := []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")
	if err := os.WriteFile(nodeCAs, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NODE_EXTRA_CA_CERTS", nodeCAs)
	s := &Scanner{runner: nil}

	got, _ := discoverRuntimeBundles(context.Background(), s)
	var found bool
	for _, b := range got {
		if b.SourceDetail == "node:NODE_EXTRA_CA_CERTS:"+nodeCAs {
			found = true
		}
	}
	if !found {
		t.Errorf("missing node:NODE_EXTRA_CA_CERTS bundle; got %+v", got)
	}
}

func TestDiscoverRuntimeBundles_NoRunnerReturnsNoShellResults(t *testing.T) {
	s := &Scanner{runner: nil}
	got, _ := discoverRuntimeBundles(context.Background(), s)
	// Without runner, Python and Ruby paths can't be probed; ony NODE_EXTRA_CA_CERTS env path can fire.
	for _, b := range got {
		if strings.Contains(b.SourceDetail, "python:") || strings.Contains(b.SourceDetail, "ruby:") {
			t.Errorf("got shell-discovered bundle without runner: %+v", b)
		}
	}
}
