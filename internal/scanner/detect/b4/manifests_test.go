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

package b4

import (
	"context"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

func TestK8sTLSSecret_Critical(t *testing.T) {
	d := &ManifestDetector{}
	data := []byte(`
apiVersion: v1
kind: Secret
type: kubernetes.io/tls
metadata:
  name: prod-tls
data:
  tls.crt: BASE64STUFF
  tls.key: BASE64SECRET
`)
	blob := enumerate.Blob{Path: "k8s/tls-secret.yaml", Size: int64(len(data))}
	findings, err := d.Detect(context.Background(), blob, data)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("want finding")
	}
	f := findings[0]
	if f.RuleID != "K8S-TLS-SECRET-IN-REPO" {
		t.Errorf("rule_id: %q", f.RuleID)
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("severity: %q (want Critical)", f.Severity)
	}
}

func TestDockerfile_CopyOfPEM(t *testing.T) {
	d := &ManifestDetector{}
	data := []byte(`
FROM nginx:1.24
COPY certs/server.pem /etc/nginx/server.pem
COPY certs/server.key /etc/nginx/server.key
`)
	blob := enumerate.Blob{Path: "Dockerfile", Size: int64(len(data))}
	findings, _ := d.Detect(context.Background(), blob, data)
	if len(findings) < 1 {
		t.Errorf("want >=1 finding, got %d", len(findings))
	}
	for _, f := range findings {
		if f.RuleID != "DOCKERFILE-COPY-KEY-MATERIAL" {
			t.Errorf("rule_id: %q", f.RuleID)
		}
	}
}

func TestSystemd_LoadCredential(t *testing.T) {
	d := &ManifestDetector{}
	data := []byte(`
[Service]
LoadCredential=tls.key:/etc/secrets/tls.key
LoadCredential=tls.crt:/etc/secrets/tls.crt
`)
	blob := enumerate.Blob{Path: "systemd/app.service", Size: int64(len(data))}
	findings, _ := d.Detect(context.Background(), blob, data)
	if len(findings) < 1 {
		t.Errorf("want >=1 finding, got %d", len(findings))
	}
}
