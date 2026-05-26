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

package b1

import (
	"context"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
)

func TestB1Dispatcher_RoutesByMagicOrExt(t *testing.T) {
	disp := NewDispatcher(DispatcherOptions{CommonPasswords: []string{""}})

	certPEM := genSelfSignedCertPEM(t)
	blob := enumerate.Blob{Path: "certs/x.pem", Size: int64(len(certPEM))}
	findings, err := disp.Detect(context.Background(), blob, certPEM)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected PEM finding")
	}
}

func TestB1Dispatcher_DedupesPEMWithSSHPrivkeyFile(t *testing.T) {
	// A file named id_rsa with valid OPENSSH PRIVATE KEY PEM content matches
	// both PEMDetector and SSHDetector. Dispatcher must emit only one finding
	// for the same (path, rule_id) to avoid double-counting.
	disp := NewDispatcher(DispatcherOptions{})
	data := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n")
	blob := enumerate.Blob{Path: "keys/id_rsa", Size: int64(len(data))}
	findings, _ := disp.Detect(context.Background(), blob, data)

	crit := 0
	for _, f := range findings {
		if f.Severity == "Critical" {
			crit++
		}
	}
	if crit > 1 {
		t.Errorf("expected <=1 Critical finding for id_rsa, got %d", crit)
	}
}
