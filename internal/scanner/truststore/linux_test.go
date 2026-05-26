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
	"testing"
)

func TestDiscoverLinuxOSBundlesFromPaths_ReadsExistingFiles(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca-certificates.crt")
	payload := []byte("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n")
	if err := os.WriteFile(bundle, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "does-not-exist.crt")

	got := discoverLinuxOSBundlesFromPaths(context.Background(), []string{bundle, missing})

	if len(got) != 1 {
		t.Fatalf("got %d bundles, want 1 (one of two paths exists)", len(got))
	}
	if got[0].Source != "os_bundle" || got[0].Format != "pem" {
		t.Errorf("got %+v, want source=os_bundle format=pem", got[0])
	}
	if got[0].SourceDetail != bundle {
		t.Errorf("SourceDetail = %s, want %s", got[0].SourceDetail, bundle)
	}
}
