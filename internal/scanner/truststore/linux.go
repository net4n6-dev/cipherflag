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

	"github.com/rs/zerolog/log"
)

var linuxOSBundlePaths = []string{
	"/etc/ssl/certs/ca-certificates.crt",                 // Debian/Ubuntu
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // RHEL/Fedora
	"/etc/ssl/cert.pem",                                  // Alpine + other musl
}

func discoverLinuxOSBundles(ctx context.Context, _ *Scanner) ([]bundleObservation, error) {
	return discoverLinuxOSBundlesFromPaths(ctx, linuxOSBundlePaths), nil
}

// discoverLinuxOSBundlesFromPaths is the testable shape — pass in the
// path list explicitly so tests don't depend on host layout.
func discoverLinuxOSBundlesFromPaths(_ context.Context, paths []string) []bundleObservation {
	var out []bundleObservation
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			log.Debug().Err(err).Str("path", p).Msg("os bundle not present, skipping")
			continue
		}
		out = append(out, bundleObservation{
			Path: p, Source: "os_bundle", SourceDetail: p,
			Format: "pem", Data: data,
		})
	}
	return out
}
