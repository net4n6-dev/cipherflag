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

	"github.com/rs/zerolog/log"
)

var macosKeychainPaths = []string{
	"/System/Library/Keychains/SystemRootCertificates.keychain",
	"/Library/Keychains/System.keychain",
}

func discoverMacOSKeychains(ctx context.Context, s *Scanner) ([]bundleObservation, error) {
	if s.runner == nil {
		return nil, nil
	}
	var out []bundleObservation
	for _, kc := range macosKeychainPaths {
		pemOut, _, err := s.runner.Run(ctx, "security", "find-certificate", "-a", "-p", kc)
		if err != nil {
			log.Warn().Err(err).Str("keychain", kc).Msg("macOS keychain read failed, skipping")
			continue
		}
		out = append(out, bundleObservation{
			Path: kc, Source: "os_bundle", SourceDetail: kc,
			Format: "pem", Data: pemOut,
		})
	}
	return out, nil
}
