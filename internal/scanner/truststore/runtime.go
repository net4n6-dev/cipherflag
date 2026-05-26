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
	"strings"

	"github.com/rs/zerolog/log"
)

func discoverRuntimeBundles(ctx context.Context, s *Scanner) ([]bundleObservation, error) {
	var out []bundleObservation

	if s.runner != nil {
		if data, _, err := s.runner.Run(ctx, "python", "-c", "import certifi; print(certifi.where())"); err == nil {
			path := strings.TrimSpace(string(data))
			if path != "" {
				if bundleData, err := os.ReadFile(path); err == nil {
					out = append(out, bundleObservation{
						Path: path, Source: "lang_runtime",
						SourceDetail: "python:certifi:" + path,
						Format: "pem", Data: bundleData,
					})
				}
			}
		} else {
			log.Debug().Err(err).Msg("python certifi probe failed")
		}
	}

	if extra := os.Getenv("NODE_EXTRA_CA_CERTS"); extra != "" {
		if data, err := os.ReadFile(extra); err == nil {
			out = append(out, bundleObservation{
				Path: extra, Source: "lang_runtime",
				SourceDetail: "node:NODE_EXTRA_CA_CERTS:" + extra,
				Format: "pem", Data: data,
			})
		}
	}

	if s.runner != nil {
		if data, _, err := s.runner.Run(ctx, "ruby", "-r", "openssl", "-e", "puts OpenSSL::X509::DEFAULT_CERT_FILE"); err == nil {
			path := strings.TrimSpace(string(data))
			if path != "" {
				if bundleData, err := os.ReadFile(path); err == nil {
					out = append(out, bundleObservation{
						Path: path, Source: "lang_runtime",
						SourceDetail: "ruby:openssl:" + path,
						Format: "pem", Data: bundleData,
					})
				}
			}
		}
	}

	return out, nil
}
