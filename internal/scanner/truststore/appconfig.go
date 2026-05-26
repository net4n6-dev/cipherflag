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
	"bufio"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/certparse"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

// TrustBundleRef is a directive-derived pointer from a config file to a
// trust-bundle file on disk. Returned by ParseTrustBundleDirectives for
// the configs scanner to call.
type TrustBundleRef struct {
	Server     string // nginx | apache | postgres
	ConfigPath string
	Directive  string
	BundlePath string
}

// TrustBundlePaths is the default set of config file paths that ScanTrustBundles
// should walk. Exported so the CLI can pass it without duplicating the list.
// The configs scanner also expands trustBundleGlobs on top of this slice.
var TrustBundlePaths = []string{
	"/etc/nginx/nginx.conf",
	"/etc/apache2/sites-enabled/default-ssl.conf",
	"/etc/httpd/conf.d/ssl.conf",
	"/etc/postgresql/postgresql.conf",
}

// trustDirectives maps directive names to the server they belong to.
var trustDirectives = map[string]string{
	"ssl_trusted_certificate": "nginx",
	"SSLCACertificateFile":    "apache",
	"ssl_ca_file":             "postgres",
}

// IngestAppConfigBundles reads each bundle file pointed to by refs, decodes
// all PEM CERTIFICATE blocks, and returns one TrustStoreObservation per
// certificate. Source is always "app_config"; SourceDetail encodes the
// originating server, config path, and directive in the form
// "<server>:<configPath>:<directive>". Per-file and per-block errors are
// logged at warn level and skipped so the caller always gets a partial result
// rather than a hard failure.
func IngestAppConfigBundles(refs []TrustBundleRef) ([]model.TrustStoreObservation, error) {
	var out []model.TrustStoreObservation
	for _, ref := range refs {
		data, err := os.ReadFile(ref.BundlePath)
		if err != nil {
			log.Warn().Err(err).
				Str("bundle", ref.BundlePath).
				Str("config", ref.ConfigPath).
				Msg("app_config trust bundle: cannot read file, skipping")
			continue
		}
		sourceDetail := fmt.Sprintf("%s:%s:%s", ref.Server, ref.ConfigPath, ref.Directive)
		rest := data
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := certparse.ParseDER(block.Bytes)
			if err != nil {
				log.Warn().Err(err).
					Str("bundle", ref.BundlePath).
					Str("source_detail", sourceDetail).
					Msg("app_config trust bundle: PEM cert parse failed, skipping block")
				continue
			}
			out = append(out, model.TrustStoreObservation{
				CAFingerprint: cert.FingerprintSHA256,
				Source:        "app_config",
				SourceDetail:  sourceDetail,
			})
		}
	}
	return out, nil
}

// ParseTrustBundleDirectives scans a config file for trust-bundle
// directives and returns one TrustBundleRef per occurrence. Comments and
// whitespace are ignored. Quoted paths are unwrapped.
func ParseTrustBundleDirectives(configPath string) []TrustBundleRef {
	f, err := os.Open(configPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []TrustBundleRef
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for directive, server := range trustDirectives {
			if !strings.HasPrefix(line, directive) {
				continue
			}
			rest := strings.TrimSpace(strings.TrimPrefix(line, directive))
			rest = strings.TrimSuffix(strings.TrimSpace(rest), ";")
			path := strings.Trim(rest, `"`)
			if path == "" {
				continue
			}
			out = append(out, TrustBundleRef{
				Server: server, ConfigPath: configPath,
				Directive: directive, BundlePath: path,
			})
		}
	}
	return out
}
