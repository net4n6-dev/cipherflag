// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package tanium

import (
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
	"github.com/net4n6-dev/cipherflag/internal/ingest/scriptparse"
	"github.com/net4n6-dev/cipherflag/internal/normalize"
)

// taniumToLibraryName maps Installed Applications application names to
// CipherFlag's canonical library names. Lookup is lowercased: exact match
// first, then prefix match.
var taniumToLibraryName = map[string]string{
	"openssl":       "openssl",
	"libssl":        "openssl",
	"libssl3":       "openssl",
	"libssl1.1":     "openssl",
	"gnutls":        "gnutls",
	"libgnutls":     "gnutls",
	"nss":           "nss",
	"libnss":        "nss",
	"libgcrypt":     "libgcrypt",
	"libsodium":     "libsodium",
	"wolfssl":       "wolfssl",
	"bouncycastle":  "bouncycastle",
	"bouncy castle": "bouncycastle",
	"libressl":      "libressl",
	"mbedtls":       "mbedtls",
	"nettle":        "nettle",
}

func canonicalLibraryName(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	if v, ok := taniumToLibraryName[lower]; ok {
		return v
	}
	for prefix, canonical := range taniumToLibraryName {
		if strings.HasPrefix(lower, prefix) {
			return canonical
		}
	}
	return lower
}

// isCryptoLibrary returns true when the given app name matches a known crypto
// library (exact or prefix match on the lowercased, trimmed input).
func isCryptoLibrary(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if _, ok := taniumToLibraryName[lower]; ok {
		return true
	}
	for prefix := range taniumToLibraryName {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// BuildDiscoveryResult builds a single DiscoveryResult for one Tanium
// endpoint. Custom-sensor NDJSON rows are parsed via scriptparse; Installed
// Applications rows are filtered for crypto libraries and mapped to
// LibraryDiscovery with PackageManager="tanium-inventory".
func BuildDiscoveryResult(ep EndpointResult) *ingest.DiscoveryResult {
	result := &ingest.DiscoveryResult{
		Source:       "tanium",
		SourceHostID: ep.EndpointID,
		Hostname:     ep.Hostname,
		OSFamily:     normalize.Platform(ep.OSPlatform),
		Timestamp:    time.Now().UTC(),
	}
	if ep.IPAddress != "" {
		result.IPAddresses = []string{ep.IPAddress}
	}

	for _, sr := range ep.Sensors {
		switch sr.SensorName {
		case "Installed Applications":
			mergeInstalledApps(result, sr, ep.EndpointID)
		default:
			mergeCustomSensor(result, sr, ep.EndpointID)
		}
	}
	return result
}

func mergeCustomSensor(result *ingest.DiscoveryResult, sr SensorReading, endpointID string) {
	if len(sr.Columns) == 0 {
		return
	}
	var sb strings.Builder
	for _, val := range sr.Columns[0].Values {
		sb.WriteString(val)
		sb.WriteByte('\n')
	}
	parsed, parseErrs, err := scriptparse.ParseNDJSON(strings.NewReader(sb.String()), "tanium", result.Hostname)
	if err != nil {
		log.Warn().Err(err).Str("endpoint_id", endpointID).Str("sensor", sr.SensorName).Msg("tanium: NDJSON stream error, partial results may apply")
	}
	for _, pe := range parseErrs {
		log.Warn().Int("line", pe.Line).Str("reason", pe.Reason).Str("endpoint_id", endpointID).Str("sensor", sr.SensorName).Msg("tanium: skipped malformed NDJSON line")
	}
	if parsed == nil {
		return
	}
	result.Certificates = append(result.Certificates, parsed.Certificates...)
	result.SSHKeys = append(result.SSHKeys, parsed.SSHKeys...)
	result.Libraries = append(result.Libraries, parsed.Libraries...)
	result.Configs = append(result.Configs, parsed.Configs...)
}

func mergeInstalledApps(result *ingest.DiscoveryResult, sr SensorReading, endpointID string) {
	byName := map[string][]string{}
	for _, col := range sr.Columns {
		byName[col.Name] = col.Values
	}
	names := byName["Name"]
	versions := byName["Version"]
	if len(names) == 0 {
		return
	}
	for i, rawName := range names {
		if !isCryptoLibrary(rawName) {
			continue
		}
		version := ""
		if i < len(versions) {
			version = versions[i]
		}
		if version == "" {
			log.Warn().Str("endpoint_id", endpointID).Str("app", rawName).Msg("tanium: skipping Installed Applications row with missing version")
			continue
		}
		result.Libraries = append(result.Libraries, dedup.LibraryDiscovery{
			LibraryName:    canonicalLibraryName(rawName),
			Version:        version,
			PackageName:    rawName,
			PackageManager: "tanium-inventory",
			InstallPath:    "",
		})
	}
}
