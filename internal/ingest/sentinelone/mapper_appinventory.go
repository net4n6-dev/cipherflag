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
package sentinelone

import (
	"fmt"
	"strings"

	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
	"github.com/net4n6-dev/cipherflag/internal/normalize"
)

// sentinelOneToLibraryName maps SentinelOne App Inventory AppName values
// to CipherFlag's canonical library names. Lookup is lowercased: exact
// match first, then prefix match.
//
// Keep the filters returned by CryptoLibFilters in sync with this map.
var sentinelOneToLibraryName = map[string]string{
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

// CryptoLibFilters returns the name__contains substrings that the poller
// passes to ListInstalledApplications. Keep in sync with
// sentinelOneToLibraryName.
func CryptoLibFilters() []string {
	return []string{
		"openssl", "libssl",
		"gnutls", "libgnutls",
		"nss", "libnss",
		"libgcrypt",
		"libsodium",
		"wolfssl",
		"bouncycastle", "bouncy castle",
		"libressl",
		"mbedtls",
		"nettle",
	}
}

func canonicalLibraryName(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	if v, ok := sentinelOneToLibraryName[lower]; ok {
		return v
	}
	for prefix, canonical := range sentinelOneToLibraryName {
		if strings.HasPrefix(lower, prefix) {
			return canonical
		}
	}
	return lower
}

// MapAppRecord converts an AppRecord into a LibraryDiscovery. Returns an
// error when required identity fields are missing.
//
// Source is left empty — the poller fills it in when assembling the
// DiscoveryResult. PackageManager is "sentinelone-inventory". InstallPath
// is empty (not exposed by this endpoint).
func MapAppRecord(rec AppRecord) (dedup.LibraryDiscovery, error) {
	if rec.AppName == "" {
		return dedup.LibraryDiscovery{}, fmt.Errorf("AppRecord missing AppName")
	}
	if rec.AppVersion == "" {
		return dedup.LibraryDiscovery{}, fmt.Errorf("AppRecord missing AppVersion (required for dedup identity)")
	}
	return dedup.LibraryDiscovery{
		LibraryName:    canonicalLibraryName(rec.AppName),
		Version:        rec.AppVersion,
		PackageName:    rec.AppName,
		PackageManager: "sentinelone-inventory",
		InstallPath:    "",
	}, nil
}

// AgentMetadata is the per-agent context extracted from any of that agent's
// AppRecords.
type AgentMetadata struct {
	AgentUUID string
	AgentName string
	OSFamily  string
}

// ExtractAgentMetadata pulls per-agent fields from an AppRecord, normalizing
// the OS family via internal/normalize.
func ExtractAgentMetadata(rec AppRecord) AgentMetadata {
	return AgentMetadata{
		AgentUUID: rec.AgentUUID,
		AgentName: rec.AgentName,
		OSFamily:  normalize.Platform(rec.OSType),
	}
}

// GroupAppsByAgent groups AppRecords by their AgentUUID. Records missing
// AgentUUID are dropped silently — the caller decides whether to log.
func GroupAppsByAgent(apps []AppRecord) map[string][]AppRecord {
	out := make(map[string][]AppRecord)
	for _, a := range apps {
		if a.AgentUUID == "" {
			continue
		}
		out[a.AgentUUID] = append(out[a.AgentUUID], a)
	}
	return out
}
