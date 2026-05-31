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
package defender

import (
	"fmt"
	"strings"

	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
	"github.com/net4n6-dev/cipherflag/internal/normalize"
)

// defenderToLibraryName maps Defender's SoftwareName values to CipherFlag's
// canonical library names. Lookup is lowercased, exact-match first, then
// prefix-match (so "OpenSSL 3.0.14" → "openssl").
//
// Keep in sync with the KQL `has_any` filter in poller.go.
var defenderToLibraryName = map[string]string{
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

// canonicalLibraryName returns the CipherFlag canonical name for a
// Defender SoftwareName. Lowercases, tries exact match, then prefix match.
// Unknown names return the lowercased input.
func canonicalLibraryName(softwareName string) string {
	lower := strings.ToLower(strings.TrimSpace(softwareName))
	if canonical, ok := defenderToLibraryName[lower]; ok {
		return canonical
	}
	// Prefix-match: e.g., "openssl 3.0.14" or "bouncy castle x.y".
	for prefix, canonical := range defenderToLibraryName {
		if strings.HasPrefix(lower, prefix) {
			return canonical
		}
	}
	return lower
}

// MapRow converts a single DeviceTvmSoftwareInventory row into a
// LibraryDiscovery. Returns an error when the row is missing required
// identity fields (DeviceId, SoftwareVersion).
//
// Source is left empty — the poller fills it in when assembling the
// DiscoveryResult. PackageManager is hardcoded to "microsoft-defender".
// InstallPath is empty (not exposed by this table).
func MapRow(row QueryRow) (dedup.LibraryDiscovery, error) {
	deviceID := stringField(row.Columns, "DeviceId")
	if deviceID == "" {
		return dedup.LibraryDiscovery{}, fmt.Errorf("row missing DeviceId")
	}
	version := stringField(row.Columns, "SoftwareVersion")
	if version == "" {
		return dedup.LibraryDiscovery{}, fmt.Errorf("row missing SoftwareVersion (required for dedup identity)")
	}
	rawName := stringField(row.Columns, "SoftwareName")

	return dedup.LibraryDiscovery{
		LibraryName:    canonicalLibraryName(rawName),
		Version:        version,
		PackageName:    rawName,
		PackageManager: "microsoft-defender",
		InstallPath:    "",
		PQCCapable:     false,
	}, nil
}

// DeviceMetadata is the per-device context extracted from any of that
// device's rows (all rows for the same DeviceId carry identical metadata).
type DeviceMetadata struct {
	DeviceID   string
	DeviceName string
	OSFamily   string
}

// ExtractDeviceMetadata pulls per-device fields from a row, normalizing
// the OS platform via internal/normalize.
func ExtractDeviceMetadata(row QueryRow) DeviceMetadata {
	return DeviceMetadata{
		DeviceID:   stringField(row.Columns, "DeviceId"),
		DeviceName: stringField(row.Columns, "DeviceName"),
		OSFamily:   normalize.Platform(stringField(row.Columns, "OSPlatform")),
	}
}

// GroupRowsByDevice groups rows by their DeviceId. Rows missing DeviceId
// are silently dropped — the caller decides whether to log.
func GroupRowsByDevice(rows []QueryRow) map[string][]QueryRow {
	out := make(map[string][]QueryRow)
	for _, row := range rows {
		id := stringField(row.Columns, "DeviceId")
		if id == "" {
			continue
		}
		out[id] = append(out[id], row)
	}
	return out
}

// stringField returns m[key] as a string, or "" if absent or non-string.
func stringField(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
