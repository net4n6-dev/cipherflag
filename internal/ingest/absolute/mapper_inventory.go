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

package absolute

import (
	"fmt"
	"strings"

	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
	"github.com/net4n6-dev/cipherflag/internal/normalize"
)

// absoluteToLibraryName maps Absolute software-inventory AppName values to
// CipherFlag's canonical library names. Lookup is lowercased: exact match
// first, then prefix match.
//
// Keep the filters returned by CryptoLibFilters in sync with this map.
var absoluteToLibraryName = map[string]string{
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

// CryptoLibFilters returns the name substrings the poller passes to
// ListInstalledApplications. Keep in sync with absoluteToLibraryName.
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
	if v, ok := absoluteToLibraryName[lower]; ok {
		return v
	}
	for prefix, canonical := range absoluteToLibraryName {
		if strings.HasPrefix(lower, prefix) {
			return canonical
		}
	}
	return lower
}

// MapDeviceApp converts a DeviceApp into a LibraryDiscovery. Returns an
// error when required identity fields are missing.
//
// Source is left empty — the poller fills it in when assembling the
// DiscoveryResult. PackageManager is "absolute-inventory".
func MapDeviceApp(app DeviceApp) (dedup.LibraryDiscovery, error) {
	if app.AppName == "" {
		return dedup.LibraryDiscovery{}, fmt.Errorf("DeviceApp missing AppName")
	}
	if app.AppVersion == "" {
		return dedup.LibraryDiscovery{}, fmt.Errorf("DeviceApp missing AppVersion (required for dedup identity)")
	}
	return dedup.LibraryDiscovery{
		LibraryName:    canonicalLibraryName(app.AppName),
		Version:        app.AppVersion,
		PackageName:    app.AppName,
		PackageManager: "absolute-inventory",
		InstallPath:    "",
	}, nil
}

// DeviceMetadata is the per-device context extracted from any of a device's
// DeviceApp rows.
type DeviceMetadata struct {
	DeviceID   string
	DeviceName string
	OSFamily   string
}

// ExtractDeviceMetadata pulls per-device fields from a DeviceApp,
// normalizing the OS family via internal/normalize.
func ExtractDeviceMetadata(app DeviceApp) DeviceMetadata {
	return DeviceMetadata{
		DeviceID:   app.DeviceID,
		DeviceName: app.DeviceName,
		OSFamily:   normalize.Platform(app.OSPlatform),
	}
}

// GroupAppsByDevice groups DeviceApps by DeviceID. Rows missing DeviceID
// are dropped silently — the caller decides whether to log.
func GroupAppsByDevice(apps []DeviceApp) map[string][]DeviceApp {
	out := make(map[string][]DeviceApp)
	for _, a := range apps {
		if a.DeviceID == "" {
			continue
		}
		out[a.DeviceID] = append(out[a.DeviceID], a)
	}
	return out
}
