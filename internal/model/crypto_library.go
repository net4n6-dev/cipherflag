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

package model

import "time"

// CryptoLibrary represents a cryptographic library installed on a host.
type CryptoLibrary struct {
	ID              string    `json:"id"`
	HostID          string    `json:"host_id"`
	LibraryName     string    `json:"library_name"`
	Version         string    `json:"version"`
	PackageName     string    `json:"package_name,omitempty"`
	PackageManager  string    `json:"package_manager,omitempty"`
	InstallPath     string    `json:"install_path,omitempty"`
	PQCCapable      bool      `json:"pqc_capable"`
	Source          string    `json:"source"`
	DiscoveryStatus string    `json:"discovery_status"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
}

// CryptoLibraryCVE represents a known CVE for a crypto library version range.
type CryptoLibraryCVE struct {
	LibraryName  string `json:"library_name"`
	VersionRange string `json:"version_range"`
	CVEID        string `json:"cve_id"`
	Severity     string `json:"severity"`
	Description  string `json:"description"`
}
