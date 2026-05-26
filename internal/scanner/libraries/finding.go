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

// Package libraries scans hosts for installed cryptographic libraries.
package libraries

// LibraryFinding represents a single crypto library discovered on the host.
type LibraryFinding struct {
	// LibraryName is the canonical library name (e.g., "openssl", "gnutls").
	LibraryName string

	// Version is the installed version string.
	Version string

	// PackageName is the OS package name (e.g., "libssl3", "openssl-libs").
	PackageName string

	// PackageManager is the package manager that reported this library.
	PackageManager string

	// InstallPath is the library file path, if known.
	InstallPath string

	// --- Scanner metadata (not mapped to discovery types) ---

	// SourceRepo is the package source/release metadata.
	SourceRepo string

	// Architecture is the package architecture (e.g., "amd64").
	Architecture string
}
