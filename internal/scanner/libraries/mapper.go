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

package libraries

import "github.com/net4n6-dev/cipherflag/internal/ingest/dedup"

// MapFindings converts library scanner findings to dedup.LibraryDiscovery
// types for the ingestion pipeline. Scanner metadata fields (SourceRepo,
// Architecture) are not mapped. PQCCapable is always false here — that
// classification is a Layer 4 intelligence concern.
func MapFindings(findings []LibraryFinding) []dedup.LibraryDiscovery {
	if len(findings) == 0 {
		return nil
	}
	discoveries := make([]dedup.LibraryDiscovery, 0, len(findings))
	for _, f := range findings {
		discoveries = append(discoveries, dedup.LibraryDiscovery{
			LibraryName:    f.LibraryName,
			Version:        f.Version,
			PackageName:    f.PackageName,
			PackageManager: f.PackageManager,
			InstallPath:    f.InstallPath,
			PQCCapable:     false,
		})
	}
	return discoveries
}
