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

package configs

import "github.com/net4n6-dev/cipherflag/internal/ingest/dedup"

// MapFindings converts config scanner findings to dedup.ConfigDiscovery
// types for the ingestion pipeline. Findings is always nil — config issue
// evaluation is a Layer 4 scoring concern.
func MapFindings(findings []ConfigFinding) []dedup.ConfigDiscovery {
	if len(findings) == 0 {
		return nil
	}
	discoveries := make([]dedup.ConfigDiscovery, 0, len(findings))
	for _, f := range findings {
		// Copy the settings map.
		settings := make(map[string]string, len(f.Settings))
		for k, v := range f.Settings {
			settings[k] = v
		}
		discoveries = append(discoveries, dedup.ConfigDiscovery{
			ConfigType: f.ConfigType,
			FilePath:   f.FilePath,
			Settings:   settings,
			Findings:   nil, // Layer 4
		})
	}
	return discoveries
}
