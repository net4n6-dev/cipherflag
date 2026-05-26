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

package sshkeys

import "github.com/net4n6-dev/cipherflag/internal/ingest/dedup"

// MapFindings converts SSH key scanner findings to dedup.SSHKeyDiscovery
// types for the ingestion pipeline. Scanner metadata fields (FileMode,
// ModifiedAt) are not mapped.
func MapFindings(findings []SSHKeyFinding) []dedup.SSHKeyDiscovery {
	if len(findings) == 0 {
		return nil
	}
	discoveries := make([]dedup.SSHKeyDiscovery, 0, len(findings))
	for _, f := range findings {
		discoveries = append(discoveries, dedup.SSHKeyDiscovery{
			KeyType:           f.KeyType,
			KeySizeBits:       f.KeySizeBits,
			FingerprintSHA256: f.FingerprintSHA256,
			FilePath:          f.FilePath,
			OwnerUser:         f.OwnerUser,
			IsAuthorized:      f.IsAuthorized,
			IsProtected:       f.IsProtected,
			GrantsRoot:        f.GrantsRoot,
			Comment:           f.Comment,
		})
	}
	return discoveries
}
