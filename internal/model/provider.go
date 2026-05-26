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

// Provider is a Git hosting instance (GitHub/GitLab/Bitbucket, public or self-hosted)
// that the operator has registered so CipherFlag can clone repos from it. Credentials
// never live in the struct; AuthSecretRef is an opaque URI resolved at clone time
// by the secret-resolver subsystem (6.1b-2).
type Provider struct {
	ID            string    `json:"id"`
	Kind          string    `json:"kind"`
	BaseURL       string    `json:"base_url"`
	AuthSecretRef string    `json:"auth_secret_ref"`
	DisplayName   string    `json:"display_name,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// ValidProviderKinds is the closed set of `Provider.Kind` values accepted by
// the API. The scanner uses Kind to pick the right REST client (discovery
// in 6.1b-4) and clone URL scheme.
var ValidProviderKinds = map[string]struct{}{
	"github":              {},
	"github_enterprise":   {},
	"gitlab":              {},
	"gitlab_self_managed": {},
	"bitbucket":           {},
	"bitbucket_server":    {},
	// container_registry: OCI-registry source discriminator (Layer 6.2a).
	"container_registry": {},
	// network_target: active TLS-endpoint scanner source (Layer 6.3).
	"network_target": {},
}

// IsValidProviderKind reports whether s is one of the recognised provider kinds.
func IsValidProviderKind(s string) bool {
	_, ok := ValidProviderKinds[s]
	return ok
}
