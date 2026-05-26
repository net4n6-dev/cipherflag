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

package ingest

import (
	"context"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
)

// DiscoveryResult is the input contract for the unified ingestion pipeline.
type DiscoveryResult struct {
	Source       string
	SourceHostID string
	Hostname     string
	IPAddresses  []string
	OSFamily     string
	Timestamp    time.Time

	Certificates []dedup.CertDiscovery
	SSHKeys      []dedup.SSHKeyDiscovery
	Libraries    []dedup.LibraryDiscovery
	Protocols    []dedup.ProtocolDiscovery
	Configs      []dedup.ConfigDiscovery

	// SkipHostResolution, when true, causes Ingest to bypass the host
	// resolver. Used exclusively by the import path where CBOMs don't
	// carry host discovery metadata. If SourceHostID is set, host is
	// looked up directly via store.GetHost. If SourceHostID is empty,
	// host is nil and only cross-host-safe asset types (certificates)
	// are processed; SSH keys / libraries / configs in the payload are
	// silently skipped.
	SkipHostResolution bool

	// ExternalSourceID, when non-empty, links every provenance row
	// produced by this DiscoveryResult to an entry in the
	// external_sources registry. AWS / CT / future polling adapters
	// set this; file-system scans and local agent discoveries leave
	// it empty (asset_provenance.external_source_id stays NULL).
	//
	// See internal/store/migrations/032_asset_provenance_external_source.sql.
	ExternalSourceID string
}

// IngestionSummary reports what happened during ingestion.
type IngestionSummary struct {
	HostID                    string          `json:"host_id"`
	CertificatesNew           int             `json:"certificates_new"`
	CertificatesUpdated       int             `json:"certificates_updated"`
	SSHKeysNew                int             `json:"ssh_keys_new"`
	SSHKeysUpdated            int             `json:"ssh_keys_updated"`
	LibrariesNew              int             `json:"libraries_new"`
	LibrariesUpdated          int             `json:"libraries_updated"`
	ProtocolObservations      int             `json:"protocol_observations"`
	ConfigsNew                int             `json:"configs_new"`
	ConfigsUpdated            int             `json:"configs_updated"`
	OwnershipSightingsEmitted int             `json:"ownership_sightings_emitted"`
	OwnershipSightingsSkipped int             `json:"ownership_sightings_skipped"`
	IngestedAssets            []IngestedAsset `json:"ingested_assets,omitempty"`
}

// Ingester is the interface for the unified ingestion pipeline.
type Ingester interface {
	Ingest(ctx context.Context, result *DiscoveryResult) (*IngestionSummary, error)
	// Phase 0 addition:
	AttributeAssets(ctx context.Context, claims []OwnershipClaim) (emitted, skipped int, err error)
}
