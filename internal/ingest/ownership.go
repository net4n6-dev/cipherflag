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

// IngestedAsset identifies one asset that passed through dedup during
// a single Ingest call. Returned in IngestionSummary.IngestedAssets so
// adapters can construct OwnershipClaims against the specific asset
// IDs the ingester assigned without a follow-up database lookup.
//
// AssetType values:
//   - "certificate"        — cert dedup keyed on FingerprintSHA256
//   - "ssh_key"            — SSH key dedup keyed on FingerprintSHA256
//   - "crypto_library"     — library dedup keyed on (name, version, host)
//   - "protocol_endpoint"  — protocol_endpoint upsert keyed on (ip, port, proto)
//
// Config discoveries do not appear here. asset_ownership_sightings'
// CHECK constraint (028_asset_ownership_sightings.sql:42) lists
// "crypto_config" as a valid asset_type, but the v1.10 attribution
// surface doesn't expose configs through IngestedAssets — the dedup
// path doesn't return enough metadata to make the claim worthwhile.
// Add when a real consumer asks for it.
type IngestedAsset struct {
	AssetType string
	AssetID   string
	IsNew     bool

	// SourceKey is the adapter's stable correlation key for the source
	// row that produced this asset (e.g. ARN for AWS ACM certs, file
	// path for filesystem scanners). Adapters use SourceKey to align
	// post-Ingest state (tag maps, region metadata, etc.) with the
	// returned IngestedAsset rows. Necessary because the ingester
	// filters input — PEM parse failures, observation-cache hits —
	// breaking any position-based pairing between adapter input and
	// IngestedAssets output.
	//
	// Populated from disc.FilePath for cert/ssh-key/library discoveries
	// and from disc.SourceKey for protocol discoveries; adapters that
	// don't need post-Ingest correlation can ignore it.
	SourceKey string
}

// OwnershipClaim is a single attribution fact — "team X owns asset Y,
// source Z, confidence tier T, with evidence E". Adapters construct
// these after a DiscoveryResult has been ingested (using the asset IDs
// returned in IngestionSummary.IngestedAssets) and submit in batches
// via UnifiedIngester.AttributeAssets. Attribution-only producers
// (future AD sync, Okta, git_author) can call AttributeAssets without
// any prior Ingest.
type OwnershipClaim struct {
	AssetType  string // "certificate" | "ssh_key" | "crypto_library" | "protocol_endpoint"
	AssetID    string
	Team       string // raw; normalised via store.SlugifyTeam at write
	Source     string // "sighting_agent" | future labels
	Confidence string // "direct" | "attested" | "inferred" | "observed"

	// Evidence carries per-producer provenance, stored verbatim in the
	// sighting's evidence JSONB column. Convention across producers:
	//
	//   - Attribution-style producers (operator-set team name from an
	//     external admin surface: FleetDM Teams, AWS resource tags,
	//     Okta groups, AD groups) SHOULD use "raw_team_name" (string)
	//     for the pre-slug team identifier, plus source-specific
	//     metadata keys (FleetDM: fleet_team_id; AWS: aws_tag_key,
	//     aws_account_id; future). The evidence-chain UI renders
	//     "raw_team_name" uniformly regardless of which adapter
	//     produced the sighting — this prevents fleet_team_name /
	//     aws_team_name / okta_team_name proliferating as the same
	//     concept under different keys.
	//
	//   - Inference-style producers (team slug derived from free-form
	//     text: ssh_comment from SSH key comments, cert_subject from
	//     cert O/OU fields) carry the raw INPUT text under a
	//     source-specific key (ssh_comment: "comment"; cert_subject:
	//     "subject_o" / "subject_ou"). "raw_team_name" is not
	//     meaningful for these — there is no attested team name, only
	//     a derived slug.
	Evidence map[string]any
}
