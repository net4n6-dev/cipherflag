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

package osquery

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/ingest"
)

// ---------------------------------------------------------------------------
// FleetDM webhook entry types
// ---------------------------------------------------------------------------

// fleetWebhookEntry represents one entry in the FleetDM webhook JSON array.
type fleetWebhookEntry struct {
	HostIdentifier string              `json:"host_identifier"`
	Hostname       string              `json:"hostname"`
	DisplayName    string              `json:"display_name"`
	ComputerName   string              `json:"computer_name"`
	Platform       string              `json:"platform"`
	OSVersion      string              `json:"os_version"`
	Name           string              `json:"name"`     // query name
	Action         string              `json:"action"`   // "snapshot" for our queries
	Snapshot       []map[string]string `json:"snapshot"` // result rows for snapshot queries
	Columns        map[string]string   `json:"columns"`  // single row for differential queries

	// Optional — populated when the operator's FleetDM webhook template
	// carries {{ .Host.Team.Name }} / {{ .Host.Team.ID }}. See the
	// adapter README paragraph for setup.
	Team   string `json:"team,omitempty"`
	TeamID int    `json:"team_id,omitempty"`
}

// ---------------------------------------------------------------------------
// Response type (exported for test decoding)
// ---------------------------------------------------------------------------

// webhookResponse is the JSON body returned by HandleWebhook.
type webhookResponse struct {
	Processed                 int    `json:"processed"`
	Skipped                   int    `json:"skipped"`
	OwnershipSightingsEmitted int    `json:"ownership_sightings_emitted"`
	Message                   string `json:"message,omitempty"`
}

// ---------------------------------------------------------------------------
// Team extraction helpers
// ---------------------------------------------------------------------------

// fleetDefaultTeams are FleetDM-server-produced defaults for hosts
// with no team assignment. Emitting a sighting for these would
// attribute every unassigned host to a meaningless slug.
var fleetDefaultTeams = map[string]bool{
	"no team": true,
	"":        true,
}

// teamFromEntry extracts the raw team name from a FleetDM webhook
// entry, returning "" for empty / whitespace / default "No team"
// buckets. Caller slugifies via store.SlugifyTeam when building
// OwnershipClaims. Preserves original casing so the Evidence map
// carries the operator-visible team name.
func teamFromEntry(entry fleetWebhookEntry) string {
	name := strings.ToLower(strings.TrimSpace(entry.Team))
	if fleetDefaultTeams[name] {
		return ""
	}
	return entry.Team
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

// Adapter receives FleetDM webhook POSTs and feeds them through the CipherFlag
// ingestion pipeline.
type Adapter struct {
	ingester ingest.Ingester
}

// NewAdapter constructs an Adapter with the given Ingester.
func NewAdapter(ing ingest.Ingester) *Adapter {
	return &Adapter{ingester: ing}
}

// HandleWebhook is the HTTP handler for FleetDM webhook POSTs.
// It parses the JSON array of entries, maps each to a DiscoveryResult, and
// calls ingester.Ingest() for each non-empty result, followed by
// ingester.AttributeAssets() when the entry carries a team assignment.
func (a *Adapter) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	var entries []fleetWebhookEntry
	if err := json.NewDecoder(r.Body).Decode(&entries); err != nil {
		writeJSON(w, http.StatusBadRequest, webhookResponse{Message: "invalid JSON: " + err.Error()})
		return
	}

	var processed, skipped, ownershipEmitted int
	for _, entry := range entries {
		result := mapEntry(entry)
		if result == nil {
			skipped++
			continue
		}
		summary, err := a.ingester.Ingest(r.Context(), result)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, webhookResponse{Message: "ingest error: " + err.Error()})
			return
		}
		processed++

		// Phase 0 two-phase attribution: after Ingest, build one
		// OwnershipClaim per ingested asset and submit via
		// AttributeAssets. Graceful no-op when the entry carries no
		// team or when Ingest produced no assets.
		team := teamFromEntry(entry)
		if team == "" || summary == nil || len(summary.IngestedAssets) == 0 {
			continue
		}
		// Per the OwnershipClaim.Evidence convention (internal/ingest/ownership.go),
		// attribution-style producers carry the pre-slug team name under
		// the canonical key "raw_team_name". Source-specific metadata
		// (FleetDM's team_id) stays under a prefixed key so provenance
		// remains resolvable back to its Fleet origin.
		evidence := map[string]any{"raw_team_name": entry.Team}
		if entry.TeamID != 0 {
			evidence["fleet_team_id"] = entry.TeamID
		}
		claims := make([]ingest.OwnershipClaim, 0, len(summary.IngestedAssets))
		for _, asset := range summary.IngestedAssets {
			// Filter to asset types osquery's host-team mapping can
			// meaningfully attribute. protocol_endpoint entries (added
			// in v1.10 Phase C) are emitted by AWS ELB and other
			// LB-style adapters; an osquery query that produced them on
			// a workstation would silently mis-attribute localhost
			// endpoints to the engineer's team. The switch makes the
			// host-attributable allow-list explicit.
			switch asset.AssetType {
			case "certificate", "ssh_key", "crypto_library":
				// OK — host-attributable types
			default:
				continue
			}
			claims = append(claims, ingest.OwnershipClaim{
				AssetType:  asset.AssetType,
				AssetID:    asset.AssetID,
				Team:       team,
				Source:     "sighting_agent",
				Confidence: "inferred",
				Evidence:   evidence,
			})
		}
		emitted, _, _ := a.ingester.AttributeAssets(r.Context(), claims)
		ownershipEmitted += emitted
	}

	writeJSON(w, http.StatusOK, webhookResponse{
		Processed:                 processed,
		Skipped:                   skipped,
		OwnershipSightingsEmitted: ownershipEmitted,
	})
}

// ---------------------------------------------------------------------------
// Entry mapping
// ---------------------------------------------------------------------------

// mapEntry converts a fleetWebhookEntry into a *ingest.DiscoveryResult.
// Returns nil if the entry should be skipped (empty snapshot, unknown query
// name, or nothing mapped after filtering).
func mapEntry(entry fleetWebhookEntry) *ingest.DiscoveryResult {
	if len(entry.Snapshot) == 0 {
		return nil
	}

	result := &ingest.DiscoveryResult{
		Source:       "osquery",
		SourceHostID: entry.HostIdentifier,
		Hostname:     entry.Hostname,
		OSFamily:     NormalizePlatform(entry.Platform),
		Timestamp:    time.Now().UTC(),
	}

	switch entry.Name {
	case "cipherflag_certificates":
		mapCertificates(result, entry.Snapshot)
	case "cipherflag_ssh_user_keys":
		mapSSHUserKeys(result, entry.Snapshot)
	case "cipherflag_authorized_keys":
		mapAuthorizedKeys(result, entry.Snapshot)
	case "cipherflag_crypto_packages_deb":
		mapLibraries(result, entry.Snapshot, "dpkg")
	case "cipherflag_crypto_packages_rpm":
		mapLibraries(result, entry.Snapshot, "rpm")
	default:
		// Unknown query name — skip entirely
		return nil
	}

	// If nothing was actually mapped, skip the entry
	if len(result.Certificates) == 0 &&
		len(result.SSHKeys) == 0 &&
		len(result.Libraries) == 0 &&
		len(result.Protocols) == 0 &&
		len(result.Configs) == 0 {
		return nil
	}

	return result
}

// ---------------------------------------------------------------------------
// Per-query mapping helpers
// ---------------------------------------------------------------------------

func mapCertificates(result *ingest.DiscoveryResult, rows []map[string]string) {
	for _, cols := range rows {
		cert := MapCertificateColumns(cols)
		if cert.FingerprintSHA256 == "" {
			continue // skip certs without a fingerprint
		}
		result.Certificates = append(result.Certificates, cert)
	}
}

func mapSSHUserKeys(result *ingest.DiscoveryResult, rows []map[string]string) {
	for _, cols := range rows {
		key := MapSSHKeyColumns(cols)
		result.SSHKeys = append(result.SSHKeys, key)
	}
}

func mapAuthorizedKeys(result *ingest.DiscoveryResult, rows []map[string]string) {
	for _, cols := range rows {
		key := MapAuthorizedKeyColumns(cols)
		result.SSHKeys = append(result.SSHKeys, key)
	}
}

func mapLibraries(result *ingest.DiscoveryResult, rows []map[string]string, pkgManager string) {
	for _, cols := range rows {
		lib := MapLibraryColumns(cols, pkgManager)
		if lib.LibraryName == "" || lib.Version == "" {
			continue // skip libraries with missing name or version
		}
		result.Libraries = append(result.Libraries, lib)
	}
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

