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

package cbomimport

import (
	"context"
	"fmt"
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
)

// Source is the provenance source string written for every asset
// ingested through the import path.
const Source = "cbom_import"

// ReasonNoHostSpecified is emitted by the importer (not the dispatcher)
// when a non-certificate component is present in a hostless import.
const ReasonNoHostSpecified = "no_host_specified"

// ingesterIface is the minimal interface the Importer needs. Allows
// tests to inject a fake ingester without pulling in the full
// UnifiedIngester dependency graph.
type ingesterIface interface {
	Ingest(ctx context.Context, result *ingest.DiscoveryResult) (*ingest.IngestionSummary, error)
}

// Importer parses CycloneDX BOM documents and feeds crypto-relevant
// components through the UnifiedIngester pipeline.
type Importer struct {
	ingester ingesterIface
}

// NewImporter constructs an Importer that writes through the given ingester.
func NewImporter(ingester ingesterIface) *Importer {
	return &Importer{ingester: ingester}
}

// ImportOptions controls per-import behaviour.
type ImportOptions struct {
	// HostID is optional. When empty, only certificates are imported
	// (hostless mode). When set to a valid host UUID, SSH keys, libraries,
	// and configs are also imported and attached to that host.
	HostID string
}

// ImportedCounts mirrors IngestionSummary counts in the import-response shape.
type ImportedCounts struct {
	CertificatesNew     int `json:"certificates_new"`
	CertificatesUpdated int `json:"certificates_updated"`
	SSHKeysNew          int `json:"ssh_keys_new"`
	SSHKeysUpdated      int `json:"ssh_keys_updated"`
	LibrariesNew        int `json:"libraries_new"`
	LibrariesUpdated    int `json:"libraries_updated"`
	ConfigsNew          int `json:"configs_new"`
	ConfigsUpdated      int `json:"configs_updated"`
}

// SkippedCategory summarises components that were not imported.
type SkippedCategory struct {
	Reason         string   `json:"reason"`
	ComponentCount int      `json:"component_count"`
	SampleBOMRefs  []string `json:"sample_bom_refs,omitempty"`
	AssetTypes     []string `json:"asset_types,omitempty"`
}

// BOMMetadata captures top-level BOM fields for the response.
type BOMMetadata struct {
	SerialNumber        string `json:"serial_number"`
	SpecVersion         string `json:"spec_version"`
	ComponentCountTotal int    `json:"component_count_total"`
}

// ImportResult is the full response payload.
type ImportResult struct {
	Source      string            `json:"source"`
	HostID      string            `json:"host_id,omitempty"`
	Imported    ImportedCounts    `json:"imported"`
	Skipped     []SkippedCategory `json:"skipped"`
	BOMMetadata BOMMetadata       `json:"bom_metadata"`
}

// Import decodes a CycloneDX BOM from r and imports all crypto-relevant
// components. Per-component failures are captured in Skipped; only
// catastrophic errors (decode error, ingester-level error) are returned.
func (i *Importer) Import(ctx context.Context, r io.Reader, opts ImportOptions) (*ImportResult, error) {
	bom, err := Parse(r)
	if err != nil {
		return nil, err
	}

	result := &ImportResult{
		Source: Source,
		HostID: opts.HostID,
		BOMMetadata: BOMMetadata{
			SerialNumber: bom.SerialNumber,
			SpecVersion:  bom.SpecVersion.String(),
		},
	}

	dr := &ingest.DiscoveryResult{
		Source:             Source,
		SourceHostID:       opts.HostID,
		SkipHostResolution: true,
	}

	skips := newSkipAggregator()
	hostlessSkipped := 0
	hostlessAssetTypes := map[string]struct{}{}

	components := []cdx.Component{}
	if bom.Components != nil {
		components = *bom.Components
	}
	result.BOMMetadata.ComponentCountTotal = len(components)

	bomSerial := bom.SerialNumber

	for _, c := range components {
		classified := ClassifyComponent(c)
		switch classified.Kind {
		case KindCertificate:
			classified.Cert.Source = Source
			classified.Cert.RawMetadata = metadata(classified.BOMRef, bomSerial)
			dr.Certificates = append(dr.Certificates, *classified.Cert)
		case KindSSHKey:
			if opts.HostID == "" {
				hostlessSkipped++
				hostlessAssetTypes["ssh_key"] = struct{}{}
				continue
			}
			classified.SSHKey.Source = Source
			classified.SSHKey.RawMetadata = metadata(classified.BOMRef, bomSerial)
			dr.SSHKeys = append(dr.SSHKeys, *classified.SSHKey)
		case KindLibrary:
			if opts.HostID == "" {
				hostlessSkipped++
				hostlessAssetTypes["crypto_library"] = struct{}{}
				continue
			}
			classified.Lib.Source = Source
			classified.Lib.RawMetadata = metadata(classified.BOMRef, bomSerial)
			dr.Libraries = append(dr.Libraries, *classified.Lib)
		case KindConfig:
			if opts.HostID == "" {
				hostlessSkipped++
				hostlessAssetTypes["crypto_config"] = struct{}{}
				continue
			}
			classified.Config.Source = Source
			classified.Config.RawMetadata = metadata(classified.BOMRef, bomSerial)
			dr.Configs = append(dr.Configs, *classified.Config)
		case KindSkipped:
			skips.add(classified.SkipReason, classified.BOMRef)
		}
	}

	// Add the hostless bucket if any non-cert assets were skipped for this reason.
	if hostlessSkipped > 0 {
		cat := SkippedCategory{
			Reason:         ReasonNoHostSpecified,
			ComponentCount: hostlessSkipped,
		}
		for t := range hostlessAssetTypes {
			cat.AssetTypes = append(cat.AssetTypes, t)
		}
		result.Skipped = append(result.Skipped, cat)
	}
	result.Skipped = append(result.Skipped, skips.result()...)

	// Invoke the ingester.
	summary, err := i.ingester.Ingest(ctx, dr)
	if err != nil {
		return nil, fmt.Errorf("cbom import: ingest: %w", err)
	}

	result.Imported = ImportedCounts{
		CertificatesNew:     summary.CertificatesNew,
		CertificatesUpdated: summary.CertificatesUpdated,
		SSHKeysNew:          summary.SSHKeysNew,
		SSHKeysUpdated:      summary.SSHKeysUpdated,
		LibrariesNew:        summary.LibrariesNew,
		LibrariesUpdated:    summary.LibrariesUpdated,
		ConfigsNew:          summary.ConfigsNew,
		ConfigsUpdated:      summary.ConfigsUpdated,
	}
	return result, nil
}

func metadata(bomRef, bomSerial string) map[string]any {
	m := map[string]any{"source_type": "cbom"}
	if bomRef != "" {
		m["bom_ref"] = bomRef
	}
	if bomSerial != "" {
		m["bom_serial"] = bomSerial
	}
	return m
}

// skipAggregator groups skipped components by reason, caps sample BOMRefs at 5.
type skipAggregator struct {
	byReason map[string]*SkippedCategory
}

func newSkipAggregator() *skipAggregator {
	return &skipAggregator{byReason: map[string]*SkippedCategory{}}
}

func (s *skipAggregator) add(reason, bomRef string) {
	cat, ok := s.byReason[reason]
	if !ok {
		cat = &SkippedCategory{Reason: reason}
		s.byReason[reason] = cat
	}
	cat.ComponentCount++
	if len(cat.SampleBOMRefs) < 5 && bomRef != "" {
		cat.SampleBOMRefs = append(cat.SampleBOMRefs, bomRef)
	}
}

func (s *skipAggregator) result() []SkippedCategory {
	out := make([]SkippedCategory, 0, len(s.byReason))
	for _, cat := range s.byReason {
		out = append(out, *cat)
	}
	return out
}
