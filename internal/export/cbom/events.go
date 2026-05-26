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

package cbom

import (
	"context"
	"fmt"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/export/cbom/sinks/types"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
	"github.com/rs/zerolog/log"
)

// notifyEvent is sent on the notifyCh channel when an asset is scored.
type notifyEvent struct {
	AssetType string
	AssetID   string
}

// NotifyAssetScored is called by the scoring dispatcher (via callback) after
// an asset is scored. Non-blocking: if the channel is full, the event is
// dropped with a warning. The scoring ingest path must never stall.
func (rt *Runtime) NotifyAssetScored(assetType, assetID string) {
	select {
	case rt.notifyCh <- notifyEvent{AssetType: assetType, AssetID: assetID}:
	default:
		log.Warn().Str("asset_type", assetType).Str("asset_id", assetID).
			Msg("cbom: notify channel full, dropping event")
	}
}

// notifyWorker drains notifyCh: resolves asset provenance hosts and marks
// matching scopes dirty. Runs as a goroutine started by Runtime.Start.
func (rt *Runtime) notifyWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-rt.notifyCh:
			if !ok {
				return
			}
			hostIDs, err := rt.store.GetProvenanceHostIDs(ctx, ev.AssetType, ev.AssetID)
			if err != nil {
				log.Error().Err(err).Str("asset_type", ev.AssetType).Str("asset_id", ev.AssetID).
					Msg("cbom: GetProvenanceHostIDs failed")
				continue
			}
			for i := range rt.scopes {
				if rt.scopes[i].MatchAssetByHostIDs(hostIDs, ev.AssetType) {
					rt.dirty.Mark(rt.scopes[i].Name)
				}
			}
		}
	}
}

// SinkEvent is re-exported from sinks/types to avoid circular imports.
type SinkEvent = types.SinkEvent

// GenerateEvents produces a stream of SinkEvents for one scope, at the given
// granularity ("asset" or "finding"). The asset granularity emits one event
// per AssetHealthReport; the finding granularity emits one event per
// HealthFinding (with minimal asset context nested in).
func (g *Generator) GenerateEvents(
	ctx context.Context,
	st store.CryptoStore,
	scope *Scope,
	granularity string,
) ([]SinkEvent, error) {
	if granularity != "asset" && granularity != "finding" {
		return nil, fmt.Errorf("cbom: GenerateEvents: granularity %q must be \"asset\" or \"finding\"", granularity)
	}
	hostIDs, err := resolveHostIDsForScope(ctx, st, scope)
	if err != nil {
		return nil, fmt.Errorf("cbom: resolve hosts for scope %q: %w", scope.Name, err)
	}
	rows, err := st.ListScopeAssets(ctx, store.ScopeAssetQuery{
		HostIDs:      hostIDs,
		AssetTypes:   scope.AssetTypes,
		MinRiskScore: scope.MinRiskScore,
	})
	if err != nil {
		return nil, fmt.Errorf("cbom: list scope assets for %q: %w", scope.Name, err)
	}

	now := time.Now().UTC()
	var events []SinkEvent
	for i := range rows {
		row := rows[i]
		payload, err := g.buildAssetPayload(ctx, st, &row)
		if err != nil {
			return nil, err
		}
		if payload == nil {
			continue // asset no longer exists
		}
		switch granularity {
		case "asset":
			events = append(events, SinkEvent{
				Timestamp: now,
				Scope:     scope.Name,
				AssetType: row.AssetType,
				AssetID:   row.AssetID,
				EventType: "asset",
				Severity:  worstSeverity(row.Report.Findings),
				Payload:   payload,
			})
		case "finding":
			for j := range row.Report.Findings {
				f := &row.Report.Findings[j]
				events = append(events, SinkEvent{
					Timestamp: now,
					Scope:     scope.Name,
					AssetType: row.AssetType,
					AssetID:   row.AssetID,
					EventType: "finding",
					Severity:  string(f.Severity),
					Payload:   findingPayload(&row.Report, f),
				})
			}
		}
	}
	return events, nil
}

// buildAssetPayload loads the asset-type-specific record and returns the flat
// JSON-compatible map.
func (g *Generator) buildAssetPayload(ctx context.Context, st store.CryptoStore, row *store.ScopeAssetRow) (map[string]interface{}, error) {
	r := &row.Report
	base := baseAssetPayload(r)
	switch row.AssetType {
	case "certificate":
		cert, err := st.GetCertificate(ctx, row.AssetID)
		if err != nil || cert == nil {
			return nil, err
		}
		base["subject_cn"] = cert.Subject.CommonName
		base["issuer_cn"] = cert.Issuer.CommonName
		base["not_before"] = cert.NotBefore.Format(time.RFC3339)
		base["not_after"] = cert.NotAfter.Format(time.RFC3339)
		base["key_algorithm"] = string(cert.KeyAlgorithm)
		base["key_size_bits"] = cert.KeySizeBits
		base["fingerprint_sha256"] = cert.FingerprintSHA256
		return base, nil
	case "ssh_key":
		key, err := st.GetSSHKey(ctx, row.AssetID)
		if err != nil || key == nil {
			return nil, err
		}
		base["key_type"] = key.KeyType
		base["key_size_bits"] = key.KeySizeBits
		base["fingerprint_sha256"] = key.FingerprintSHA256
		base["first_seen"] = key.FirstSeen.Format(time.RFC3339)
		return base, nil
	case "crypto_library":
		lib, err := st.GetCryptoLibrary(ctx, row.AssetID)
		if err != nil || lib == nil {
			return nil, err
		}
		base["library_name"] = lib.LibraryName
		base["version"] = lib.Version
		base["pqc_capable"] = lib.PQCCapable
		return base, nil
	case "crypto_config":
		cfg, err := st.GetCryptoConfig(ctx, row.AssetID)
		if err != nil || cfg == nil {
			return nil, err
		}
		base["config_type"] = cfg.ConfigType
		base["file_path"] = cfg.FilePath
		return base, nil
	// CE-flavor: "crypto_protocol" asset type backs Layer 4.1c
	// protocol-endpoint scoring (EE-only). Without protocol_endpoints
	// in the schema, this case has no rows to fetch — no need to wire
	// a CBOM event payload for it.
	}
	return nil, nil
}

// baseAssetPayload builds the common fields shared across asset types.
func baseAssetPayload(r *model.AssetHealthReport) map[string]interface{} {
	findings := make([]map[string]interface{}, 0, len(r.Findings))
	for i := range r.Findings {
		f := &r.Findings[i]
		findings = append(findings, map[string]interface{}{
			"rule_id":        f.RuleID,
			"title":          f.Title,
			"severity":       string(f.Severity),
			"category":       string(f.Category),
			"detail":         f.Detail,
			"remediation":    f.Remediation,
			"deduction":      f.Deduction,
			"immediate_fail": f.ImmediateFail,
		})
	}
	return map[string]interface{}{
		"asset_type":          r.AssetType,
		"asset_id":            r.AssetID,
		"grade":               r.Grade,
		"score":               r.Score,
		"pqc_status":          r.PQCStatus,
		"risk_score":          r.RiskScore,
		"risk_factors":        r.RiskFactors,
		"compliance":          r.Compliance,
		"findings":            findings,
		"rule_engine_version": r.RuleEngineVersion,
		"scored_at":           r.ScoredAt.Format(time.RFC3339),
	}
}

// findingPayload builds the per-finding event body with minimal asset context.
func findingPayload(r *model.AssetHealthReport, f *model.HealthFinding) map[string]interface{} {
	return map[string]interface{}{
		"asset_type":       r.AssetType,
		"asset_id":         r.AssetID,
		"asset_grade":      r.Grade,
		"asset_risk_score": r.RiskScore,
		"rule_id":          f.RuleID,
		"title":            f.Title,
		"severity":         string(f.Severity),
		"category":         string(f.Category),
		"detail":           f.Detail,
		"remediation":      f.Remediation,
		"deduction":        f.Deduction,
		"immediate_fail":   f.ImmediateFail,
	}
}

// worstSeverity returns the highest-severity finding's severity. For an asset
// with no findings, returns "Info".
func worstSeverity(findings []model.HealthFinding) string {
	rank := map[model.Severity]int{
		model.SeverityCritical: 5,
		model.SeverityHigh:     4,
		model.SeverityMedium:   3,
		model.SeverityLow:      2,
		model.SeverityInfo:     1,
	}
	worst := model.SeverityInfo
	worstRank := 0
	for i := range findings {
		r := rank[findings[i].Severity]
		if r > worstRank {
			worst = findings[i].Severity
			worstRank = r
		}
	}
	return string(worst)
}
