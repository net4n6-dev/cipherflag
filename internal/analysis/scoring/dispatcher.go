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

package scoring

import (
	"context"
	"fmt"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/analysis"
	"github.com/net4n6-dev/cipherflag/internal/analysis/compliance"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
	"github.com/rs/zerolog/log"
)

// Scorer is the contract UnifiedIngester uses to trigger scoring on
// cache-miss and Sweeper uses to rescore stale rows.
//
// ScoreAsset is idempotent — safe to call repeatedly on the same asset.
// Errors are logged by callers; they never block ingest.
type Scorer interface {
	ScoreAsset(ctx context.Context, assetType, assetID string) error
}

// ScoredCallback is invoked after an AssetHealthReport is successfully saved.
// It is fire-and-forget: the dispatcher does not wait for or check the callback's
// side effects. Designed to feed the cbom.Runtime.NotifyAssetScored hook.
type ScoredCallback func(assetType, assetID string)

// DispatcherOption is a functional option for NewDispatcher.
type DispatcherOption func(*dispatcher)

// WithScoredCallback returns a DispatcherOption that sets an optional callback
// fired after each successful SaveAssetHealthReport call.
func WithScoredCallback(cb ScoredCallback) DispatcherOption {
	return func(d *dispatcher) { d.onScored = cb }
}

type dispatcher struct {
	store    store.CryptoStore
	onScored ScoredCallback // nil when no callback configured
}

// NewDispatcher returns the production scorer.
func NewDispatcher(st store.CryptoStore, opts ...DispatcherOption) Scorer {
	d := &dispatcher{store: st}
	for _, o := range opts {
		o(d)
	}
	return d
}

func (d *dispatcher) ScoreAsset(ctx context.Context, assetType, assetID string) error {
	switch assetType {
	case "certificate":
		return d.scoreCertificate(ctx, assetID)
	case "ssh_key":
		return d.scoreSSHKey(ctx, assetID)
	case "crypto_library":
		return d.scoreLibrary(ctx, assetID)
	case "crypto_config":
		return d.scoreConfig(ctx, assetID)
	default:
		return fmt.Errorf("scoring: unknown asset type %q", assetType)
	}
}

func (d *dispatcher) scoreCertificate(ctx context.Context, fingerprint string) error {
	cert, err := d.store.GetCertificate(ctx, fingerprint)
	if err != nil {
		return fmt.Errorf("get certificate: %w", err)
	}
	if cert == nil {
		return nil
	}
	// Existing cert scorer — unchanged path for cert API handler.
	hr := analysis.ScoreCertificate(cert)
	if err := d.store.SaveHealthReport(ctx, hr); err != nil {
		return fmt.Errorf("save cert health report: %w", err)
	}
	// New unified path — convert + save AssetHealthReport.
	asset := &model.AssetHealthReport{
		AssetType:         "certificate",
		AssetID:           cert.FingerprintSHA256,
		Grade:             string(hr.Grade),
		Score:             hr.Score,
		Findings:          hr.Findings,
		PQCStatus:         ForCertificate(cert),
		Compliance:        map[string]string{}, // populated by 4.3 Compliance Engine
		RuleEngineVersion: CurrentRuleEngineVersion,
		ScoredAt:          time.Now(),
	}
	compliance.EvaluateCertificate(asset, cert)
	if err := d.store.SaveAssetHealthReport(ctx, asset); err != nil {
		return err
	}
	if d.onScored != nil {
		d.onScored("certificate", cert.FingerprintSHA256)
	}
	return nil
}

func (d *dispatcher) scoreSSHKey(ctx context.Context, id string) error {
	k, err := d.store.GetSSHKey(ctx, id)
	if err != nil {
		return fmt.Errorf("get ssh key: %w", err)
	}
	if k == nil {
		return nil
	}
	r := ScoreSSHKey(k)
	r.RuleEngineVersion = CurrentRuleEngineVersion
	if r.Compliance == nil {
		r.Compliance = map[string]string{}
	}
	compliance.EvaluateSSHKey(r, k)
	if err := d.store.SaveAssetHealthReport(ctx, r); err != nil {
		return err
	}
	if d.onScored != nil {
		d.onScored("ssh_key", k.ID)
	}
	return nil
}

func (d *dispatcher) scoreLibrary(ctx context.Context, id string) error {
	lib, err := d.store.GetCryptoLibrary(ctx, id)
	if err != nil {
		return fmt.Errorf("get crypto library: %w", err)
	}
	if lib == nil {
		return nil
	}
	cves, err := d.store.GetCryptoLibraryCVEs(ctx, lib.LibraryName, lib.Version)
	if err != nil {
		log.Warn().Err(err).Str("library", lib.LibraryName).Msg("scoring: cve fetch failed, scoring without CVEs")
		cves = []model.CryptoLibraryCVE{}
	}
	r := ScoreLibrary(lib, cves)
	r.RuleEngineVersion = CurrentRuleEngineVersion
	if r.Compliance == nil {
		r.Compliance = map[string]string{}
	}
	compliance.EvaluateLibrary(r, lib)
	if err := d.store.SaveAssetHealthReport(ctx, r); err != nil {
		return err
	}
	if d.onScored != nil {
		d.onScored("crypto_library", lib.ID)
	}
	return nil
}

func (d *dispatcher) scoreConfig(ctx context.Context, id string) error {
	cfg, err := d.store.GetCryptoConfig(ctx, id)
	if err != nil {
		return fmt.Errorf("get crypto config: %w", err)
	}
	if cfg == nil {
		return nil
	}
	r := ScoreConfig(cfg)
	r.RuleEngineVersion = CurrentRuleEngineVersion
	if r.Compliance == nil {
		r.Compliance = map[string]string{}
	}
	compliance.EvaluateConfig(r, cfg)
	if err := d.store.SaveAssetHealthReport(ctx, r); err != nil {
		return err
	}
	if d.onScored != nil {
		d.onScored("crypto_config", cfg.ID)
	}
	return nil
}


// NewNoopScorer returns a scorer that silently returns nil. Used as the
// default when NewUnifiedIngester is called without WithScorer — byte-
// identical to pre-scoring behaviour.
func NewNoopScorer() Scorer { return noopScorer{} }

type noopScorer struct{}

func (noopScorer) ScoreAsset(context.Context, string, string) error { return nil }
