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
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/net4n6-dev/cipherflag/internal/analysis/scoring"
	"github.com/net4n6-dev/cipherflag/internal/certparse"
	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
	"github.com/net4n6-dev/cipherflag/internal/ingest/hostresolver"
	"github.com/net4n6-dev/cipherflag/internal/ingest/observcache"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// UnifiedIngester processes DiscoveryResults from any source.
type UnifiedIngester struct {
	store        store.CryptoStore
	hostResolver *hostresolver.Resolver
	dedup        *dedup.Deduplicator
	cache        observcache.ObservationCache
	metrics      *observcache.Metrics
	scorer       scoring.Scorer
}

// Option is a functional option for NewUnifiedIngester.
type Option func(*UnifiedIngester)

// WithObservationCache attaches a non-default ObservationCache. Without
// this option, a no-op cache is used — behaviour is byte-identical to the
// pre-cache code path.
func WithObservationCache(c observcache.ObservationCache) Option {
	return func(u *UnifiedIngester) { u.cache = c }
}

// WithMetrics attaches a Metrics collector. When absent, a fresh
// collector is created but its output is never emitted — callers can
// still retrieve snapshots via Metrics().
func WithMetrics(m *observcache.Metrics) Option {
	return func(u *UnifiedIngester) { u.metrics = m }
}

// WithScorer attaches a Scorer that will be invoked on each cache-miss
// after successful DedupXxx. Default is a noop scorer — no scoring.
func WithScorer(s scoring.Scorer) Option {
	return func(u *UnifiedIngester) { u.scorer = s }
}


// NewUnifiedIngester creates a new UnifiedIngester. With no options, the
// ingester uses a no-op cache (current behaviour preserved). Call sites
// that want the optimisation pass WithObservationCache.
func NewUnifiedIngester(st store.CryptoStore, opts ...Option) *UnifiedIngester {
	u := &UnifiedIngester{
		store:        st,
		hostResolver: hostresolver.NewResolver(st),
		dedup:        dedup.NewDeduplicator(st),
		cache:        observcache.NewNoop(),
		metrics:      observcache.NewMetrics(),
		scorer:       scoring.NewNoopScorer(),
	}
	for _, opt := range opts {
		opt(u)
	}
	return u
}

// Metrics returns the metrics collector for this ingester. Useful for
// operators who want to log cache hit rates on a timer.
func (u *UnifiedIngester) Metrics() *observcache.Metrics { return u.metrics }

// Ingest processes a DiscoveryResult: resolves host, deduplicates assets,
// records provenance, and returns a summary.
func (u *UnifiedIngester) Ingest(ctx context.Context, result *DiscoveryResult) (*IngestionSummary, error) {
	summary := &IngestionSummary{}

	// Per-asset tuples returned in IngestionSummary.IngestedAssets.
	// Appended during dedup passes below; returned at the end.
	var ingested []IngestedAsset
	// ssh_comment ownership claims (Phase 0 migration from DedupSSHKey).
	// Collected during the SSH-key dedup loop and fanned out via
	// AttributeAssets at the end of Ingest.
	var sshCommentClaims []OwnershipClaim

	// 1. Host resolution. Adapter path: always resolve. Import path
	//    (SkipHostResolution=true): direct lookup if SourceHostID is set,
	//    otherwise host is nil (hostless import — certs only).
	var host *model.Host
	var err error
	if !result.SkipHostResolution {
		host, err = u.hostResolver.ResolveHost(ctx, result.SourceHostID, result.Hostname, result.IPAddresses, result.Source, result.OSFamily)
		if err != nil {
			return nil, fmt.Errorf("resolve host: %w", err)
		}
		summary.HostID = host.ID
	} else if result.SourceHostID != "" {
		host, err = u.store.GetHost(ctx, result.SourceHostID)
		if err != nil {
			return nil, fmt.Errorf("get host %s: %w", result.SourceHostID, err)
		}
		if host == nil {
			return nil, fmt.Errorf("host %s not found", result.SourceHostID)
		}
		summary.HostID = host.ID
	}
	// If SkipHostResolution && SourceHostID == "" → host remains nil.
	// Non-cert asset types are skipped below.

	// v1.5.0 — endpoint-tier sighting dual-write. Whenever the
	// ingestion has a resolved host, record each of its claimed IPs as
	// a direct-tier sighting. This feeds the cert blast-radius
	// attribution path: certs observed from those IPs will resolve to
	// this host with confidence=direct, winning over any sighting-only
	// tier. See research/hip-sightings-spec-v1.5.0.md §4 (ingest paths).
	// Hoisted out of the per-asset loops because the host↔IP mapping
	// is a property of the host (not of any individual asset) and
	// upserting per-IP once per cycle is cheaper than per-asset.
	//
	// Failure mode: log-and-continue. Sighting is secondary evidence;
	// a sighting write failure MUST NOT block the primary provenance
	// path. Matches the existing scoring-failure pattern below.
	if host != nil {
		u.writeEndpointSightings(ctx, host, result)
	}

	// 2. Certificates (cross-host dedup — runs even when host is nil)
	for i := range result.Certificates {
		disc := &result.Certificates[i]
		if disc.Source == "" {
			disc.Source = result.Source
		}
		// Derive FingerprintSHA256 from RawPEM when adapter didn't pre-compute it.
		// Adapters that set FingerprintSHA256 themselves (osquery, scanners) take
		// the fast path. Adapters that only have RawPEM (AWS ACM, future CT) get
		// the FP derived here at the boundary so they don't all reimplement the
		// same SHA256 + parse dance. Empty-FP empty-RawPEM combinations are
		// dropped (matches osquery's pre-existing convention).
		if disc.FingerprintSHA256 == "" && disc.RawPEM != "" {
			parsed, err := certparse.ParsePEM([]byte(disc.RawPEM))
			if err != nil {
				log.Warn().Err(err).Str("source", result.Source).Msg("ingest: PEM parse failed, skipping cert")
				continue
			}
			disc.FingerprintSHA256 = parsed.FingerprintSHA256
		}
		if disc.FingerprintSHA256 == "" {
			log.Warn().Str("source", result.Source).Msg("ingest: cert has neither FingerprintSHA256 nor parseable RawPEM, skipping")
			continue
		}
		var hostIDForKey string
		if host != nil {
			hostIDForKey = host.ID
		}
		key := observcache.Key(result.Source, hostIDForKey, "certificate", *disc)
		if u.cache.Seen(key) {
			u.metrics.RecordHit(result.Source, "certificate")
			continue
		}
		u.metrics.RecordMiss(result.Source, "certificate")
		assetID, isNew, err := u.dedup.DedupCertificate(ctx, hostIDForKey, disc)
		if err != nil {
			return nil, fmt.Errorf("dedup certificate: %w", err)
		}
		if isNew {
			summary.CertificatesNew++
		} else {
			summary.CertificatesUpdated++
		}
		ingested = append(ingested, IngestedAsset{AssetType: "certificate", AssetID: assetID, IsNew: isNew, SourceKey: disc.FilePath})
		u.store.RecordProvenance(ctx, &model.AssetProvenance{
			AssetType: "certificate", AssetID: assetID, Source: result.Source,
			ExternalSourceID: result.ExternalSourceID,
			HostID:           hostIDForKey, FilePath: disc.FilePath, StoreType: disc.StoreType,
			RawMetadata: disc.RawMetadata,
		})
		u.cache.Mark(key)
		if err := u.scorer.ScoreAsset(ctx, "certificate", assetID); err != nil {
			log.Warn().Err(err).
				Str("asset_type", "certificate").
				Str("asset_id", assetID).
				Msg("scoring failed — ingest continues")
		}
	}

	// 3-6. SSH Keys, Libraries, Protocols, Configs — require a host.
	if host != nil {
		// 3. SSH Keys
		for i := range result.SSHKeys {
			disc := &result.SSHKeys[i]
			if disc.Source == "" {
				disc.Source = result.Source
			}
			key := observcache.Key(result.Source, host.ID, "ssh_key", *disc)
			if u.cache.Seen(key) {
				u.metrics.RecordHit(result.Source, "ssh_key")
				continue
			}
			u.metrics.RecordMiss(result.Source, "ssh_key")
			assetID, isNew, err := u.dedup.DedupSSHKey(ctx, host.ID, disc)
			if err != nil {
				return nil, fmt.Errorf("dedup ssh key: %w", err)
			}
			if isNew {
				summary.SSHKeysNew++
			} else {
				summary.SSHKeysUpdated++
			}
			ingested = append(ingested, IngestedAsset{AssetType: "ssh_key", AssetID: assetID, IsNew: isNew, SourceKey: disc.FilePath})

			// ssh_comment producer (migrated from DedupSSHKey in Phase 0).
			// Observed-tier attribution from email-shaped SSH key comments.
			if team := store.InferTeamFromSSHComment(disc.Comment); team != "" {
				sshCommentClaims = append(sshCommentClaims, OwnershipClaim{
					AssetType:  "ssh_key",
					AssetID:    assetID,
					Team:       team,
					Source:     "ssh_comment",
					Confidence: "observed",
					Evidence:   map[string]any{"comment": disc.Comment},
				})
			}

			u.store.RecordProvenance(ctx, &model.AssetProvenance{
				AssetType: "ssh_key", AssetID: assetID, Source: result.Source,
				ExternalSourceID: result.ExternalSourceID,
				HostID:           host.ID, FilePath: disc.FilePath,
				RawMetadata: disc.RawMetadata,
			})
			u.cache.Mark(key)
			if err := u.scorer.ScoreAsset(ctx, "ssh_key", assetID); err != nil {
				log.Warn().Err(err).
					Str("asset_type", "ssh_key").
					Str("asset_id", assetID).
					Msg("scoring failed — ingest continues")
			}
		}

		// 4. Libraries
		for i := range result.Libraries {
			disc := &result.Libraries[i]
			if disc.Source == "" {
				disc.Source = result.Source
			}
			key := observcache.Key(result.Source, host.ID, "crypto_library", *disc)
			if u.cache.Seen(key) {
				u.metrics.RecordHit(result.Source, "crypto_library")
				continue
			}
			u.metrics.RecordMiss(result.Source, "crypto_library")
			assetID, isNew, err := u.dedup.DedupLibrary(ctx, host.ID, disc)
			if err != nil {
				return nil, fmt.Errorf("dedup library: %w", err)
			}
			if isNew {
				summary.LibrariesNew++
			} else {
				summary.LibrariesUpdated++
			}
			ingested = append(ingested, IngestedAsset{AssetType: "crypto_library", AssetID: assetID, IsNew: isNew, SourceKey: disc.InstallPath})
			u.store.RecordProvenance(ctx, &model.AssetProvenance{
				AssetType: "crypto_library", AssetID: assetID, Source: result.Source,
				ExternalSourceID: result.ExternalSourceID,
				HostID:           host.ID, FilePath: disc.InstallPath,
				RawMetadata: disc.RawMetadata,
			})
			u.cache.Mark(key)
			if err := u.scorer.ScoreAsset(ctx, "crypto_library", assetID); err != nil {
				log.Warn().Err(err).
					Str("asset_type", "crypto_library").
					Str("asset_id", assetID).
					Msg("scoring failed — ingest continues")
			}
		}

		// CE-flavor: protocol_observations + protocol_endpoints +
		// Layer 4.1c protocol-scoring rules are EE-only. The Zeek
		// SSH/TLS protocol observations are still collected by the
		// upstream parser (result.Protocols populated) but CE silently
		// drops them — there is no scorable asset and no destination
		// table in the v2.0 baseline. Operators get protocol-level
		// visibility through the EE upgrade path.
		_ = result.Protocols

		// 6. Configs
		for i := range result.Configs {
			disc := &result.Configs[i]
			if disc.Source == "" {
				disc.Source = result.Source
			}
			key := observcache.Key(result.Source, host.ID, "crypto_config", *disc)
			if u.cache.Seen(key) {
				u.metrics.RecordHit(result.Source, "crypto_config")
				continue
			}
			u.metrics.RecordMiss(result.Source, "crypto_config")
			assetID, isNew, err := u.dedup.DedupConfig(ctx, host.ID, disc)
			if err != nil {
				return nil, fmt.Errorf("dedup config: %w", err)
			}
			if isNew {
				summary.ConfigsNew++
			} else {
				summary.ConfigsUpdated++
			}
			u.store.RecordProvenance(ctx, &model.AssetProvenance{
				AssetType: "crypto_config", AssetID: assetID, Source: result.Source,
				ExternalSourceID: result.ExternalSourceID,
				HostID:           host.ID, FilePath: disc.FilePath,
				RawMetadata: disc.RawMetadata,
			})
			u.cache.Mark(key)
			if err := u.scorer.ScoreAsset(ctx, "crypto_config", assetID); err != nil {
				log.Warn().Err(err).
					Str("asset_type", "crypto_config").
					Str("asset_id", assetID).
					Msg("scoring failed — ingest continues")
			}
		}
	}

	summary.IngestedAssets = ingested

	if len(sshCommentClaims) > 0 {
		emitted, skipped, _ := u.AttributeAssets(ctx, sshCommentClaims)
		summary.OwnershipSightingsEmitted += emitted
		summary.OwnershipSightingsSkipped += skipped
	}

	return summary, nil
}

// writeEndpointSightings records one direct-tier host_ip_sighting per
// IP the resolved host claims. Called once per Ingest cycle when
// host != nil. Errors are logged and swallowed — the primary ingest
// path (cert / ssh / library / config provenance) must not be gated
// on a secondary-evidence write. Spec §4 ingest paths, §6 failure mode.
func (u *UnifiedIngester) writeEndpointSightings(ctx context.Context, host *model.Host, result *DiscoveryResult) {
	if host == nil || len(host.IPAddresses) == 0 {
		return
	}
	// Window bounds: prefer the explicit Timestamp on the
	// DiscoveryResult (a poller may be back-filling historical
	// evidence); fall back to now. Either way, LastSeen = now — this
	// sighting "is current as of this observation".
	start := result.Timestamp
	if start.IsZero() {
		start = time.Now()
	}
	last := time.Now()
	if last.Before(start) {
		// Defensive: if the caller somehow passes a future Timestamp,
		// UpsertHostIPSighting's CHECK constraint (first_seen ≤ last_seen)
		// would reject the row. Coerce to the widest valid window.
		last = start
	}
	var attribution map[string]any
	if result.Source != "" {
		attribution = map[string]any{"source_adapter": result.Source}
	}
	for _, ip := range host.IPAddresses {
		if ip == "" {
			continue
		}
		sighting := &store.HostIPSighting{
			HostID:      host.ID,
			IP:          ip,
			FirstSeen:   start,
			LastSeen:    last,
			Source:      "endpoint",
			Confidence:  "direct",
			Attribution: attribution,
		}
		if err := u.store.UpsertHostIPSighting(ctx, sighting); err != nil {
			log.Warn().Err(err).
				Str("host_id", host.ID).
				Str("ip", ip).
				Str("source", result.Source).
				Msg("endpoint sighting upsert failed — ingest continues (secondary evidence)")
		}
	}
}

// CE-flavor: classifyProtocolObservation removed. The Layer 4.1c
// protocol-endpoint classifier (which mapped Zeek protocol observations
// into worst-ever-merge UpsertProtocolEndpointParams using the weak-
// SSH-kex / weak-SSH-cipher / weak-SSH-mac / null-export-cipher scoring
// helpers) is EE-only. Without protocol_endpoints in the schema and
// without internal/analysis/scoring/protocol.go in the package, this
// helper has no implementation surface in CE.

// AttributeAssets writes one asset_ownership_sightings row per claim.
// Team values are normalised through store.SlugifyTeam; the raw team
// on the claim is preserved in the Evidence map by the caller.
// Fail-soft per claim — individual upsert failures are logged WARN and
// swallowed (matches v1.8.1 ssh_comment + v1.9 FleetDM semantics).
//
// Returns (emitted, skipped, err) where err is non-nil only when
// ctx.Err() is set before a given claim is attempted. In that case
// processing stops at the first cancelled iteration and the partial
// counts (emitted + skipped accumulated from already-processed claims)
// are returned alongside ctx.Err(). Callers that care about total
// batch completion should check the error.
//
// Skip reasons log at INFO with reason-coded fields so operators can
// distinguish configuration errors from expected no-ops:
//   - empty_team: claim.Team is empty or whitespace-only
//   - slug_too_short: store.SlugifyTeam returned "" for this claim
func (u *UnifiedIngester) AttributeAssets(ctx context.Context, claims []OwnershipClaim) (emitted, skipped int, err error) {
	now := time.Now()
	for _, c := range claims {
		if cerr := ctx.Err(); cerr != nil {
			return emitted, skipped, cerr
		}
		if strings.TrimSpace(c.Team) == "" {
			logAttributionSkip(c, "empty_team")
			skipped++
			continue
		}
		team := store.SlugifyTeam(c.Team)
		if team == "" {
			logAttributionSkip(c, "slug_too_short")
			skipped++
			continue
		}
		if uerr := u.store.UpsertOwnershipSighting(ctx, &store.OwnershipSighting{
			AssetType:  c.AssetType,
			AssetID:    c.AssetID,
			Team:       team,
			Source:     c.Source,
			Confidence: c.Confidence,
			FirstSeen:  now,
			LastSeen:   now,
			Evidence:   c.Evidence,
		}); uerr != nil {
			log.Warn().Err(uerr).
				Str("asset_type", c.AssetType).
				Str("asset_id", c.AssetID).
				Str("team", team).
				Str("source", c.Source).
				Msg("ownership-sighting emit failed")
			continue
		}
		emitted++
	}
	return emitted, skipped, nil
}

// logAttributionSkip is the INFO-reason-code log fired when a claim is
// rejected before any upsert attempt. Reason codes ("empty_team" /
// "slug_too_short") let operators distinguish configuration errors
// from expected no-ops without log-scraping.
func logAttributionSkip(claim OwnershipClaim, reason string) {
	log.Info().
		Str("source", claim.Source).
		Str("reason", reason).
		Str("team_raw", claim.Team).
		Str("asset_type", claim.AssetType).
		Str("asset_id", claim.AssetID).
		Msg("ownership-claim rejected")
}
