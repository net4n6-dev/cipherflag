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

package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/analysis/scoring"
	"github.com/net4n6-dev/cipherflag/internal/api/handler"
	"github.com/net4n6-dev/cipherflag/internal/api/middleware"
	"github.com/net4n6-dev/cipherflag/internal/config"
	cbomimport "github.com/net4n6-dev/cipherflag/internal/import/cbom"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/ingest/observcache"
	"github.com/net4n6-dev/cipherflag/internal/ingest/osquery"
	"github.com/net4n6-dev/cipherflag/internal/sse"
	"github.com/net4n6-dev/cipherflag/internal/store"
	"github.com/net4n6-dev/cipherflag/internal/web"
)

// NewRouter builds the HTTP router with all CE-flavor API routes.
//
// EE-only handler wiring (risk, host blast-radius, host-dependencies, host
// subgraph, host trust store, AI usage, briefing, container images,
// network targets, teams, external sources, rank review, PQC migration
// planner, evidence export, agency OMB) has been stripped. The Layer
// 0/1/2/4/5/6.1a-c surface remains, including the PKI cert-graph
// landscape views (/graph/*) and the SSE live-update stream (/events/stream).
//
// cache and scorer are wired into the UnifiedIngester used by the ingest
// and osquery webhook handlers. Pass observcache.NewNoop() and
// scoring.NewNoopScorer() to keep the legacy no-op behaviour.
func NewRouter(
	st store.CryptoStore,
	cfg *config.Config,
	cfgPath string,
	frontendURL string,
	jwtSecret []byte,
	cache observcache.ObservationCache,
	scorer scoring.Scorer,
	sseHub *sse.Hub,
) http.Handler {
	r := chi.NewRouter()

	// Global middleware
	r.Use(chiMiddleware.RequestID)
	r.Use(chiMiddleware.RealIP)
	r.Use(chiMiddleware.Recoverer)
	r.Use(middleware.CORS(frontendURL))

	// Handlers — CE-bound only
	certH := handler.NewCertHandler(st)
	statsH := handler.NewStatsHandler(st)
	reportsH := handler.NewReportsHandler(st)
	configH := handler.NewConfigHandler(cfg, cfgPath, st)
	authH := handler.NewAuthHandler(st, jwtSecret)
	agentTokenH := handler.NewAgentTokenHandler(st)
	unifiedIngester := ingest.NewUnifiedIngester(
		st,
		ingest.WithObservationCache(cache),
		ingest.WithScorer(scorer),
	)
	ingestH := handler.NewIngestHandler(unifiedIngester)
	osqueryAdapter := osquery.NewAdapter(unifiedIngester)
	cbomImporter := cbomimport.NewImporter(unifiedIngester)
	cbomH := handler.NewCBOMHandler(st, &cfg.CBOM, cbomImporter)
	providersH := handler.NewProvidersHandler(st)
	reposMgmtH := handler.NewRepositoriesHandler(st)
	// CE-flavor: deterministic-only scan submission. AIRuntime is left
	// at zero value (Enabled=false) — the handler short-circuits the
	// AI-gate path. Pricing table is unused in CE.
	scansH := handler.NewScansHandler(st, handler.AIRuntime{}, nil)
	findingsH := handler.NewFindingsHandler(st)
	repoCBOMH := handler.NewRepoCBOMHandler(st, cfg.CBOM.Signing)
	sshKeyH := handler.NewSSHKeyHandler(st)
	cryptoLibH := handler.NewCryptoLibraryHandler(st)
	cryptoConfigH := handler.NewCryptoConfigHandler(st)
	hostH := handler.NewHostHandler(st)
	assetFindingH := handler.NewAssetFindingHandler(st)
	lineageH := handler.NewLineageHandler(st)
	hygieneH := handler.NewHygieneHandler(st)
	shadowCAH := handler.NewShadowCAHandler(st)
	appMetaH := handler.NewApplicationMetadataHandler(st)
	assetOwnH := handler.NewAssetOwnershipHandler(st)
	venafiH := handler.NewVenafiHandler(st, cfg, cfgPath)
	graphH := handler.NewGraphHandler(st)

	// Health check
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// API v1
	r.Route("/api/v1", func(r chi.Router) {
		// Public auth routes (no auth middleware)
		r.Post("/auth/login", authH.Login)
		r.Get("/auth/status", authH.Status)
		r.Post("/auth/setup-admin", authH.SetupAdmin)
		r.Get("/auth/me", authH.Me)

		// All authenticated routes
		r.Group(func(r chi.Router) {
			r.Use(middleware.Auth(st, jwtSecret))

			// Auth endpoints (any role)
			r.Post("/auth/logout", authH.Logout)
			r.Put("/auth/me/password", authH.ChangePassword)

			// Auth endpoints (admin only)
			r.Route("/auth/users", func(r chi.Router) {
				r.Use(middleware.RequireAdmin)
				r.Get("/", authH.ListUsers)
				r.Post("/", authH.CreateUser)
				r.Put("/{id}", authH.UpdateUser)
				r.Delete("/{id}", authH.DeleteUser)
			})

			// Agent tokens (admin only)
			r.Route("/auth/agent-tokens", func(r chi.Router) {
				r.Use(middleware.RequireAdmin)
				r.Post("/", agentTokenH.Create)
				r.Get("/", agentTokenH.List)
				r.Delete("/{id}", agentTokenH.Delete)
			})

			// Ingest
			r.Post("/ingest", ingestH.Ingest)
			r.Post("/ingest/osquery", osqueryAdapter.HandleWebhook)

			// Certificates
			r.Get("/certificates", certH.List)
			r.Get("/certificates/{fingerprint}", certH.Get)
			r.Get("/certificates/{fingerprint}/chain", certH.Chain)
			r.Get("/certificates/{fingerprint}/observations", certH.Observations)
			r.Get("/certificates/{fingerprint}/health", certH.Health)

			// Global search
			r.Get("/search", certH.GlobalSearch)

			// Stats (full analytics suite — CE parity with EE; the host
			// dependency/blast-radius Cytoscape graph views remain EE-only)
			r.Get("/stats/summary", statsH.Summary)
			r.Get("/stats/ciphers", statsH.Ciphers)
			r.Get("/stats/issuers", statsH.Issuers)
			r.Get("/stats/expiry-timeline", statsH.ExpiryTimeline)
			r.Get("/stats/crypto-posture", statsH.CryptoPosture)
			r.Get("/stats/expiry-forecast", statsH.ExpiryForecast)
			r.Get("/stats/chain-flow", statsH.ChainFlow)
			r.Get("/stats/ownership", statsH.Ownership)
			r.Get("/stats/deployment", statsH.Deployment)
			r.Get("/stats/source-lineage", statsH.SourceLineage)

			// PKI tree
			r.Get("/pki/tree", statsH.PKITree)

			// Graph / PKI landscape (Cytoscape.js views)
			r.Get("/graph/landscape", graphH.Landscape)
			r.Get("/graph/chain/{fingerprint}", graphH.ChainGraph)
			r.Get("/graph/landscape/aggregated", graphH.AggregatedLandscape)
			r.Get("/graph/ca/{fingerprint}/children", graphH.CAChildren)
			r.Get("/graph/ca/{fingerprint}/blast-radius", graphH.BlastRadius)

			// SSE live-update event stream
			r.Get("/events/stream", sse.NewHandler(sseHub))

			// Endpoints
			r.Get("/endpoints", certH.Endpoints)

			// Algorithmic hygiene — AQ-AH-01 (CE-bound)
			r.Get("/analysis/weak-algorithms", hygieneH.ListWeakAlgorithms)

			// HNDL risk — AQ-AH-04 (CE-bound; default horizon 2030 CNSA 2.0)
			r.Get("/analysis/hndl", appMetaH.ListHNDL)

			// Shadow CA inventory — AQ-IC-04 (CE-bound)
			r.Route("/inventory", func(r chi.Router) {
				r.Get("/shadow-cas", shadowCAH.ListShadow)
				r.Get("/declared-cas", shadowCAH.ListDeclared)
				r.Group(func(r chi.Router) {
					r.Use(middleware.RequireAdmin)
					r.Post("/declared-cas", shadowCAH.Declare)
					r.Delete("/declared-cas/{fingerprint}", shadowCAH.Revoke)
				})
			})

			// CBOM export (Layer 5.1)
			r.Get("/export/cbom", cbomH.Download)

			// CBOM import (Layer 5.2)
			r.Post("/import/cbom", cbomH.Import)

			// Reports
			r.Get("/reports/domain", reportsH.DomainReport)
			r.Get("/reports/ca", reportsH.CAReport)
			r.Get("/reports/compliance", reportsH.ComplianceReport)
			r.Get("/reports/expiry", reportsH.ExpiryReport)

			// Venafi push export (Layer 3 connector; disabled by default)
			r.Get("/venafi/status", venafiH.Status)
			r.Get("/venafi/config", venafiH.GetConfig)
			r.Route("/venafi", func(r chi.Router) {
				r.Use(middleware.RequireAdmin)
				r.Put("/config", venafiH.UpdateConfig)
				r.Post("/test-connection", venafiH.TestConnection)
			})

			// Config
			r.Get("/config/sources", configH.GetSources)
			r.Get("/config/interfaces", configH.ListInterfaces)
			r.Route("/config", func(r chi.Router) {
				r.Use(middleware.RequireAdmin)
				r.Put("/sources", configH.UpdateSources)
			})

			// Repo scanner — providers (Layer 6.1b-1)
			r.Route("/repo/providers", func(r chi.Router) {
				r.Get("/", providersH.List)
				r.Get("/{id}", providersH.Get)
				r.Group(func(r chi.Router) {
					r.Use(middleware.RequireAdmin)
					r.Post("/", providersH.Create)
					r.Delete("/{id}", providersH.Delete)
				})
			})

			// Repo scanner — repositories (Layer 6.1b-4)
			r.Route("/repo/repos", func(r chi.Router) {
				r.Get("/", reposMgmtH.List)
				r.Get("/{id}", reposMgmtH.Get)
				r.Group(func(r chi.Router) {
					r.Use(middleware.RequireAdmin)
					r.Post("/", reposMgmtH.Create)
					r.Patch("/{id}", reposMgmtH.Patch)
					r.Delete("/{id}", reposMgmtH.Delete)
				})
			})

			// Repo scanner — scans (Layer 6.1b-4; deterministic only in CE)
			r.Route("/repo/scans", func(r chi.Router) {
				r.Get("/", scansH.List)
				r.Get("/{id}", scansH.Get)
				r.Post("/", scansH.Create)
				r.Delete("/{id}", scansH.Cancel)
			})

			// Repo scanner — findings (Layer 6.1b-4)
			r.Get("/repo/findings", findingsH.List)

			// Repo scanner — CBOM export (Layer 6.1c-2)
			r.Get("/repo/exports/cbom", repoCBOMH.Download)

			// SSH keys
			r.Get("/ssh-keys", sshKeyH.List)
			r.Get("/ssh-keys/{id}", sshKeyH.Get)

			// Crypto libraries
			r.Get("/crypto-libraries", cryptoLibH.List)
			r.Get("/crypto-libraries/{id}", cryptoLibH.Get)

			// Crypto configs
			r.Get("/crypto-configs", cryptoConfigH.List)
			r.Get("/crypto-configs/{id}", cryptoConfigH.Get)

			// Hosts (CE subset — no dependencies / blast-radius / subgraph /
			// trust-store endpoints; those back Layer 4.4 + 8 features)
			r.Get("/hosts", hostH.List)
			r.Get("/hosts/{id}", hostH.Get)
			r.Get("/hosts/{id}/assets", hostH.ListAssets)

			// Asset-scoped finding drill-down + polymorphic lineage fan-out
			r.Get("/findings/{asset_type}/{asset_id}/{rule_id}", assetFindingH.Get)
			r.Get("/lineage/{asset_type}/{asset_id}", lineageH.Get)

			// v1.7.0 — per-application TTL metadata backing the HNDL flag.
			// GET is viewer+; mutations are admin-only.
			r.Get("/applications/{tag}/metadata", appMetaH.Get)
			r.Group(func(r chi.Router) {
				r.Use(middleware.RequireAdmin)
				r.Put("/applications/{tag}/metadata", appMetaH.Put)
				r.Delete("/applications/{tag}/metadata", appMetaH.Delete)
			})

			// v1.8.0 — per-asset ownership resolver (AQ-OP-01).
			// GET is viewer+; PUT/DELETE are admin-only.
			r.Get("/assets/{type}/{id}/ownership", assetOwnH.Get)
			r.Group(func(r chi.Router) {
				r.Use(middleware.RequireAdmin)
				r.Put("/assets/{type}/{id}/ownership", assetOwnH.Put)
				r.Delete("/assets/{type}/{id}/ownership/{source}/{team}", assetOwnH.Delete)
			})

			// Extended stats
			r.Get("/stats/library-distribution", statsH.LibraryDistribution)
			r.Get("/stats/ssh-key-analytics", statsH.SSHKeyAnalytics)
		})
	})

	log.Info().Msg("CE API routes registered")

	// SPA catch-all. Registered last so all /api/v1 and /healthz routes
	// take precedence; unmatched /api/* still gets a JSON 404 from the
	// handler, everything else gets the embedded SPA shell.
	r.NotFound(web.Handler().ServeHTTP)
	return r
}
