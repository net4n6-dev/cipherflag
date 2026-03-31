package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/api/handler"
	"github.com/net4n6-dev/cipherflag/internal/api/middleware"
	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// NewRouter builds the HTTP router with all API routes.
func NewRouter(st store.CertStore, cfg *config.Config, cfgPath string, frontendURL string, pcapInputDir string, pcapMaxSizeMB int, jwtSecret []byte) http.Handler {
	r := chi.NewRouter()

	// Global middleware
	r.Use(chiMiddleware.RequestID)
	r.Use(chiMiddleware.RealIP)
	r.Use(chiMiddleware.Recoverer)
	r.Use(middleware.CORS(frontendURL))

	// Handlers
	certH := handler.NewCertHandler(st)
	graphH := handler.NewGraphHandler(st)
	statsH := handler.NewStatsHandler(st)
	exportH := handler.NewExportHandler(st)
	pcapH := handler.NewPCAPHandler(st, pcapInputDir, pcapMaxSizeMB)
	venafiH := handler.NewVenafiHandler(st, cfg, cfgPath)
	reportsH := handler.NewReportsHandler(st)
	configH := handler.NewConfigHandler(cfg, cfgPath)
	authH := handler.NewAuthHandler(st, jwtSecret)

	// Health check
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// API v1
	r.Route("/api/v1", func(r chi.Router) {
		// Public auth routes (no auth middleware)
		r.Post("/auth/login", authH.Login)
		r.Get("/auth/status", authH.Status)
		r.Post("/auth/setup-admin", authH.SetupAdmin)

		// All authenticated routes
		r.Group(func(r chi.Router) {
			r.Use(middleware.Auth(st, jwtSecret))

			// Auth endpoints (any role)
			r.Post("/auth/logout", authH.Logout)
			r.Get("/auth/me", authH.Me)
			r.Put("/auth/me/password", authH.ChangePassword)

			// Auth endpoints (admin only)
			r.Route("/auth/users", func(r chi.Router) {
				r.Use(middleware.RequireAdmin)
				r.Get("/", authH.ListUsers)
				r.Post("/", authH.CreateUser)
				r.Put("/{id}", authH.UpdateUser)
				r.Delete("/{id}", authH.DeleteUser)
			})

			// Certificates
			r.Get("/certificates", certH.List)
			r.Get("/certificates/{fingerprint}", certH.Get)
			r.Get("/certificates/{fingerprint}/chain", certH.Chain)
			r.Get("/certificates/{fingerprint}/observations", certH.Observations)
			r.Get("/certificates/{fingerprint}/health", certH.Health)

			// Global search
			r.Get("/search", certH.GlobalSearch)

			// Graph
			r.Get("/graph/landscape", graphH.Landscape)
			r.Get("/graph/chain/{fingerprint}", graphH.ChainGraph)
			r.Get("/graph/landscape/aggregated", graphH.AggregatedLandscape)
			r.Get("/graph/ca/{fingerprint}/children", graphH.CAChildren)
			r.Get("/graph/ca/{fingerprint}/blast-radius", graphH.BlastRadius)

			// Stats
			r.Get("/stats/summary", statsH.Summary)
			r.Get("/stats/ciphers", statsH.Ciphers)
			r.Get("/stats/issuers", statsH.Issuers)
			r.Get("/stats/expiry-timeline", statsH.ExpiryTimeline)
			r.Get("/stats/chain-flow", statsH.ChainFlow)
			r.Get("/stats/ownership", statsH.Ownership)
			r.Get("/stats/deployment", statsH.Deployment)
			r.Get("/stats/crypto-posture", statsH.CryptoPosture)
			r.Get("/stats/expiry-forecast", statsH.ExpiryForecast)
			r.Get("/stats/source-lineage", statsH.SourceLineage)

			// PKI tree
			r.Get("/pki/tree", statsH.PKITree)

			// Endpoints
			r.Get("/endpoints", certH.Endpoints)

			// Export
			r.Get("/export/certificates", exportH.ExportCertificates)

			// PCAP
			r.Post("/pcap/upload", pcapH.Upload)
			r.Get("/pcap/jobs/{id}", pcapH.GetJob)
			r.Get("/pcap/jobs", pcapH.ListJobs)

			// Reports
			r.Get("/reports/domain", reportsH.DomainReport)
			r.Get("/reports/ca", reportsH.CAReport)
			r.Get("/reports/compliance", reportsH.ComplianceReport)
			r.Get("/reports/expiry", reportsH.ExpiryReport)

			// Venafi
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
		})
	})

	log.Info().Msg("API routes registered")
	return r
}
