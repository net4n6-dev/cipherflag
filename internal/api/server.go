package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog/log"

	"github.com/cyberflag-ai/cipherflag/internal/api/handler"
	"github.com/cyberflag-ai/cipherflag/internal/api/middleware"
	"github.com/cyberflag-ai/cipherflag/internal/store"
)

// NewRouter builds the HTTP router with all API routes.
func NewRouter(st store.CertStore, frontendURL string, pcapInputDir string, pcapMaxSizeMB int) http.Handler {
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

	// Health check
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// API v1
	r.Route("/api/v1", func(r chi.Router) {
		// Certificates
		r.Get("/certificates", certH.List)
		r.Get("/certificates/{fingerprint}", certH.Get)
		r.Get("/certificates/{fingerprint}/chain", certH.Chain)
		r.Get("/certificates/{fingerprint}/observations", certH.Observations)
		r.Get("/certificates/{fingerprint}/health", certH.Health)

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
	})

	log.Info().Msg("API routes registered")
	return r
}
