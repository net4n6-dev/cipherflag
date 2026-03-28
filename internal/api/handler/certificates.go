package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/cyberflag-ai/cipherflag/internal/analysis"
	"github.com/cyberflag-ai/cipherflag/internal/model"
	"github.com/cyberflag-ai/cipherflag/internal/store"
)

type CertHandler struct {
	store store.CertStore
}

func NewCertHandler(s store.CertStore) *CertHandler {
	return &CertHandler{store: s}
}

func (h *CertHandler) List(w http.ResponseWriter, r *http.Request) {
	q := store.CertSearchQuery{
		Search:   r.URL.Query().Get("search"),
		Grade:    r.URL.Query().Get("grade"),
		Source:   r.URL.Query().Get("source"),
		IssuerCN:      r.URL.Query().Get("issuer_cn"),
		SubjectOU:     r.URL.Query().Get("subject_ou"),
		IssuerOrg:     r.URL.Query().Get("issuer_org"),
		KeyAlgorithm:  r.URL.Query().Get("key_algorithm"),
		SignatureAlgo: r.URL.Query().Get("signature_algorithm"),
		ServerName:     r.URL.Query().Get("server_name"),
		TLSVersion:    r.URL.Query().Get("tls_version"),
		CipherStrength: r.URL.Query().Get("cipher_strength"),
		SortBy:        r.URL.Query().Get("sort_by"),
		SortDir:  r.URL.Query().Get("sort_dir"),
	}

	if p := r.URL.Query().Get("page"); p != "" {
		q.Page, _ = strconv.Atoi(p)
	}
	if ps := r.URL.Query().Get("page_size"); ps != "" {
		q.PageSize, _ = strconv.Atoi(ps)
	}
	if isCA := r.URL.Query().Get("is_ca"); isCA != "" {
		v := isCA == "true"
		q.IsCA = &v
	}
	if exp := r.URL.Query().Get("expired"); exp == "true" {
		v := true
		q.Expired = &v
	}
	if ed := r.URL.Query().Get("expiring_within_days"); ed != "" {
		v, _ := strconv.Atoi(ed)
		q.ExpiringWithinDays = &v
	}

	result, err := h.store.SearchCertificates(r.Context(), q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *CertHandler) Get(w http.ResponseWriter, r *http.Request) {
	fp := chi.URLParam(r, "fingerprint")
	cert, err := h.store.GetCertificate(r.Context(), fp)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cert == nil {
		writeError(w, http.StatusNotFound, "certificate not found")
		return
	}

	// Include health report
	report, _ := h.store.GetHealthReport(r.Context(), fp)

	writeJSON(w, http.StatusOK, map[string]any{
		"certificate":   cert,
		"health_report": report,
	})
}

func (h *CertHandler) Chain(w http.ResponseWriter, r *http.Request) {
	fp := chi.URLParam(r, "fingerprint")

	cert, err := h.store.GetCertificate(r.Context(), fp)
	if err != nil || cert == nil {
		writeError(w, http.StatusNotFound, "certificate not found")
		return
	}

	allCerts, err := h.store.GetAllCertificatesForGraph(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	reports := loadReportsMap(h.store, r)

	tree := analysis.BuildChainTree(cert, allCerts, reports)
	writeJSON(w, http.StatusOK, tree)
}

func (h *CertHandler) Observations(w http.ResponseWriter, r *http.Request) {
	fp := chi.URLParam(r, "fingerprint")
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		limit, _ = strconv.Atoi(l)
	}

	obs, err := h.store.GetObservations(r.Context(), fp, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"observations": obs})
}

func (h *CertHandler) Health(w http.ResponseWriter, r *http.Request) {
	fp := chi.URLParam(r, "fingerprint")
	report, err := h.store.GetHealthReport(r.Context(), fp)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if report == nil {
		writeError(w, http.StatusNotFound, "no health report for this certificate")
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (h *CertHandler) Endpoints(w http.ResponseWriter, r *http.Request) {
	eps, err := h.store.GetAllEndpointProfiles(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"endpoints": eps})
}

func (h *CertHandler) GlobalSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		writeError(w, http.StatusBadRequest, "query parameter 'q' is required")
		return
	}

	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 50 {
			limit = n
		}
	}

	result, err := h.store.GlobalSearch(r.Context(), query, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func loadReportsMap(s store.CertStore, r *http.Request) map[string]*model.HealthReport {
	reports, _ := s.GetAllHealthReports(r.Context())
	m := make(map[string]*model.HealthReport, len(reports))
	for i := range reports {
		m[reports[i].CertFingerprint] = &reports[i]
	}
	return m
}
