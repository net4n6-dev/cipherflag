package handler

import (
	"net/http"
	"strconv"

	"github.com/cyberflag-ai/cipherflag/internal/store"
)

type ReportsHandler struct {
	store store.CertStore
}

func NewReportsHandler(s store.CertStore) *ReportsHandler {
	return &ReportsHandler{store: s}
}

func (h *ReportsHandler) DomainReport(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("q")
	if domain == "" {
		writeError(w, http.StatusBadRequest, "query parameter 'q' is required")
		return
	}

	report, err := h.store.GetDomainReport(r.Context(), domain)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (h *ReportsHandler) CAReport(w http.ResponseWriter, r *http.Request) {
	fp := r.URL.Query().Get("fingerprint")
	issuerCN := r.URL.Query().Get("issuer_cn")
	if fp == "" && issuerCN == "" {
		writeError(w, http.StatusBadRequest, "either 'fingerprint' or 'issuer_cn' parameter is required")
		return
	}

	report, err := h.store.GetCAReport(r.Context(), fp, issuerCN)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (h *ReportsHandler) ComplianceReport(w http.ResponseWriter, r *http.Request) {
	report, err := h.store.GetComplianceReport(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (h *ReportsHandler) ExpiryReport(w http.ResponseWriter, r *http.Request) {
	days := 30
	if d := r.URL.Query().Get("days"); d != "" {
		if n, err := strconv.Atoi(d); err == nil && n > 0 && n <= 365 {
			days = n
		}
	}

	report, err := h.store.GetExpiryReport(r.Context(), days)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}
