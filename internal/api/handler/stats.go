package handler

import (
	"net/http"

	"github.com/cyberflag-ai/cipherflag/internal/store"
)

type StatsHandler struct {
	store store.CertStore
}

func NewStatsHandler(s store.CertStore) *StatsHandler {
	return &StatsHandler{store: s}
}

func (h *StatsHandler) Summary(w http.ResponseWriter, r *http.Request) {
	stats, err := h.store.GetSummaryStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (h *StatsHandler) Ciphers(w http.ResponseWriter, r *http.Request) {
	stats, err := h.store.GetCipherStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (h *StatsHandler) PKITree(w http.ResponseWriter, r *http.Request) {
	tree, err := h.store.GetPKITree(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, tree)
}

func (h *StatsHandler) Issuers(w http.ResponseWriter, r *http.Request) {
	stats, err := h.store.GetIssuerStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"issuers": stats})
}

func (h *StatsHandler) ExpiryTimeline(w http.ResponseWriter, r *http.Request) {
	timeline, err := h.store.GetExpiryTimeline(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, timeline)
}

func (h *StatsHandler) ChainFlow(w http.ResponseWriter, r *http.Request) {
	resp, err := h.store.GetChainFlow(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *StatsHandler) Ownership(w http.ResponseWriter, r *http.Request) {
	resp, err := h.store.GetOwnershipStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *StatsHandler) Deployment(w http.ResponseWriter, r *http.Request) {
	resp, err := h.store.GetDeploymentStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *StatsHandler) CryptoPosture(w http.ResponseWriter, r *http.Request) {
	resp, err := h.store.GetCryptoPosture(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *StatsHandler) ExpiryForecast(w http.ResponseWriter, r *http.Request) {
	resp, err := h.store.GetExpiryForecast(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
