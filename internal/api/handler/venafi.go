package handler

import (
	"net/http"
	"time"

	"github.com/cyberflag-ai/cipherflag/internal/store"
)

type VenafiHandler struct {
	store        store.CertStore
	enabled      bool
	pushInterval time.Duration
}

func NewVenafiHandler(s store.CertStore, enabled bool, pushInterval time.Duration) *VenafiHandler {
	return &VenafiHandler{
		store:        s,
		enabled:      enabled,
		pushInterval: pushInterval,
	}
}

func (h *VenafiHandler) Status(w http.ResponseWriter, r *http.Request) {
	stats, err := h.store.GetVenafiPushStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	stats.Enabled = h.enabled

	if stats.LastPushAt != nil && h.enabled {
		next := stats.LastPushAt.Add(h.pushInterval)
		stats.NextPushAt = &next
	}

	writeJSON(w, http.StatusOK, stats)
}
