package handler

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/net4n6-dev/cipherflag/internal/analysis"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

type GraphHandler struct {
	store store.CertStore
}

func NewGraphHandler(s store.CertStore) *GraphHandler {
	return &GraphHandler{store: s}
}

// Landscape returns all certificates as Cytoscape.js-compatible graph elements.
func (h *GraphHandler) Landscape(w http.ResponseWriter, r *http.Request) {
	certs, err := h.store.GetAllCertificatesForGraph(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	reports := loadReportsMap(h.store, r)
	graph := analysis.BuildGraphData(certs, reports)
	writeJSON(w, http.StatusOK, graph)
}

// ChainGraph returns a chain-specific graph starting from a fingerprint.
func (h *GraphHandler) ChainGraph(w http.ResponseWriter, r *http.Request) {
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
	graph := analysis.BuildChainGraphData(tree)
	writeJSON(w, http.StatusOK, graph)
}

// AggregatedLandscape returns CAs-only with aggregate stats for the force graph.
func (h *GraphHandler) AggregatedLandscape(w http.ResponseWriter, r *http.Request) {
	resp, err := h.store.GetAggregatedLandscape(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// CAChildren returns the direct children of a CA node.
func (h *GraphHandler) CAChildren(w http.ResponseWriter, r *http.Request) {
	fp := chi.URLParam(r, "fingerprint")

	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}

	offset := 0
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}

	resp, err := h.store.GetCAChildren(r.Context(), fp, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// BlastRadius returns the full downstream subgraph of a CA.
func (h *GraphHandler) BlastRadius(w http.ResponseWriter, r *http.Request) {
	fp := chi.URLParam(r, "fingerprint")

	resp, err := h.store.GetBlastRadius(r.Context(), fp, 500)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
