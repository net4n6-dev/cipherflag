package handler

import (
	"net/http"

	"github.com/cyberflag-ai/cipherflag/internal/export"
	"github.com/cyberflag-ai/cipherflag/internal/model"
	"github.com/cyberflag-ai/cipherflag/internal/store"
)

type ExportHandler struct {
	store store.CertStore
}

func NewExportHandler(st store.CertStore) *ExportHandler {
	return &ExportHandler{store: st}
}

func (h *ExportHandler) ExportCertificates(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	q := store.CertSearchQuery{
		Search:   r.URL.Query().Get("search"),
		Grade:    r.URL.Query().Get("grade"),
		Source:   r.URL.Query().Get("source"),
		PageSize: 500,
		Page:     1,
	}

	// Paginate through ALL results (SearchCertificates caps at 500 per page)
	var allCerts []model.Certificate
	for {
		result, err := h.store.SearchCertificates(r.Context(), q)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		allCerts = append(allCerts, result.Certificates...)
		if len(allCerts) >= result.Total {
			break
		}
		q.Page++
	}

	certs := make([]*model.Certificate, len(allCerts))
	for i := range allCerts {
		certs[i] = &allCerts[i]
	}

	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=cipherflag-certificates.csv")
		export.WriteCSV(w, certs)
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=cipherflag-certificates.json")
		export.WriteJSON(w, certs)
	default:
		http.Error(w, "format must be csv or json", http.StatusBadRequest)
	}
}
