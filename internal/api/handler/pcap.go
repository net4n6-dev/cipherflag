package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

type PCAPHandler struct {
	store    store.CertStore
	inputDir string
	maxSize  int64
}

func NewPCAPHandler(st store.CertStore, inputDir string, maxSizeMB int) *PCAPHandler {
	return &PCAPHandler{store: st, inputDir: inputDir, maxSize: int64(maxSizeMB) * 1024 * 1024}
}

// Upload accepts a multipart PCAP file upload and creates a processing job.
func (h *PCAPHandler) Upload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, h.maxSize)

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read uploaded file: "+err.Error())
		return
	}
	defer file.Close()

	jobID := uuid.New().String()
	job := &model.PCAPJob{
		ID:       jobID,
		Filename: header.Filename,
		FileSize: header.Size,
		Status:   "pending",
	}

	if err := h.store.CreatePCAPJob(r.Context(), job); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create job: "+err.Error())
		return
	}

	jobDir := filepath.Join(h.inputDir, jobID)
	if err := os.MkdirAll(jobDir, 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create job directory: "+err.Error())
		return
	}

	destPath := filepath.Join(jobDir, header.Filename)
	dest, err := os.Create(destPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create file: "+err.Error())
		return
	}
	defer dest.Close()

	if _, err := io.Copy(dest, file); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write file: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(job)
}

// GetJob returns the status of a single PCAP processing job.
func (h *PCAPHandler) GetJob(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	job, err := h.store.GetPCAPJob(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if job == nil {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}

	writeJSON(w, http.StatusOK, job)
}

// ListJobs returns the most recent PCAP processing jobs.
func (h *PCAPHandler) ListJobs(w http.ResponseWriter, r *http.Request) {
	jobs, err := h.store.ListPCAPJobs(r.Context(), 50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"jobs": jobs})
}
