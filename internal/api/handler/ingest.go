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

package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
)

type IngestHandler struct {
	ingester ingest.Ingester
}

func NewIngestHandler(ing ingest.Ingester) *IngestHandler {
	return &IngestHandler{ingester: ing}
}

type ingestRequest struct {
	Source       string                    `json:"source"`
	SourceHostID string                    `json:"source_host_id"`
	Hostname     string                    `json:"hostname"`
	IPAddresses  []string                  `json:"ip_addresses"`
	OSFamily     string                    `json:"os_family"`
	Timestamp    time.Time                 `json:"timestamp"`
	Certificates []dedup.CertDiscovery     `json:"certificates"`
	SSHKeys      []dedup.SSHKeyDiscovery   `json:"ssh_keys"`
	Libraries    []dedup.LibraryDiscovery  `json:"libraries"`
	Protocols    []dedup.ProtocolDiscovery `json:"protocols"`
	Configs      []dedup.ConfigDiscovery   `json:"configs"`
}

func (h *IngestHandler) Ingest(w http.ResponseWriter, r *http.Request) {
	var req ingestRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 10*1024*1024)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Source == "" {
		writeError(w, http.StatusBadRequest, "source is required")
		return
	}

	if req.Timestamp.IsZero() {
		req.Timestamp = time.Now()
	}

	result := &ingest.DiscoveryResult{
		Source:       req.Source,
		SourceHostID: req.SourceHostID,
		Hostname:     req.Hostname,
		IPAddresses:  req.IPAddresses,
		OSFamily:     req.OSFamily,
		Timestamp:    req.Timestamp,
		Certificates: req.Certificates,
		SSHKeys:      req.SSHKeys,
		Libraries:    req.Libraries,
		Protocols:    req.Protocols,
		Configs:      req.Configs,
	}

	summary, err := h.ingester.Ingest(r.Context(), result)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, summary)
}
