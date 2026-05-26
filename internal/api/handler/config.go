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
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

// configStore is the minimal store interface required by ConfigHandler.
type configStore interface {
	GetIngestionState(ctx context.Context, sourceName string) (*model.IngestionState, error)
	CountAssetsBySource(ctx context.Context, sourceName string) (int, error)
}

type ConfigHandler struct {
	cfg     *config.Config
	cfgPath string
	store   configStore
}

func NewConfigHandler(cfg *config.Config, cfgPath string, st configStore) *ConfigHandler {
	return &ConfigHandler{cfg: cfg, cfgPath: cfgPath, store: st}
}

// SourceRow is one entry in the GET /config/sources response.
type SourceRow struct {
	Name                string     `json:"name"`
	Enabled             bool       `json:"enabled"`
	PollIntervalSeconds int        `json:"poll_interval_seconds"`
	LastSyncAt          *time.Time `json:"last_sync_at"`
	Status              string     `json:"status"`
	AssetCount          int        `json:"asset_count"`
}

// SourcesConfigResponse is the response for GET /config/sources.
type SourcesConfigResponse struct {
	Sources   []SourceRow             `json:"sources"`
	Corelight CorelightConfigResponse `json:"corelight"`
	PCAP      PCAPConfigResponse      `json:"pcap"`
}

type CorelightConfigResponse struct {
	Enabled  bool   `json:"enabled"`
	APIURL   string `json:"api_url"`
	HasToken bool   `json:"has_token"`
}

type PCAPConfigResponse struct {
	MaxFileSizeMB  int    `json:"max_file_size_mb"`
	RetentionHours int    `json:"retention_hours"`
	InputDir       string `json:"input_dir"`
}

// deriveStatus computes "connected", "stale", or "disconnected" from the
// ingestion state's UpdatedAt vs the source's poll interval.
//
//   - "connected"    — last_sync_at is within 2× poll_interval of now
//   - "stale"        — last_sync_at is older than 2× poll_interval
//   - "disconnected" — no record in ingestion_state (never synced)
func deriveStatus(lastSyncAt *time.Time, pollIntervalSeconds int) string {
	if lastSyncAt == nil {
		return "disconnected"
	}
	if pollIntervalSeconds <= 0 {
		pollIntervalSeconds = 3600
	}
	threshold := time.Duration(pollIntervalSeconds*2) * time.Second
	if time.Since(*lastSyncAt) <= threshold {
		return "connected"
	}
	return "stale"
}

// sourceRow builds a SourceRow for one discovery platform by querying the
// ingestion_state table and the asset count. A nil store skips the DB
// lookups (useful in unit tests that only test config-only paths).
func (h *ConfigHandler) sourceRow(ctx context.Context, name string, enabled bool, pollIntervalSeconds int) SourceRow {
	row := SourceRow{
		Name:                name,
		Enabled:             enabled,
		PollIntervalSeconds: pollIntervalSeconds,
		Status:              "disconnected",
	}
	if h.store == nil {
		return row
	}
	if st, err := h.store.GetIngestionState(ctx, name); err == nil && st != nil {
		t := st.UpdatedAt
		row.LastSyncAt = &t
		row.Status = deriveStatus(&t, pollIntervalSeconds)
	}
	if n, err := h.store.CountAssetsBySource(ctx, name); err == nil {
		row.AssetCount = n
	}
	return row
}

// GetSources returns configuration and live status for all 9 discovery
// platforms, plus Corelight and PCAP metadata.
func (h *ConfigHandler) GetSources(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c := h.cfg

	// Poll-interval helpers for platforms that don't have a single top-level field.
	s1InventoryPoll := c.Sources.SentinelOne.AppInventory.PollIntervalSeconds
	if s1InventoryPoll == 0 {
		s1InventoryPoll = 3600
	}
	abInventoryPoll := c.Sources.Absolute.Inventory.PollIntervalSeconds
	if abInventoryPoll == 0 {
		abInventoryPoll = 3600
	}

	sources := []SourceRow{
		h.sourceRow(ctx, "zeek", c.Sources.ZeekFile.Enabled, c.Sources.ZeekFile.PollIntervalSeconds),
		// osquery is webhook-only (no config section); enabled defaults to false
		h.sourceRow(ctx, "osquery", false, 0),
		h.sourceRow(ctx, "velociraptor", c.Sources.Velociraptor.Enabled, c.Sources.Velociraptor.PollIntervalSeconds),
		// wazuh is webhook-only (no config section); enabled defaults to false
		h.sourceRow(ctx, "wazuh", false, 0),
		h.sourceRow(ctx, "defender", c.Sources.Defender.Enabled, c.Sources.Defender.PollIntervalSeconds),
		h.sourceRow(ctx, "sentinelone", c.Sources.SentinelOne.Enabled, s1InventoryPoll),
		h.sourceRow(ctx, "tanium", c.Sources.Tanium.Enabled, c.Sources.Tanium.PollIntervalSeconds),
		h.sourceRow(ctx, "absolute", c.Sources.Absolute.Enabled, abInventoryPoll),
		h.sourceRow(ctx, "netwrix", c.Sources.Netwrix.Enabled, c.Sources.Netwrix.PollIntervalSeconds),
	}

	writeJSON(w, http.StatusOK, SourcesConfigResponse{
		Sources: sources,
		Corelight: CorelightConfigResponse{
			Enabled:  c.Sources.Corelight.Enabled,
			APIURL:   c.Sources.Corelight.APIURL,
			HasToken: c.Sources.Corelight.APIToken != "",
		},
		PCAP: PCAPConfigResponse{
			MaxFileSizeMB:  c.PCAP.MaxFileSizeMB,
			RetentionHours: c.PCAP.RetentionHours,
			InputDir:       c.PCAP.InputDir,
		},
	})
}

// SourcesConfigUpdate is the request body for updating sources config.
type SourcesConfigUpdate struct {
	Zeek      *ZeekConfigUpdate      `json:"zeek,omitempty"`
	Corelight *CorelightConfigUpdate `json:"corelight,omitempty"`
	PCAP      *PCAPConfigUpdate      `json:"pcap,omitempty"`
}

type ZeekConfigUpdate struct {
	Enabled             *bool   `json:"enabled,omitempty"`
	LogDir              *string `json:"log_dir,omitempty"`
	PollIntervalSeconds *int    `json:"poll_interval_seconds,omitempty"`
	NetworkInterface    *string `json:"network_interface,omitempty"`
}

type CorelightConfigUpdate struct {
	Enabled  *bool   `json:"enabled,omitempty"`
	APIURL   *string `json:"api_url,omitempty"`
	APIToken *string `json:"api_token,omitempty"`
}

type PCAPConfigUpdate struct {
	MaxFileSizeMB  *int `json:"max_file_size_mb,omitempty"`
	RetentionHours *int `json:"retention_hours,omitempty"`
}

// UpdateSources updates the sources configuration with validation.
func (h *ConfigHandler) UpdateSources(w http.ResponseWriter, r *http.Request) {
	var req SourcesConfigUpdate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Zeek
	if req.Zeek != nil {
		if req.Zeek.Enabled != nil {
			h.cfg.Sources.ZeekFile.Enabled = *req.Zeek.Enabled
		}
		if req.Zeek.LogDir != nil {
			dir := strings.TrimSpace(*req.Zeek.LogDir)
			if dir == "" {
				writeError(w, http.StatusBadRequest, "log_dir cannot be empty")
				return
			}
			h.cfg.Sources.ZeekFile.LogDir = dir
		}
		if req.Zeek.PollIntervalSeconds != nil {
			interval := *req.Zeek.PollIntervalSeconds
			if interval < 5 || interval > 300 {
				writeError(w, http.StatusBadRequest, "poll_interval_seconds must be between 5 and 300")
				return
			}
			h.cfg.Sources.ZeekFile.PollIntervalSeconds = interval
		}
		if req.Zeek.NetworkInterface != nil {
			h.cfg.Sources.ZeekFile.NetworkInterface = strings.TrimSpace(*req.Zeek.NetworkInterface)
		}
	}

	// Corelight
	if req.Corelight != nil {
		if req.Corelight.Enabled != nil {
			h.cfg.Sources.Corelight.Enabled = *req.Corelight.Enabled
		}
		if req.Corelight.APIURL != nil {
			h.cfg.Sources.Corelight.APIURL = strings.TrimSpace(*req.Corelight.APIURL)
		}
		if req.Corelight.APIToken != nil {
			h.cfg.Sources.Corelight.APIToken = strings.TrimSpace(*req.Corelight.APIToken)
		}
	}

	// PCAP
	if req.PCAP != nil {
		if req.PCAP.MaxFileSizeMB != nil {
			size := *req.PCAP.MaxFileSizeMB
			if size < 1 || size > 5000 {
				writeError(w, http.StatusBadRequest, "max_file_size_mb must be between 1 and 5000")
				return
			}
			h.cfg.PCAP.MaxFileSizeMB = size
		}
		if req.PCAP.RetentionHours != nil {
			hours := *req.PCAP.RetentionHours
			if hours < 1 || hours > 720 {
				writeError(w, http.StatusBadRequest, "retention_hours must be between 1 and 720")
				return
			}
			h.cfg.PCAP.RetentionHours = hours
		}
	}

	if err := config.Save(h.cfgPath, h.cfg); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("saving config: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated", "note": "restart required for changes to take effect"})
}

// InterfaceInfo describes a network interface.
type InterfaceInfo struct {
	Name       string `json:"name"`
	IP         string `json:"ip"`
	IsUp       bool   `json:"is_up"`
	IsLoopback bool   `json:"is_loopback"`
	MAC        string `json:"mac"`
}

// ListInterfaces returns available network interfaces on the host.
func (h *ConfigHandler) ListInterfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, err := net.Interfaces()
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("listing interfaces: %v", err))
		return
	}

	var result []InterfaceInfo
	for _, iface := range ifaces {
		info := InterfaceInfo{
			Name:       iface.Name,
			IsUp:       iface.Flags&net.FlagUp != 0,
			IsLoopback: iface.Flags&net.FlagLoopback != 0,
			MAC:        iface.HardwareAddr.String(),
		}

		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
					info.IP = ipnet.IP.String()
					break
				}
			}
		}

		// Only include interfaces with an IP
		if info.IP != "" {
			result = append(result, info)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"interfaces":        result,
		"current_interface": h.cfg.Sources.ZeekFile.NetworkInterface,
	})
}
