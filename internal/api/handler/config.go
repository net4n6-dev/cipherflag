package handler

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/net4n6-dev/cipherflag/internal/config"
)

type ConfigHandler struct {
	cfg     *config.Config
	cfgPath string
}

func NewConfigHandler(cfg *config.Config, cfgPath string) *ConfigHandler {
	return &ConfigHandler{cfg: cfg, cfgPath: cfgPath}
}

// SourcesConfigResponse is the response for GET /config/sources.
type SourcesConfigResponse struct {
	Zeek      ZeekConfigResponse      `json:"zeek"`
	Corelight CorelightConfigResponse `json:"corelight"`
	PCAP      PCAPConfigResponse      `json:"pcap"`
}

type ZeekConfigResponse struct {
	Enabled             bool   `json:"enabled"`
	LogDir              string `json:"log_dir"`
	PollIntervalSeconds int    `json:"poll_interval_seconds"`
	NetworkInterface    string `json:"network_interface"`
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

// GetSources returns the sources configuration.
func (h *ConfigHandler) GetSources(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, SourcesConfigResponse{
		Zeek: ZeekConfigResponse{
			Enabled:             h.cfg.Sources.ZeekFile.Enabled,
			LogDir:              h.cfg.Sources.ZeekFile.LogDir,
			PollIntervalSeconds: h.cfg.Sources.ZeekFile.PollIntervalSeconds,
			NetworkInterface:    h.cfg.Sources.ZeekFile.NetworkInterface,
		},
		Corelight: CorelightConfigResponse{
			Enabled:  h.cfg.Sources.Corelight.Enabled,
			APIURL:   h.cfg.Sources.Corelight.APIURL,
			HasToken: h.cfg.Sources.Corelight.APIToken != "",
		},
		PCAP: PCAPConfigResponse{
			MaxFileSizeMB:  h.cfg.PCAP.MaxFileSizeMB,
			RetentionHours: h.cfg.PCAP.RetentionHours,
			InputDir:       h.cfg.PCAP.InputDir,
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
