package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cyberflag-ai/cipherflag/internal/config"
	"github.com/cyberflag-ai/cipherflag/internal/export/venafi"
	"github.com/cyberflag-ai/cipherflag/internal/store"
)

type VenafiHandler struct {
	store        store.CertStore
	cfg          *config.Config
	cfgPath      string
	mu           sync.RWMutex
	enabled      bool
	pushInterval time.Duration
}

func NewVenafiHandler(s store.CertStore, cfg *config.Config, cfgPath string) *VenafiHandler {
	return &VenafiHandler{
		store:        s,
		cfg:          cfg,
		cfgPath:      cfgPath,
		enabled:      cfg.Export.Venafi.Enabled,
		pushInterval: time.Duration(cfg.Export.Venafi.PushIntervalMinutes) * time.Minute,
	}
}

func (h *VenafiHandler) Status(w http.ResponseWriter, r *http.Request) {
	stats, err := h.store.GetVenafiPushStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.mu.RLock()
	stats.Enabled = h.enabled
	interval := h.pushInterval
	h.mu.RUnlock()

	if stats.LastPushAt != nil && stats.Enabled {
		next := stats.LastPushAt.Add(interval)
		stats.NextPushAt = &next
	}

	writeJSON(w, http.StatusOK, stats)
}

// VenafiConfigResponse is the config returned to the frontend (credentials masked).
type VenafiConfigResponse struct {
	Enabled             bool   `json:"enabled"`
	Platform            string `json:"platform"`
	Region              string `json:"region"`
	HasAPIKey           bool   `json:"has_api_key"`
	BaseURL             string `json:"base_url"`
	ClientID            string `json:"client_id"`
	HasRefreshToken     bool   `json:"has_refresh_token"`
	Folder              string `json:"folder"`
	PushIntervalMinutes int    `json:"push_interval_minutes"`
}

// GetConfig returns the Venafi configuration with credentials masked.
func (h *VenafiHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	v := h.cfg.Export.Venafi
	h.mu.RUnlock()

	writeJSON(w, http.StatusOK, VenafiConfigResponse{
		Enabled:             v.Enabled,
		Platform:            v.Platform,
		Region:              v.Region,
		HasAPIKey:           v.APIKey != "",
		BaseURL:             v.BaseURL,
		ClientID:            v.ClientID,
		HasRefreshToken:     v.RefreshToken != "",
		Folder:              v.Folder,
		PushIntervalMinutes: v.PushIntervalMinutes,
	})
}

// VenafiConfigUpdate is the request body for updating Venafi config.
type VenafiConfigUpdate struct {
	Enabled             *bool   `json:"enabled,omitempty"`
	Platform            *string `json:"platform,omitempty"`
	Region              *string `json:"region,omitempty"`
	APIKey              *string `json:"api_key,omitempty"`
	BaseURL             *string `json:"base_url,omitempty"`
	ClientID            *string `json:"client_id,omitempty"`
	RefreshToken        *string `json:"refresh_token,omitempty"`
	Folder              *string `json:"folder,omitempty"`
	PushIntervalMinutes *int    `json:"push_interval_minutes,omitempty"`
}

// UpdateConfig updates the Venafi configuration with validation.
func (h *VenafiHandler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	var req VenafiConfigUpdate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	v := &h.cfg.Export.Venafi

	// Validate and apply each field
	if req.Platform != nil {
		p := strings.ToLower(*req.Platform)
		if p != "cloud" && p != "tpp" {
			writeError(w, http.StatusBadRequest, "platform must be 'cloud' or 'tpp'")
			return
		}
		v.Platform = p
	}

	if req.Region != nil {
		r := strings.ToLower(*req.Region)
		if r != "us" && r != "eu" {
			writeError(w, http.StatusBadRequest, "region must be 'us' or 'eu'")
			return
		}
		v.Region = r
	}

	if req.BaseURL != nil {
		u := strings.TrimSpace(*req.BaseURL)
		if u != "" {
			parsed, err := url.Parse(u)
			if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") {
				writeError(w, http.StatusBadRequest, "base_url must be a valid HTTP/HTTPS URL")
				return
			}
			if parsed.Scheme == "http" && !strings.Contains(parsed.Host, "localhost") && !strings.Contains(parsed.Host, "127.0.0.1") {
				writeError(w, http.StatusBadRequest, "base_url must use HTTPS for non-localhost connections")
				return
			}
		}
		v.BaseURL = u
	}

	if req.PushIntervalMinutes != nil {
		interval := *req.PushIntervalMinutes
		if interval < 5 || interval > 1440 {
			writeError(w, http.StatusBadRequest, "push_interval_minutes must be between 5 and 1440")
			return
		}
		v.PushIntervalMinutes = interval
		h.pushInterval = time.Duration(interval) * time.Minute
	}

	if req.APIKey != nil {
		v.APIKey = strings.TrimSpace(*req.APIKey)
	}
	if req.ClientID != nil {
		v.ClientID = strings.TrimSpace(*req.ClientID)
	}
	if req.RefreshToken != nil {
		v.RefreshToken = strings.TrimSpace(*req.RefreshToken)
	}
	if req.Folder != nil {
		v.Folder = strings.TrimSpace(*req.Folder)
	}
	if req.Enabled != nil {
		v.Enabled = *req.Enabled
		h.enabled = v.Enabled
	}

	// Save to TOML file
	if err := config.Save(h.cfgPath, h.cfg); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("saving config: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated", "note": "restart required for push scheduler changes"})
}

// TestConnection validates the current Venafi credentials.
func (h *VenafiHandler) TestConnection(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	v := h.cfg.Export.Venafi
	h.mu.RUnlock()

	var client venafi.VenafiClient

	if v.Platform == "cloud" {
		if v.APIKey == "" {
			writeError(w, http.StatusBadRequest, "API key is not configured")
			return
		}
		client = venafi.NewCloudClient(v.Region, v.APIKey)
	} else {
		if v.BaseURL == "" || v.ClientID == "" || v.RefreshToken == "" {
			writeError(w, http.StatusBadRequest, "TPP credentials are not fully configured")
			return
		}
		authBase := v.BaseURL + "/vedauth"
		sdkBase := v.BaseURL + "/vedsdk"
		tppClient := venafi.NewClient(sdkBase, authBase, v.ClientID, v.RefreshToken)
		client = venafi.NewTPPAdapter(tppClient, v.Folder)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	if err := client.ValidateConnection(ctx); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"connected": false,
			"error":     err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"connected": true,
		"platform":  v.Platform,
	})
}
