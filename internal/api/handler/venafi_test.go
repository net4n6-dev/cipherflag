package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/venafi"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// --- minimal fake store for Venafi tests ----------------------------------

type fakeVenafiHandlerStore struct {
	store.CertStore
}

func (f *fakeVenafiHandlerStore) GetVenafiPushStats(_ context.Context) (*model.VenafiPushStats, error) {
	return &model.VenafiPushStats{}, nil
}

// --- helpers --------------------------------------------------------------

// tempCfgPath writes a minimal TOML config to a temp file and returns the path.
func tempCfgPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[server]
[storage]
[export]
  [export.venafi]
    enabled = false
    platform = "cloud"
    push_interval_minutes = 5
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}
	return path
}

func makeCfg(enabled bool) *config.Config {
	return &config.Config{
		Export: config.ExportConfig{
			Venafi: config.VenafiExportConfig{
				Enabled:             enabled,
				Platform:            "cloud",
				APIKey:              "test-key",
				PushIntervalMinutes: 5,
			},
		},
	}
}

// --- tests ----------------------------------------------------------------

// TestVenafiHandler_UpdateConfig_UpdatesLiveConfig verifies that a successful
// PUT /venafi/config propagates the new enabled state into the LiveConfig.
func TestVenafiHandler_UpdateConfig_UpdatesLiveConfig(t *testing.T) {
	cfgPath := tempCfgPath(t)
	cfg := makeCfg(false)
	live := venafi.NewLiveConfig(cfg.Export.Venafi)
	st := &fakeVenafiHandlerStore{}

	h := NewVenafiHandler(st, cfg, cfgPath, live)

	enabled := true
	reqBody, _ := json.Marshal(VenafiConfigUpdate{Enabled: &enabled})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/venafi/config", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.UpdateConfig(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	// The live config must reflect the new enabled state.
	if snap := live.Snapshot(); !snap.Enabled {
		t.Errorf("live.Snapshot().Enabled = false, want true after UpdateConfig")
	}
}

// TestVenafiHandler_UpdateConfig_ResponseSaysApplied checks the success
// response no longer contains "restart required".
func TestVenafiHandler_UpdateConfig_ResponseSaysApplied(t *testing.T) {
	cfgPath := tempCfgPath(t)
	cfg := makeCfg(false)
	live := venafi.NewLiveConfig(cfg.Export.Venafi)
	st := &fakeVenafiHandlerStore{}

	h := NewVenafiHandler(st, cfg, cfgPath, live)

	enabled := true
	reqBody, _ := json.Marshal(VenafiConfigUpdate{Enabled: &enabled})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/venafi/config", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.UpdateConfig(rr, req)

	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	if note, ok := resp["note"]; ok && note == "restart required for push scheduler changes" {
		t.Error("response still says 'restart required for push scheduler changes', should say 'applied'")
	}
	if resp["status"] != "updated" {
		t.Errorf("status = %q, want 'updated'", resp["status"])
	}
}

// TestVenafiHandler_UpdateConfig_IntervalUpdatesLiveConfig ensures that
// a push_interval_minutes change is reflected in live config.
func TestVenafiHandler_UpdateConfig_IntervalUpdatesLiveConfig(t *testing.T) {
	cfgPath := tempCfgPath(t)
	cfg := makeCfg(true)
	cfg.Export.Venafi.PushIntervalMinutes = 5
	live := venafi.NewLiveConfig(cfg.Export.Venafi)
	st := &fakeVenafiHandlerStore{}

	h := NewVenafiHandler(st, cfg, cfgPath, live)

	newInterval := 30
	reqBody, _ := json.Marshal(VenafiConfigUpdate{PushIntervalMinutes: &newInterval})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/venafi/config", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.UpdateConfig(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	snap := live.Snapshot()
	if snap.PushIntervalMinutes != 30 {
		t.Errorf("live PushIntervalMinutes = %d, want 30", snap.PushIntervalMinutes)
	}
	if snap.PushIntervalMinutes != int(30*time.Minute/time.Minute) {
		t.Errorf("unexpected interval value")
	}
}

// Saving the Venafi config appends its own table to a file that lacks it and
// leaves the rest of the file alone.
func TestVenafiHandler_UpdateConfig_OnlyRewritesItsOwnTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cipherflag.toml")
	original := "# hand edited\n[storage]\npostgres_url = \"x\"\n\n[analysis]\n# tuned\nrecheck_interval_hours = 12\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	h := NewVenafiHandler(&fakeVenafiHandlerStore{}, cfg, path, venafi.NewLiveConfig(cfg.Export.Venafi))

	enabled := true
	body, _ := json.Marshal(VenafiConfigUpdate{Enabled: &enabled})
	rr := httptest.NewRecorder()
	h.UpdateConfig(rr, httptest.NewRequest(http.MethodPut, "/api/v1/venafi/config", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	got, _ := os.ReadFile(path)
	text := string(got)
	if !strings.HasPrefix(text, original) {
		t.Errorf("the hand-edited file was not preserved:\n%s", text)
	}
	if !strings.Contains(text, "[export.venafi]") {
		t.Errorf("the [export.venafi] table was not appended:\n%s", text)
	}
	if strings.Contains(text, "rank_formula") {
		t.Errorf("unrelated default keys were written:\n%s", text)
	}
}

func TestVenafiHandler_UpdateConfig_ReadOnlyConfigReturnsAHelpfulError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("file permissions do not stop root")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "cipherflag.toml")
	if err := os.WriteFile(path, []byte("[storage]\npostgres_url = \"x\"\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	h := NewVenafiHandler(&fakeVenafiHandlerStore{}, cfg, path, venafi.NewLiveConfig(cfg.Export.Venafi))

	enabled := true
	body, _ := json.Marshal(VenafiConfigUpdate{Enabled: &enabled})
	rr := httptest.NewRecorder()
	h.UpdateConfig(rr, httptest.NewRequest(http.MethodPut, "/api/v1/venafi/config", bytes.NewReader(body)))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "read-write") {
		t.Errorf("error does not say what to do: %s", rr.Body.String())
	}
	after, _ := os.ReadFile(path)
	if string(after) != "[storage]\npostgres_url = \"x\"\n" {
		t.Errorf("the config file changed after a failed save: %q", after)
	}
}
