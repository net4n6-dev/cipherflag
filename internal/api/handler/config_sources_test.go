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
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/net4n6-dev/cipherflag/internal/config"
)

// The Settings → Sources page reads GET /config/sources. The v2.0.0 port
// replaced the response's zeek object with a generic sources list and the
// page was never updated: it read undefined, silently kept its hard-coded
// defaults, and a Save wrote those defaults over the real Zeek config.
//
// This is one half of a contract test. The response is compared to a
// fixture the frontend's own parser test consumes
// (frontend/src/lib/settings/sources-config.test.ts), so a change of shape
// on either side fails a test instead of the Settings page.
const sourcesFixture = "../../../frontend/src/lib/testdata/sources-config.json"

func sourcesFixtureConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Sources.ZeekFile.Enabled = false
	cfg.Sources.ZeekFile.LogDir = "/data/zeek/current"
	cfg.Sources.ZeekFile.PollIntervalSeconds = 45
	cfg.Sources.ZeekFile.NetworkInterface = "eth1"
	cfg.Sources.Corelight.Enabled = true
	cfg.Sources.Corelight.APIURL = "https://corelight.example.test"
	cfg.Sources.Corelight.APIToken = "not-a-real-token"
	cfg.PCAP.MaxFileSizeMB = 500
	cfg.PCAP.RetentionHours = 24
	cfg.PCAP.InputDir = "/pcap-input"
	return cfg
}

func getSources(t *testing.T, h *ConfigHandler) []byte {
	t.Helper()
	rec := httptest.NewRecorder()
	h.GetSources(rec, httptest.NewRequest(http.MethodGet, "/api/v1/config/sources", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	return rec.Body.Bytes()
}

func TestGetSources_MatchesFrontendContractFixture(t *testing.T) {
	h := NewConfigHandler(sourcesFixtureConfig(), "", nil)
	want, err := os.ReadFile(filepath.FromSlash(sourcesFixture))
	require.NoError(t, err)
	require.JSONEq(t, string(want), string(getSources(t, h)),
		"GET /config/sources changed shape; update %s and check the Settings page still parses it", sourcesFixture)
}

// The secret itself never appears in the response, only has_token.
func TestGetSources_DoesNotExposeCorelightToken(t *testing.T) {
	h := NewConfigHandler(sourcesFixtureConfig(), "", nil)
	require.NotContains(t, string(getSources(t, h)), "not-a-real-token")
}

// What the page reads back after a Save is what it sent.
func TestUpdateSources_RoundTripsZeek(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "cipherflag.toml")
	h := NewConfigHandler(sourcesFixtureConfig(), cfgPath, nil)

	body := `{"zeek":{"enabled":true,"log_dir":"/other/zeek","poll_interval_seconds":60,"network_interface":"eth2"}}`
	rec := httptest.NewRecorder()
	h.UpdateSources(rec, httptest.NewRequest(http.MethodPut, "/api/v1/config/sources", strings.NewReader(body)))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var got struct {
		Zeek map[string]any `json:"zeek"`
	}
	require.NoError(t, json.Unmarshal(getSources(t, h), &got))
	require.Equal(t, map[string]any{
		"enabled": true, "log_dir": "/other/zeek", "poll_interval_seconds": float64(60), "network_interface": "eth2",
	}, got.Zeek)
}

// Saving Settings > Sources must rewrite only the tables the page edits.
func TestUpdateSources_OnlyRewritesItsOwnTables(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cipherflag.toml")
	original := "# hand edited\n[storage]\npostgres_url = \"x\"\n\n[analysis]\n# tuned\nrecheck_interval_hours = 12\n"
	require.NoError(t, os.WriteFile(path, []byte(original), 0o644))
	cfg, err := config.Load(path)
	require.NoError(t, err)
	h := NewConfigHandler(cfg, path, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/config/sources",
		strings.NewReader(`{"corelight":{"api_url":"https://corelight.example.test"}}`))
	h.UpdateSources(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	got, _ := os.ReadFile(path)
	require.True(t, strings.HasPrefix(string(got), original), "the hand-edited file is preserved")
	require.Contains(t, string(got), "[sources.corelight]")
	require.NotContains(t, string(got), "rank_formula")
	require.NotContains(t, string(got), "[sources.zeek_file]", "an unchanged table is not appended")
	require.NotContains(t, string(got), "[pcap]", "an unchanged table is not appended")
}

// A save of one table must not revert hand edits made to the others after
// CipherFlag started.
func TestUpdateSources_ASaveOfOneTableKeepsHandEditsToTheOthers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cipherflag.toml")
	require.NoError(t, os.WriteFile(path, []byte("[pcap]\nmax_file_size_mb = 500\n"), 0o644))
	cfg, err := config.Load(path)
	require.NoError(t, err)
	h := NewConfigHandler(cfg, path, nil)
	// The operator edits the file while CipherFlag runs.
	require.NoError(t, os.WriteFile(path, []byte("[pcap]\nmax_file_size_mb = 123\n"), 0o644))

	rec := httptest.NewRecorder()
	h.UpdateSources(rec, httptest.NewRequest(http.MethodPut, "/api/v1/config/sources",
		strings.NewReader(`{"corelight":{"api_url":"https://corelight.example.test"}}`)))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	got, _ := os.ReadFile(path)
	require.Contains(t, string(got), "max_file_size_mb = 123", "the hand-edited pcap table is kept")
	require.Contains(t, string(got), `api_url = "https://corelight.example.test"`)
}

// A body that carries no table writes nothing.
func TestUpdateSources_AnEmptyBodyWritesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cipherflag.toml")
	original := "[pcap]\nmax_file_size_mb = 123\n"
	require.NoError(t, os.WriteFile(path, []byte(original), 0o644))
	cfg, err := config.Load(path)
	require.NoError(t, err)
	h := NewConfigHandler(cfg, path, nil)

	rec := httptest.NewRecorder()
	h.UpdateSources(rec, httptest.NewRequest(http.MethodPut, "/api/v1/config/sources", strings.NewReader(`{}`)))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	got, _ := os.ReadFile(path)
	require.Equal(t, original, string(got))
	_, err = os.Stat(path + ".bak")
	require.True(t, os.IsNotExist(err))
}

// A config file that cannot be written gives an actionable 500, not a
// truncated file.
func TestUpdateSources_ReadOnlyConfigReturnsAHelpfulError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("file permissions do not stop root")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "cipherflag.toml")
	original := "[storage]\npostgres_url = \"x\"\n"
	require.NoError(t, os.WriteFile(path, []byte(original), 0o444))
	require.NoError(t, os.Chmod(dir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	cfg, err := config.Load(path)
	require.NoError(t, err)
	h := NewConfigHandler(cfg, path, nil)

	rec := httptest.NewRecorder()
	h.UpdateSources(rec, httptest.NewRequest(http.MethodPut, "/api/v1/config/sources",
		strings.NewReader(`{"corelight":{"api_url":"https://corelight.example.test"}}`)))
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Contains(t, rec.Body.String(), "read-write")
	got, _ := os.ReadFile(path)
	require.Equal(t, original, string(got))
}
