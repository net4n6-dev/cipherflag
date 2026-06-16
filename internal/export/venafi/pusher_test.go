package venafi

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// --- fake store -----------------------------------------------------------

// fakeVenafiStore records calls to Venafi-related store methods.
// All other CertStore methods panic if called (embedded nil interface).
type fakeVenafiStore struct {
	store.CertStore // nil embed — panics on any unimplemented method

	getCertsCallCount  int32
	getCertsResult     []model.Certificate
	getCertsErr        error

	markSuccessCalled int32
}

func (f *fakeVenafiStore) GetCertsForVenafiPush(_ context.Context, _ time.Duration, _ int) ([]model.Certificate, error) {
	atomic.AddInt32(&f.getCertsCallCount, 1)
	return f.getCertsResult, f.getCertsErr
}

func (f *fakeVenafiStore) GetLatestObservationsForCerts(_ context.Context, _ []string) (map[string]*model.CertificateObservation, error) {
	return map[string]*model.CertificateObservation{}, nil
}

func (f *fakeVenafiStore) MarkVenafiPushSuccess(_ context.Context, _ []string) error {
	atomic.AddInt32(&f.markSuccessCalled, 1)
	return nil
}

func (f *fakeVenafiStore) MarkVenafiPushFailure(_ context.Context, _ []string) error {
	return nil
}

// --- fake client ----------------------------------------------------------

type fakeVenafiClient struct {
	importCallCount int32
	importResult    *ImportResult
	importErr       error
}

func (f *fakeVenafiClient) ImportCertificates(_ context.Context, _ []CertImport) (*ImportResult, error) {
	atomic.AddInt32(&f.importCallCount, 1)
	if f.importResult == nil {
		return &ImportResult{Imported: 1}, f.importErr
	}
	return f.importResult, f.importErr
}

func (f *fakeVenafiClient) ValidateConnection(_ context.Context) error { return nil }

// --- Pusher gating tests --------------------------------------------------

// TestPusher_DisabledSkipsPush verifies that runCycleFromLive does nothing when
// the live config has Enabled=false.
func TestPusher_DisabledSkipsPush(t *testing.T) {
	st := &fakeVenafiStore{}
	lc := NewLiveConfig(config.VenafiExportConfig{
		Enabled:             false,
		Platform:            "cloud",
		APIKey:              "k",
		PushIntervalMinutes: 5,
	})

	p := NewPusher(lc, st)
	// Run one cycle directly (don't start the full ticker loop).
	p.runCycleFromLive(context.Background())

	calls := atomic.LoadInt32(&st.getCertsCallCount)
	if calls != 0 {
		t.Errorf("GetCertsForVenafiPush called %d times with Enabled=false, want 0", calls)
	}
}

// TestPusher_EnabledRunsCycle verifies that runCycle queries the store and
// calls the client when Enabled=true and credentials are present.
func TestPusher_EnabledRunsCycle(t *testing.T) {
	cert := model.Certificate{FingerprintSHA256: "aa:bb:cc", RawPEM: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"}
	st := &fakeVenafiStore{
		getCertsResult: []model.Certificate{cert},
	}
	lc := NewLiveConfig(config.VenafiExportConfig{
		Enabled:             true,
		Platform:            "cloud",
		APIKey:              "valid-key",
		PushIntervalMinutes: 5,
	})

	// We can't easily inject the fake client through BuildClient (which would
	// create a real CloudClient), so we exercise runCycle directly with a
	// known client.
	p := NewPusher(lc, st)
	fakeClient := &fakeVenafiClient{}
	interval := 5 * time.Minute
	p.runCycle(context.Background(), fakeClient, interval)

	calls := atomic.LoadInt32(&st.getCertsCallCount)
	if calls == 0 {
		t.Errorf("GetCertsForVenafiPush not called, want >= 1")
	}
	importCalls := atomic.LoadInt32(&fakeClient.importCallCount)
	if importCalls == 0 {
		t.Errorf("ImportCertificates not called, want >= 1")
	}
}

// TestPusher_DisabledThenEnabledViaLiveConfig exercises the gating behaviour
// by checking runCycleFromLive before and after a Set.
func TestPusher_DisabledThenEnabledViaLiveConfig(t *testing.T) {
	cert := model.Certificate{FingerprintSHA256: "aa:bb:cc", RawPEM: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"}
	st := &fakeVenafiStore{
		getCertsResult: []model.Certificate{cert},
	}
	lc := NewLiveConfig(config.VenafiExportConfig{
		Enabled:             false,
		Platform:            "cloud",
		APIKey:              "valid-key",
		PushIntervalMinutes: 5,
	})

	fakeClient := &fakeVenafiClient{}
	p := NewPusher(lc, st)
	// Inject a fake client factory so no real HTTPS call is ever made to
	// api.venafi.cloud. BuildClient is never reached when buildClient is set.
	p.buildClient = func(_ config.VenafiExportConfig) (VenafiClient, error) {
		return fakeClient, nil
	}

	// Disabled: no push.
	p.runCycleFromLive(context.Background())
	if c := atomic.LoadInt32(&st.getCertsCallCount); c != 0 {
		t.Errorf("getCertsCallCount = %d before enable, want 0", c)
	}

	// Enable via live config.
	lc.Set(config.VenafiExportConfig{
		Enabled:             true,
		Platform:            "cloud",
		APIKey:              "valid-key",
		PushIntervalMinutes: 5,
	})

	// Enabled: store should be queried and the fake client should receive the push.
	p.runCycleFromLive(context.Background())
	if c := atomic.LoadInt32(&st.getCertsCallCount); c == 0 {
		t.Errorf("getCertsCallCount = 0 after enable, want >= 1")
	}
	if ic := atomic.LoadInt32(&fakeClient.importCallCount); ic == 0 {
		t.Errorf("ImportCertificates not called on fake client after enable, want >= 1")
	}
}

// --- BuildClient tests ----------------------------------------------------

func TestBuildClient_CloudMissingAPIKey(t *testing.T) {
	v := config.VenafiExportConfig{
		Platform: "cloud",
		APIKey:   "",
	}
	client, err := BuildClient(v)
	if err == nil {
		t.Error("expected error for cloud with empty APIKey, got nil")
	}
	if client != nil {
		t.Error("expected nil client on error")
	}
}

func TestBuildClient_TPPMissingBaseURL(t *testing.T) {
	v := config.VenafiExportConfig{
		Platform:     "tpp",
		BaseURL:      "",
		ClientID:     "cid",
		RefreshToken: "tok",
	}
	client, err := BuildClient(v)
	if err == nil {
		t.Error("expected error for tpp with missing BaseURL, got nil")
	}
	if client != nil {
		t.Error("expected nil client on error")
	}
}

func TestBuildClient_TPPMissingClientID(t *testing.T) {
	v := config.VenafiExportConfig{
		Platform:     "tpp",
		BaseURL:      "https://tpp.example.com",
		ClientID:     "",
		RefreshToken: "tok",
	}
	client, err := BuildClient(v)
	if err == nil {
		t.Error("expected error for tpp with missing ClientID, got nil")
	}
	if client != nil {
		t.Error("expected nil client on error")
	}
}

func TestBuildClient_TPPMissingRefreshToken(t *testing.T) {
	v := config.VenafiExportConfig{
		Platform:     "tpp",
		BaseURL:      "https://tpp.example.com",
		ClientID:     "cid",
		RefreshToken: "",
	}
	client, err := BuildClient(v)
	if err == nil {
		t.Error("expected error for tpp with missing RefreshToken, got nil")
	}
	if client != nil {
		t.Error("expected nil client on error")
	}
}

func TestBuildClient_CloudValidConfig(t *testing.T) {
	v := config.VenafiExportConfig{
		Platform: "cloud",
		APIKey:   "my-api-key",
		Region:   "us",
	}
	client, err := BuildClient(v)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if client == nil {
		t.Error("expected non-nil client")
	}
}

func TestBuildClient_TPPValidConfig(t *testing.T) {
	v := config.VenafiExportConfig{
		Platform:     "tpp",
		BaseURL:      "https://tpp.example.com",
		ClientID:     "cid",
		RefreshToken: "tok",
		Folder:       "\\VED\\Policy",
	}
	client, err := BuildClient(v)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if client == nil {
		t.Error("expected non-nil client")
	}
}
