package venafi

import (
	"sync"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/config"
)

func TestLiveConfig_SnapshotReturnsInitialValue(t *testing.T) {
	v := config.VenafiExportConfig{
		Enabled:             true,
		Platform:            "cloud",
		APIKey:              "key-abc",
		PushIntervalMinutes: 15,
	}
	lc := NewLiveConfig(v)

	got := lc.Snapshot()
	if got.Enabled != true {
		t.Errorf("Enabled = %v, want true", got.Enabled)
	}
	if got.Platform != "cloud" {
		t.Errorf("Platform = %q, want cloud", got.Platform)
	}
	if got.APIKey != "key-abc" {
		t.Errorf("APIKey = %q, want key-abc", got.APIKey)
	}
	if got.PushIntervalMinutes != 15 {
		t.Errorf("PushIntervalMinutes = %d, want 15", got.PushIntervalMinutes)
	}
}

func TestLiveConfig_SetThenSnapshotReturnsNewValue(t *testing.T) {
	initial := config.VenafiExportConfig{Enabled: false, Platform: "cloud", PushIntervalMinutes: 5}
	lc := NewLiveConfig(initial)

	updated := config.VenafiExportConfig{
		Enabled:             true,
		Platform:            "tpp",
		BaseURL:             "https://tpp.example.com",
		ClientID:            "my-client",
		RefreshToken:        "tok",
		PushIntervalMinutes: 30,
	}
	lc.Set(updated)

	got := lc.Snapshot()
	if got.Enabled != true {
		t.Errorf("Enabled = %v, want true", got.Enabled)
	}
	if got.Platform != "tpp" {
		t.Errorf("Platform = %q, want tpp", got.Platform)
	}
	if got.PushIntervalMinutes != 30 {
		t.Errorf("PushIntervalMinutes = %d, want 30", got.PushIntervalMinutes)
	}
}

func TestLiveConfig_SetOverwritesPreviousValue(t *testing.T) {
	lc := NewLiveConfig(config.VenafiExportConfig{Enabled: true, PushIntervalMinutes: 10})
	lc.Set(config.VenafiExportConfig{Enabled: false, PushIntervalMinutes: 20})
	lc.Set(config.VenafiExportConfig{Enabled: true, PushIntervalMinutes: 60})

	got := lc.Snapshot()
	if got.Enabled != true {
		t.Errorf("Enabled = %v, want true", got.Enabled)
	}
	if got.PushIntervalMinutes != 60 {
		t.Errorf("PushIntervalMinutes = %d, want 60", got.PushIntervalMinutes)
	}
}

// TestLiveConfig_ConcurrentSafe exercises concurrent reads and writes.
// Run with -race to catch data races.
func TestLiveConfig_ConcurrentSafe(t *testing.T) {
	lc := NewLiveConfig(config.VenafiExportConfig{Enabled: false, PushIntervalMinutes: 5})

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			lc.Set(config.VenafiExportConfig{Enabled: i%2 == 0, PushIntervalMinutes: i + 1})
		}(i)
		go func() {
			defer wg.Done()
			_ = lc.Snapshot()
		}()
	}

	wg.Wait()
	// Just need to complete without data race; value doesn't matter.
}
