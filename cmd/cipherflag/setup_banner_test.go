package main

import (
	"strings"
	"testing"
)

// The setup banner must only name files and commands that exist.
func TestSetupBanner(t *testing.T) {
	got := setupBanner()

	for _, want := range []string{
		"Edit config/cipherflag.toml",
		"docker compose up -d",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("banner missing %q:\n%s", want, got)
		}
	}
	for _, stale := range []string{
		"cipherflag.toml.example",
		"docker-compose up",
		"v2.0",
	} {
		if strings.Contains(got, stale) {
			t.Errorf("banner still contains stale text %q:\n%s", stale, got)
		}
	}
}
