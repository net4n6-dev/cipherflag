package export

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/cyberflag-ai/cipherflag/internal/model"
)

func TestWriteJSON_Structure(t *testing.T) {
	var buf bytes.Buffer
	cert := sampleCert()

	if err := WriteJSON(&buf, []*model.Certificate{cert}); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	var payload ExportPayload
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshalling JSON: %v", err)
	}

	if payload.Count != 1 {
		t.Errorf("Count = %d, want 1", payload.Count)
	}

	if payload.ExportedAt.IsZero() {
		t.Error("ExportedAt should not be zero")
	}

	if len(payload.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(payload.Certificates))
	}

	c := payload.Certificates[0]
	if c.FingerprintSHA256 != "AABBCCDD" {
		t.Errorf("FingerprintSHA256 = %q, want %q", c.FingerprintSHA256, "AABBCCDD")
	}
	if c.Subject.CommonName != "example.com" {
		t.Errorf("Subject CN = %q, want %q", c.Subject.CommonName, "example.com")
	}
}

func TestWriteJSON_Indented(t *testing.T) {
	var buf bytes.Buffer
	cert := sampleCert()

	if err := WriteJSON(&buf, []*model.Certificate{cert}); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	output := buf.String()
	// Indented JSON should contain newlines and leading spaces
	if !bytes.Contains(buf.Bytes(), []byte("\n  ")) {
		t.Error("expected indented JSON output")
	}

	// Should be valid JSON
	if !json.Valid([]byte(output)) {
		t.Error("output is not valid JSON")
	}
}

func TestWriteJSON_EmptyCerts(t *testing.T) {
	var buf bytes.Buffer

	if err := WriteJSON(&buf, []*model.Certificate{}); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	var payload ExportPayload
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshalling JSON: %v", err)
	}

	if payload.Count != 0 {
		t.Errorf("Count = %d, want 0", payload.Count)
	}
	if len(payload.Certificates) != 0 {
		t.Errorf("expected 0 certificates, got %d", len(payload.Certificates))
	}
}

func TestWriteJSON_ExportedAtIsRecent(t *testing.T) {
	var buf bytes.Buffer
	before := time.Now().UTC().Add(-time.Second)

	if err := WriteJSON(&buf, []*model.Certificate{}); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	var payload ExportPayload
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshalling JSON: %v", err)
	}

	if payload.ExportedAt.Before(before) {
		t.Errorf("ExportedAt %v is before test start %v", payload.ExportedAt, before)
	}
}
