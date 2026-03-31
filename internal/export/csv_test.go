package export

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

func sampleCert() *model.Certificate {
	return &model.Certificate{
		ID:                "test-id-1",
		FingerprintSHA256: "AABBCCDD",
		Subject: model.DistinguishedName{
			CommonName:   "example.com",
			Organization: "Example Inc",
			Full:         "CN=example.com,O=Example Inc",
		},
		Issuer: model.DistinguishedName{
			CommonName:   "Issuer CA",
			Organization: "Issuer Org",
			Full:         "CN=Issuer CA,O=Issuer Org",
		},
		SerialNumber:       "123456",
		NotBefore:          time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyAlgorithm:       model.KeyRSA,
		KeySizeBits:        2048,
		SignatureAlgorithm: model.SigSHA256WithRSA,
		SubjectAltNames:    []string{"example.com", "www.example.com"},
		IsCA:               false,
		SourceDiscovery:    model.SourceActiveScan,
		FirstSeen:          time.Date(2025, 3, 1, 12, 0, 0, 0, time.UTC),
		LastSeen:           time.Date(2025, 3, 15, 12, 0, 0, 0, time.UTC),
	}
}

func TestWriteCSV_Header(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCSV(&buf, nil); err != nil {
		t.Fatalf("WriteCSV returned error: %v", err)
	}

	r := csv.NewReader(strings.NewReader(buf.String()))
	header, err := r.Read()
	if err != nil {
		t.Fatalf("reading header: %v", err)
	}

	if len(header) != len(csvHeaders) {
		t.Fatalf("expected %d header columns, got %d", len(csvHeaders), len(header))
	}
	for i, h := range csvHeaders {
		if header[i] != h {
			t.Errorf("header[%d] = %q, want %q", i, header[i], h)
		}
	}
}

func TestWriteCSV_Row(t *testing.T) {
	var buf bytes.Buffer
	cert := sampleCert()

	if err := WriteCSV(&buf, []*model.Certificate{cert}); err != nil {
		t.Fatalf("WriteCSV returned error: %v", err)
	}

	r := csv.NewReader(strings.NewReader(buf.String()))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("reading CSV: %v", err)
	}

	if len(records) != 2 {
		t.Fatalf("expected 2 records (header + 1 row), got %d", len(records))
	}

	row := records[1]

	tests := []struct {
		col  int
		name string
		want string
	}{
		{0, "Fingerprint SHA256", "AABBCCDD"},
		{1, "Subject CN", "example.com"},
		{2, "Subject Organization", "Example Inc"},
		{3, "Subject Full DN", "CN=example.com,O=Example Inc"},
		{4, "Issuer CN", "Issuer CA"},
		{5, "Issuer Organization", "Issuer Org"},
		{6, "Issuer Full DN", "CN=Issuer CA,O=Issuer Org"},
		{7, "Serial Number", "123456"},
		{8, "Not Before", "2025-01-01T00:00:00Z"},
		{9, "Not After", "2026-01-01T00:00:00Z"},
		{10, "Key Algorithm", "RSA"},
		{11, "Key Size Bits", "2048"},
		{12, "Signature Algorithm", "SHA256WithRSA"},
		{13, "Subject Alt Names", "example.com; www.example.com"},
		{14, "Is CA", "false"},
		{15, "Discovery Source", "active_scan"},
		{16, "First Seen", "2025-03-01T12:00:00Z"},
		{17, "Last Seen", "2025-03-15T12:00:00Z"},
	}

	for _, tt := range tests {
		if row[tt.col] != tt.want {
			t.Errorf("%s: got %q, want %q", tt.name, row[tt.col], tt.want)
		}
	}
}

func TestWriteCSV_IsCA_True(t *testing.T) {
	var buf bytes.Buffer
	cert := sampleCert()
	cert.IsCA = true

	if err := WriteCSV(&buf, []*model.Certificate{cert}); err != nil {
		t.Fatalf("WriteCSV returned error: %v", err)
	}

	r := csv.NewReader(strings.NewReader(buf.String()))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("reading CSV: %v", err)
	}

	row := records[1]
	if row[14] != "true" {
		t.Errorf("Is CA: got %q, want %q", row[14], "true")
	}
}

func TestWriteCSV_EmptyCerts(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCSV(&buf, []*model.Certificate{}); err != nil {
		t.Fatalf("WriteCSV returned error: %v", err)
	}

	r := csv.NewReader(strings.NewReader(buf.String()))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("reading CSV: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("expected 1 record (header only), got %d", len(records))
	}
}
