package zeek

import (
	"testing"
	"time"
)

func TestParseX509Record(t *testing.T) {
	input := `{
		"ts": 1700000000.123456,
		"id": "FhJMEj3ISz0FZpRMi4",
		"certificate.version": 3,
		"certificate.serial": "0A0141420000015385736A0B85ECA708",
		"certificate.subject": "CN=example.com,O=Example Inc.,C=US",
		"certificate.issuer": "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US",
		"certificate.not_valid_before": 1690000000.0,
		"certificate.not_valid_after": 1700000000.0,
		"certificate.key_alg": "rsaEncryption",
		"certificate.sig_alg": "sha256WithRSAEncryption",
		"certificate.key_type": "rsa",
		"certificate.key_length": 2048,
		"san.dns": ["example.com", "www.example.com"],
		"san.ip": ["192.168.1.1"],
		"san.email": ["admin@example.com"],
		"basic_constraints.ca": false,
		"fingerprint": "ABC123DEF456"
	}`

	rec, err := ParseX509Record([]byte(input))
	if err != nil {
		t.Fatalf("ParseX509Record failed: %v", err)
	}

	if rec.FileID != "FhJMEj3ISz0FZpRMi4" {
		t.Errorf("FileID = %q, want %q", rec.FileID, "FhJMEj3ISz0FZpRMi4")
	}
	if rec.Fingerprint != "ABC123DEF456" {
		t.Errorf("Fingerprint = %q, want %q", rec.Fingerprint, "ABC123DEF456")
	}
	if rec.SubjectCN != "example.com" {
		t.Errorf("SubjectCN = %q, want %q", rec.SubjectCN, "example.com")
	}
	if rec.SubjectOrg != "Example Inc." {
		t.Errorf("SubjectOrg = %q, want %q", rec.SubjectOrg, "Example Inc.")
	}
	if rec.IssuerCN != "Let's Encrypt Authority X3" {
		t.Errorf("IssuerCN = %q, want %q", rec.IssuerCN, "Let's Encrypt Authority X3")
	}
	if rec.IssuerOrg != "Let's Encrypt" {
		t.Errorf("IssuerOrg = %q, want %q", rec.IssuerOrg, "Let's Encrypt")
	}
	if rec.Serial != "0A0141420000015385736A0B85ECA708" {
		t.Errorf("Serial = %q, want %q", rec.Serial, "0A0141420000015385736A0B85ECA708")
	}
	if rec.Version != 3 {
		t.Errorf("Version = %d, want %d", rec.Version, 3)
	}
	if rec.KeyAlg != "rsaEncryption" {
		t.Errorf("KeyAlg = %q, want %q", rec.KeyAlg, "rsaEncryption")
	}
	if rec.KeyType != "rsa" {
		t.Errorf("KeyType = %q, want %q", rec.KeyType, "rsa")
	}
	if rec.KeyLength != 2048 {
		t.Errorf("KeyLength = %d, want %d", rec.KeyLength, 2048)
	}
	if rec.SigAlg != "sha256WithRSAEncryption" {
		t.Errorf("SigAlg = %q, want %q", rec.SigAlg, "sha256WithRSAEncryption")
	}
	if len(rec.SANsDNS) != 2 || rec.SANsDNS[0] != "example.com" || rec.SANsDNS[1] != "www.example.com" {
		t.Errorf("SANsDNS = %v, want [example.com www.example.com]", rec.SANsDNS)
	}
	if len(rec.SANsIP) != 1 || rec.SANsIP[0] != "192.168.1.1" {
		t.Errorf("SANsIP = %v, want [192.168.1.1]", rec.SANsIP)
	}
	if len(rec.SANsEmail) != 1 || rec.SANsEmail[0] != "admin@example.com" {
		t.Errorf("SANsEmail = %v, want [admin@example.com]", rec.SANsEmail)
	}
	if rec.IsCA {
		t.Error("IsCA = true, want false")
	}

	// Check timestamp conversion (allow 1 microsecond tolerance for float64 precision).
	expectedTS := time.Date(2023, 11, 14, 22, 13, 20, 123456000, time.UTC)
	if diff := rec.Timestamp.Sub(expectedTS).Abs(); diff > time.Microsecond {
		t.Errorf("Timestamp = %v, want ~%v (diff %v)", rec.Timestamp, expectedTS, diff)
	}
}

func TestParseSSLRecord(t *testing.T) {
	input := `{
		"ts": 1700000000.0,
		"uid": "CYN2yq3sCqnKvu0hg",
		"id.orig_h": "10.0.0.5",
		"id.orig_p": 52345,
		"id.resp_h": "93.184.216.34",
		"id.resp_p": 443,
		"version": "TLSv13",
		"cipher": "TLS_AES_256_GCM_SHA384",
		"server_name": "example.com",
		"established": true,
		"ja3": "771,4866-4867-4865-49196-49200-159,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0",
		"ja3s": "771,4866,0-43-51",
		"cert_chain_fps": ["ABC123DEF456", "789GHI012JKL"]
	}`

	rec, err := ParseSSLRecord([]byte(input))
	if err != nil {
		t.Fatalf("ParseSSLRecord failed: %v", err)
	}

	if rec.UID != "CYN2yq3sCqnKvu0hg" {
		t.Errorf("UID = %q, want %q", rec.UID, "CYN2yq3sCqnKvu0hg")
	}
	if rec.ClientIP != "10.0.0.5" {
		t.Errorf("ClientIP = %q, want %q", rec.ClientIP, "10.0.0.5")
	}
	if rec.ClientPort != 52345 {
		t.Errorf("ClientPort = %d, want %d", rec.ClientPort, 52345)
	}
	if rec.ServerIP != "93.184.216.34" {
		t.Errorf("ServerIP = %q, want %q", rec.ServerIP, "93.184.216.34")
	}
	if rec.ServerPort != 443 {
		t.Errorf("ServerPort = %d, want %d", rec.ServerPort, 443)
	}
	if rec.Version != "TLSv13" {
		t.Errorf("Version = %q, want %q", rec.Version, "TLSv13")
	}
	if rec.Cipher != "TLS_AES_256_GCM_SHA384" {
		t.Errorf("Cipher = %q, want %q", rec.Cipher, "TLS_AES_256_GCM_SHA384")
	}
	if rec.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want %q", rec.ServerName, "example.com")
	}
	if !rec.Established {
		t.Error("Established = false, want true")
	}
	if rec.JA3 == "" {
		t.Error("JA3 should not be empty")
	}
	if rec.JA3S == "" {
		t.Error("JA3S should not be empty")
	}
	if len(rec.CertChainFPs) != 2 {
		t.Fatalf("CertChainFPs length = %d, want 2", len(rec.CertChainFPs))
	}
	if rec.CertChainFPs[0] != "ABC123DEF456" {
		t.Errorf("CertChainFPs[0] = %q, want %q", rec.CertChainFPs[0], "ABC123DEF456")
	}
}

func TestParseConnRecord(t *testing.T) {
	input := `{
		"ts": 1700000000.0,
		"uid": "C1aq7t3VMDyFbxON4i",
		"id.orig_h": "10.0.0.5",
		"id.orig_p": 52345,
		"id.resp_h": "93.184.216.34",
		"id.resp_p": 443,
		"proto": "tcp",
		"duration": 1.234567,
		"orig_bytes": 512,
		"resp_bytes": 4096,
		"conn_state": "SF"
	}`

	rec, err := ParseConnRecord([]byte(input))
	if err != nil {
		t.Fatalf("ParseConnRecord failed: %v", err)
	}

	if rec.UID != "C1aq7t3VMDyFbxON4i" {
		t.Errorf("UID = %q, want %q", rec.UID, "C1aq7t3VMDyFbxON4i")
	}
	if rec.ClientIP != "10.0.0.5" {
		t.Errorf("ClientIP = %q, want %q", rec.ClientIP, "10.0.0.5")
	}
	if rec.ClientPort != 52345 {
		t.Errorf("ClientPort = %d, want %d", rec.ClientPort, 52345)
	}
	if rec.ServerIP != "93.184.216.34" {
		t.Errorf("ServerIP = %q, want %q", rec.ServerIP, "93.184.216.34")
	}
	if rec.ServerPort != 443 {
		t.Errorf("ServerPort = %d, want %d", rec.ServerPort, 443)
	}
	if rec.Proto != "tcp" {
		t.Errorf("Proto = %q, want %q", rec.Proto, "tcp")
	}
	if rec.Duration != 1.234567 {
		t.Errorf("Duration = %f, want %f", rec.Duration, 1.234567)
	}
	if rec.OrigBytes != 512 {
		t.Errorf("OrigBytes = %d, want %d", rec.OrigBytes, 512)
	}
	if rec.RespBytes != 4096 {
		t.Errorf("RespBytes = %d, want %d", rec.RespBytes, 4096)
	}
	if rec.ConnState != "SF" {
		t.Errorf("ConnState = %q, want %q", rec.ConnState, "SF")
	}
}

func TestParseDN(t *testing.T) {
	tests := []struct {
		name     string
		dn       string
		wantCN   string
		wantOrg  string
	}{
		{
			name:    "full DN",
			dn:      "CN=example.com,O=Example Inc.,C=US",
			wantCN:  "example.com",
			wantOrg: "Example Inc.",
		},
		{
			name:    "CN only",
			dn:      "CN=example.com",
			wantCN:  "example.com",
			wantOrg: "",
		},
		{
			name:    "empty string",
			dn:      "",
			wantCN:  "",
			wantOrg: "",
		},
		{
			name:    "with spaces",
			dn:      "CN=example.com, O=Example Inc., C=US",
			wantCN:  "example.com",
			wantOrg: "Example Inc.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cn, org := parseDN(tt.dn)
			if cn != tt.wantCN {
				t.Errorf("parseDN(%q) cn = %q, want %q", tt.dn, cn, tt.wantCN)
			}
			if org != tt.wantOrg {
				t.Errorf("parseDN(%q) org = %q, want %q", tt.dn, org, tt.wantOrg)
			}
		})
	}
}

func TestUnixToTime(t *testing.T) {
	ts := 1700000000.123456
	got := unixToTime(ts)

	expected := time.Date(2023, 11, 14, 22, 13, 20, 123456000, time.UTC)
	// Allow 1 microsecond tolerance for float64 precision.
	if diff := got.Sub(expected).Abs(); diff > time.Microsecond {
		t.Errorf("unixToTime(%f) = %v, want ~%v (diff %v)", ts, got, expected, diff)
	}
}

func TestParseX509Record_InvalidJSON(t *testing.T) {
	_, err := ParseX509Record([]byte(`{invalid`))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestParseSSLRecord_InvalidJSON(t *testing.T) {
	_, err := ParseSSLRecord([]byte(`{invalid`))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestParseConnRecord_InvalidJSON(t *testing.T) {
	_, err := ParseConnRecord([]byte(`{invalid`))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}
