package zeek

import (
	"testing"
	"time"

	"github.com/cyberflag-ai/cipherflag/internal/model"
)

func TestMapX509ToCertificate(t *testing.T) {
	rec := &X509Record{
		Timestamp:      time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC),
		FileID:         "FhJMEj3ISz0FZpRMi4",
		Fingerprint:    "ABC123DEF456",
		SubjectCN:      "example.com",
		SubjectOrg:     "Example Inc.",
		SubjectFull:    "CN=example.com,O=Example Inc.,C=US",
		IssuerCN:       "Let's Encrypt Authority X3",
		IssuerOrg:      "Let's Encrypt",
		IssuerFull:     "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US",
		Serial:         "0A0141420000015385736A0B85ECA708",
		NotValidBefore: time.Date(2023, 7, 22, 0, 0, 0, 0, time.UTC),
		NotValidAfter:  time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC),
		KeyAlg:         "rsaEncryption",
		KeyType:        "rsa",
		KeyLength:      2048,
		SigAlg:         "sha256WithRSAEncryption",
		SANsDNS:        []string{"example.com", "www.example.com"},
		SANsIP:         []string{"192.168.1.1"},
		SANsEmail:      []string{"admin@example.com"},
		IsCA:           false,
		Version:        3,
	}

	cert := MapX509ToCertificate(rec)

	if cert.FingerprintSHA256 != "ABC123DEF456" {
		t.Errorf("FingerprintSHA256 = %q, want %q", cert.FingerprintSHA256, "ABC123DEF456")
	}
	if cert.Subject.CommonName != "example.com" {
		t.Errorf("Subject.CommonName = %q, want %q", cert.Subject.CommonName, "example.com")
	}
	if cert.Subject.Organization != "Example Inc." {
		t.Errorf("Subject.Organization = %q, want %q", cert.Subject.Organization, "Example Inc.")
	}
	if cert.Subject.Full != "CN=example.com,O=Example Inc.,C=US" {
		t.Errorf("Subject.Full = %q, want %q", cert.Subject.Full, "CN=example.com,O=Example Inc.,C=US")
	}
	if cert.Issuer.CommonName != "Let's Encrypt Authority X3" {
		t.Errorf("Issuer.CommonName = %q, want %q", cert.Issuer.CommonName, "Let's Encrypt Authority X3")
	}
	if cert.Issuer.Organization != "Let's Encrypt" {
		t.Errorf("Issuer.Organization = %q, want %q", cert.Issuer.Organization, "Let's Encrypt")
	}
	if cert.SerialNumber != "0A0141420000015385736A0B85ECA708" {
		t.Errorf("SerialNumber = %q, want %q", cert.SerialNumber, "0A0141420000015385736A0B85ECA708")
	}
	if cert.KeyAlgorithm != model.KeyRSA {
		t.Errorf("KeyAlgorithm = %q, want %q", cert.KeyAlgorithm, model.KeyRSA)
	}
	if cert.KeySizeBits != 2048 {
		t.Errorf("KeySizeBits = %d, want %d", cert.KeySizeBits, 2048)
	}
	if cert.SignatureAlgorithm != model.SigSHA256WithRSA {
		t.Errorf("SignatureAlgorithm = %q, want %q", cert.SignatureAlgorithm, model.SigSHA256WithRSA)
	}
	if cert.IsCA {
		t.Error("IsCA = true, want false")
	}
	if cert.SourceDiscovery != model.SourceZeekPassive {
		t.Errorf("SourceDiscovery = %q, want %q", cert.SourceDiscovery, model.SourceZeekPassive)
	}

	// SANs should combine DNS + IP + Email
	expectedSANs := []string{"example.com", "www.example.com", "192.168.1.1", "admin@example.com"}
	if len(cert.SubjectAltNames) != len(expectedSANs) {
		t.Fatalf("SubjectAltNames length = %d, want %d", len(cert.SubjectAltNames), len(expectedSANs))
	}
	for i, san := range expectedSANs {
		if cert.SubjectAltNames[i] != san {
			t.Errorf("SubjectAltNames[%d] = %q, want %q", i, cert.SubjectAltNames[i], san)
		}
	}

	// FirstSeen and LastSeen should be recent (within a minute of now).
	now := time.Now().UTC()
	if now.Sub(cert.FirstSeen) > time.Minute {
		t.Errorf("FirstSeen too old: %v", cert.FirstSeen)
	}
	if now.Sub(cert.LastSeen) > time.Minute {
		t.Errorf("LastSeen too old: %v", cert.LastSeen)
	}
}

func TestMapX509ToCertificate_EmptySANs(t *testing.T) {
	rec := &X509Record{
		Fingerprint: "FP1",
		SubjectCN:   "test.com",
		KeyAlg:      "rsaEncryption",
		KeyType:     "rsa",
		SigAlg:      "sha256WithRSAEncryption",
	}

	cert := MapX509ToCertificate(rec)

	if cert.SubjectAltNames != nil {
		t.Errorf("SubjectAltNames = %v, want nil for empty SANs", cert.SubjectAltNames)
	}
}

func TestMapSSLToObservations(t *testing.T) {
	ts := time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC)
	rec := &SSLRecord{
		Timestamp:    ts,
		UID:          "CYN2yq3sCqnKvu0hg",
		ClientIP:     "10.0.0.5",
		ClientPort:   52345,
		ServerIP:     "93.184.216.34",
		ServerPort:   443,
		Version:      "TLSv13",
		Cipher:       "TLS_AES_256_GCM_SHA384",
		ServerName:   "example.com",
		Established:  true,
		JA3:          "ja3hash",
		JA3S:         "ja3shash",
		CertChainFPs: []string{"FP1", "FP2", "FP3"},
	}

	obs := MapSSLToObservations(rec)

	if len(obs) != 3 {
		t.Fatalf("observations count = %d, want 3", len(obs))
	}

	// Check first observation in detail.
	o := obs[0]
	if o.CertFingerprint != "FP1" {
		t.Errorf("CertFingerprint = %q, want %q", o.CertFingerprint, "FP1")
	}
	if o.ServerIP != "93.184.216.34" {
		t.Errorf("ServerIP = %q, want %q", o.ServerIP, "93.184.216.34")
	}
	if o.ServerPort != 443 {
		t.Errorf("ServerPort = %d, want %d", o.ServerPort, 443)
	}
	if o.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want %q", o.ServerName, "example.com")
	}
	if o.ClientIP != "10.0.0.5" {
		t.Errorf("ClientIP = %q, want %q", o.ClientIP, "10.0.0.5")
	}
	if o.NegotiatedVersion != model.TLSVersion13 {
		t.Errorf("NegotiatedVersion = %q, want %q", o.NegotiatedVersion, model.TLSVersion13)
	}
	if o.NegotiatedCipher != "TLS_AES_256_GCM_SHA384" {
		t.Errorf("NegotiatedCipher = %q, want %q", o.NegotiatedCipher, "TLS_AES_256_GCM_SHA384")
	}
	if o.CipherStrength != model.StrengthBest {
		t.Errorf("CipherStrength = %q, want %q", o.CipherStrength, model.StrengthBest)
	}
	if o.JA3Fingerprint != "ja3hash" {
		t.Errorf("JA3Fingerprint = %q, want %q", o.JA3Fingerprint, "ja3hash")
	}
	if o.JA3SFingerprint != "ja3shash" {
		t.Errorf("JA3SFingerprint = %q, want %q", o.JA3SFingerprint, "ja3shash")
	}
	if o.Source != model.SourceZeekPassive {
		t.Errorf("Source = %q, want %q", o.Source, model.SourceZeekPassive)
	}
	if !o.ObservedAt.Equal(ts) {
		t.Errorf("ObservedAt = %v, want %v", o.ObservedAt, ts)
	}

	// Check remaining observations have correct fingerprints.
	if obs[1].CertFingerprint != "FP2" {
		t.Errorf("obs[1].CertFingerprint = %q, want %q", obs[1].CertFingerprint, "FP2")
	}
	if obs[2].CertFingerprint != "FP3" {
		t.Errorf("obs[2].CertFingerprint = %q, want %q", obs[2].CertFingerprint, "FP3")
	}
}

func TestMapSSLToObservations_EmptyChain(t *testing.T) {
	rec := &SSLRecord{
		ServerIP:     "10.0.0.1",
		ServerPort:   443,
		CertChainFPs: nil,
	}

	obs := MapSSLToObservations(rec)
	if len(obs) != 0 {
		t.Errorf("observations count = %d, want 0 for empty chain", len(obs))
	}
}

func TestMapKeyAlgorithm(t *testing.T) {
	tests := []struct {
		alg, keyType string
		want         model.KeyAlgorithm
	}{
		{"rsaEncryption", "rsa", model.KeyRSA},
		{"id-ecPublicKey", "ecdsa", model.KeyECDSA},
		{"ecPublicKey", "ec", model.KeyECDSA},
		{"ED25519", "", model.KeyEd25519},
		{"unknown", "unknown", model.KeyUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.alg+"_"+tt.keyType, func(t *testing.T) {
			got := mapKeyAlgorithm(tt.alg, tt.keyType)
			if got != tt.want {
				t.Errorf("mapKeyAlgorithm(%q, %q) = %q, want %q", tt.alg, tt.keyType, got, tt.want)
			}
		})
	}
}

func TestMapSigAlgorithm(t *testing.T) {
	tests := []struct {
		alg  string
		want model.SignatureAlgorithm
	}{
		{"sha256WithRSAEncryption", model.SigSHA256WithRSA},
		{"sha384WithRSAEncryption", model.SigSHA384WithRSA},
		{"sha512WithRSAEncryption", model.SigSHA512WithRSA},
		{"sha1WithRSAEncryption", model.SigSHA1WithRSA},
		{"md5WithRSAEncryption", model.SigMD5WithRSA},
		{"ecdsa-with-SHA256", model.SigECDSAWithSHA256},
		{"ecdsa-with-SHA384", model.SigECDSAWithSHA384},
		{"ED25519", model.SigEd25519Sig},
		{"somethingUnknown", model.SigUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			got := mapSigAlgorithm(tt.alg)
			if got != tt.want {
				t.Errorf("mapSigAlgorithm(%q) = %q, want %q", tt.alg, got, tt.want)
			}
		})
	}
}

func TestMapTLSVersion(t *testing.T) {
	tests := []struct {
		version string
		want    model.TLSVersion
	}{
		{"TLSv13", model.TLSVersion13},
		{"TLSv1.3", model.TLSVersion13},
		{"TLSv12", model.TLSVersion12},
		{"TLSv1.2", model.TLSVersion12},
		{"TLSv11", model.TLSVersion11},
		{"TLSv1.1", model.TLSVersion11},
		{"TLSv10", model.TLSVersion10},
		{"TLSv1.0", model.TLSVersion10},
		{"TLSv1", model.TLSVersion10},
		{"SSLv30", model.TLSVersionSSL30},
		{"SSLv3", model.TLSVersionSSL30},
		{"unknown", model.TLSVersionUnk},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := mapTLSVersion(tt.version)
			if got != tt.want {
				t.Errorf("mapTLSVersion(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

func TestClassifyCipherStrength(t *testing.T) {
	tests := []struct {
		cipher string
		want   model.CipherStrength
	}{
		{"TLS_CHACHA20_POLY1305_SHA256", model.StrengthBest},
		{"TLS_AES_256_GCM_SHA384", model.StrengthBest},
		{"TLS_AES_128_GCM_SHA256", model.StrengthStrong},
		{"TLS_AES_128_CBC_SHA256", model.StrengthAcceptable},
		{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", model.StrengthWeak},
		{"TLS_RSA_WITH_RC4_128_SHA", model.StrengthWeak},
		{"TLS_RSA_WITH_NULL_SHA", model.StrengthInsecure},
		{"TLS_RSA_EXPORT_WITH_RC4_40_MD5", model.StrengthInsecure},
		{"SOME_UNKNOWN_CIPHER", model.StrengthUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.cipher, func(t *testing.T) {
			got := classifyCipherStrength(tt.cipher)
			if got != tt.want {
				t.Errorf("classifyCipherStrength(%q) = %q, want %q", tt.cipher, got, tt.want)
			}
		})
	}
}
