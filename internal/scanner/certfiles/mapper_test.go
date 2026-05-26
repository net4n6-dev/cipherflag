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

package certfiles

import (
	"testing"
	"time"
)

func TestMapFindings(t *testing.T) {
	findings := []CertFileFinding{
		{
			FingerprintSHA256:  "abc123def456",
			SubjectCN:          "*.example.com",
			Subject:            "CN=*.example.com,O=Example Inc",
			IssuerCN:           "DigiCert SHA2",
			Issuer:             "CN=DigiCert SHA2,O=DigiCert Inc",
			SerialNumber:       "0A1B2C3D",
			NotBefore:          time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:           time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC),
			KeyAlgorithm:       "RSA",
			KeySizeBits:        2048,
			SignatureAlgorithm: "SHA256-RSA",
			SubjectAltNames:    []string{"*.example.com", "example.com"},
			IsCA:               false,
			RawPEM:             "-----BEGIN CERTIFICATE-----\nMIIE...\n-----END CERTIFICATE-----",
			FilePath:           "/etc/ssl/certs/example.pem",
			StoreType:          "pem",
			FileMode:           0644,
			ModifiedAt:         time.Now(),
			CertIndex:          0,
		},
	}

	discoveries := MapFindings(findings)

	if len(discoveries) != 1 {
		t.Fatalf("got %d, want 1", len(discoveries))
	}

	d := discoveries[0]
	if d.FingerprintSHA256 != "abc123def456" {
		t.Errorf("FingerprintSHA256 = %q", d.FingerprintSHA256)
	}
	if d.SubjectCN != "*.example.com" {
		t.Errorf("SubjectCN = %q", d.SubjectCN)
	}
	if d.IssuerCN != "DigiCert SHA2" {
		t.Errorf("IssuerCN = %q", d.IssuerCN)
	}
	if d.KeyAlgorithm != "RSA" {
		t.Errorf("KeyAlgorithm = %q", d.KeyAlgorithm)
	}
	if d.KeySizeBits != 2048 {
		t.Errorf("KeySizeBits = %d", d.KeySizeBits)
	}
	if d.FilePath != "/etc/ssl/certs/example.pem" {
		t.Errorf("FilePath = %q", d.FilePath)
	}
	if d.StoreType != "pem" {
		t.Errorf("StoreType = %q", d.StoreType)
	}
	if d.RawPEM == "" {
		t.Error("RawPEM should be preserved")
	}
	if len(d.SubjectAltNames) != 2 {
		t.Errorf("SubjectAltNames len = %d, want 2", len(d.SubjectAltNames))
	}
}

func TestMapFindings_Empty(t *testing.T) {
	discoveries := MapFindings(nil)
	if len(discoveries) != 0 {
		t.Errorf("got %d, want 0", len(discoveries))
	}
}
