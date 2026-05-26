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

package model

import "time"

type KeyAlgorithm string

const (
	KeyRSA     KeyAlgorithm = "RSA"
	KeyECDSA   KeyAlgorithm = "ECDSA"
	KeyEd25519 KeyAlgorithm = "Ed25519"
	KeyUnknown KeyAlgorithm = "Unknown"
)

type SignatureAlgorithm string

const (
	SigSHA1WithRSA     SignatureAlgorithm = "SHA1WithRSA"
	SigSHA256WithRSA   SignatureAlgorithm = "SHA256WithRSA"
	SigSHA384WithRSA   SignatureAlgorithm = "SHA384WithRSA"
	SigSHA512WithRSA   SignatureAlgorithm = "SHA512WithRSA"
	SigECDSAWithSHA256 SignatureAlgorithm = "ECDSAWithSHA256"
	SigECDSAWithSHA384 SignatureAlgorithm = "ECDSAWithSHA384"
	SigEd25519Sig      SignatureAlgorithm = "Ed25519"
	SigMD5WithRSA      SignatureAlgorithm = "MD5WithRSA"
	SigUnknown         SignatureAlgorithm = "Unknown"
)

type DiscoverySource string

const (
	SourceZeekPassive  DiscoverySource = "zeek_passive"
	SourceZeekActive   DiscoverySource = "zeek_active"
	SourceCorelight    DiscoverySource = "corelight"
	SourceManualUpload DiscoverySource = "manual_upload"
	SourceActiveScan   DiscoverySource = "active_scan"
	// SourceCTLog — certificate discovered via a Certificate Transparency
	// log (v1.11 ct_domain external_source kind). Distinguished from
	// active-scan sources because CT certs may never have been deployed
	// to a host the operator owns; they're inventory-gap evidence, not
	// observed traffic. See internal/ingest/ct/poller.go and
	// internal/store/external_sources_shadow_certs.go.
	SourceCTLog DiscoverySource = "ct_log"
)

type DistinguishedName struct {
	CommonName         string `json:"common_name"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty"`
	Country            string `json:"country,omitempty"`
	State              string `json:"state,omitempty"`
	Locality           string `json:"locality,omitempty"`
	Full               string `json:"full"`
}

type Certificate struct {
	ID                    string             `json:"id"`
	FingerprintSHA256     string             `json:"fingerprint_sha256"`
	Subject               DistinguishedName  `json:"subject"`
	Issuer                DistinguishedName  `json:"issuer"`
	SerialNumber          string             `json:"serial_number"`
	NotBefore             time.Time          `json:"not_before"`
	NotAfter              time.Time          `json:"not_after"`
	KeyAlgorithm          KeyAlgorithm       `json:"key_algorithm"`
	KeySizeBits           int                `json:"key_size_bits"`
	SignatureAlgorithm    SignatureAlgorithm `json:"signature_algorithm"`
	SubjectAltNames       []string           `json:"subject_alt_names"`
	IsCA                  bool               `json:"is_ca"`
	BasicConstraintsPathLen *int             `json:"basic_constraints_path_len,omitempty"`
	KeyUsage              []string           `json:"key_usage"`
	ExtendedKeyUsage      []string           `json:"extended_key_usage"`
	OCSPResponderURLs     []string           `json:"ocsp_responder_urls"`
	CRLDistributionPoints []string           `json:"crl_distribution_points"`
	SCTs                  []string           `json:"scts"`
	RawPEM                string             `json:"raw_pem,omitempty"`
	SourceDiscovery       DiscoverySource    `json:"source_discovery"`
	FirstSeen             time.Time          `json:"first_seen"`
	LastSeen              time.Time          `json:"last_seen"`

	// SP-1.6 — AKI/SKI raw bytes per RFC 5280 §4.2.1.1, §4.2.1.2.
	// The resolver matches AuthorityKeyID byte-for-byte against parent.SubjectKeyID.
	AuthorityKeyID []byte `json:"authority_key_id,omitempty"`
	SubjectKeyID   []byte `json:"subject_key_id,omitempty"`

	// SPKIFingerprintSHA256 is hex-encoded SHA-256 of the cert's
	// RawSubjectPublicKeyInfo DER. Used by the trust-store scanner to
	// match private-key files to their corresponding certs. Computed at
	// parse time in certparse.parseDER.
	SPKIFingerprintSHA256 string `json:"spki_fingerprint_sha256,omitempty"`
}

// DaysUntilExpiry returns days until expiry (negative = expired).
func (c *Certificate) DaysUntilExpiry() int {
	return int(time.Until(c.NotAfter).Hours() / 24)
}

// IsExpired returns true if the certificate has expired.
func (c *Certificate) IsExpired() bool {
	return time.Now().After(c.NotAfter)
}

// IsSelfSigned returns true if subject matches issuer.
func (c *Certificate) IsSelfSigned() bool {
	if c.Subject.CommonName != "" && c.Subject.CommonName == c.Issuer.CommonName {
		return true
	}
	return c.Subject.Full != "" && c.Subject.Full == c.Issuer.Full
}
