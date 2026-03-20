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
