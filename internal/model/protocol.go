package model

import "time"

type EndpointProfile struct {
	ServerIP              string     `json:"server_ip"`
	ServerPort            int        `json:"server_port"`
	ServerName            string     `json:"server_name,omitempty"`
	CertFingerprint       string     `json:"cert_fingerprint"`
	MinTLSVersion         TLSVersion `json:"min_tls_version"`
	MaxTLSVersion         TLSVersion `json:"max_tls_version"`
	CipherSuites          []string   `json:"cipher_suites"`
	SupportsForwardSecrecy bool      `json:"supports_forward_secrecy"`
	SupportsAEAD          bool       `json:"supports_aead"`
	HasWeakCiphers        bool       `json:"has_weak_ciphers"`
	ObservationCount      int        `json:"observation_count"`
	FirstSeen             time.Time  `json:"first_seen"`
	LastSeen              time.Time  `json:"last_seen"`
}
