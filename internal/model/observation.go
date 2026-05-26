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

type TLSVersion string

const (
	TLSVersionSSL30 TLSVersion = "SSL 3.0"
	TLSVersion10    TLSVersion = "TLS 1.0"
	TLSVersion11    TLSVersion = "TLS 1.1"
	TLSVersion12    TLSVersion = "TLS 1.2"
	TLSVersion13    TLSVersion = "TLS 1.3"
	TLSVersionUnk   TLSVersion = "Unknown"
)

type CipherStrength string

const (
	StrengthBest       CipherStrength = "Best"
	StrengthStrong     CipherStrength = "Strong"
	StrengthAcceptable CipherStrength = "Acceptable"
	StrengthWeak       CipherStrength = "Weak"
	StrengthInsecure   CipherStrength = "Insecure"
	StrengthUnknown    CipherStrength = "Unknown"
)

type CertificateObservation struct {
	ID                   string         `json:"id"`
	CertFingerprint      string         `json:"cert_fingerprint"`
	ServerIP             string         `json:"server_ip"`
	ServerPort           int            `json:"server_port"`
	ServerName           string         `json:"server_name,omitempty"`
	ClientIP             string         `json:"client_ip,omitempty"`
	NegotiatedVersion    TLSVersion     `json:"negotiated_version"`
	NegotiatedCipher     string         `json:"negotiated_cipher"`
	CipherStrength       CipherStrength `json:"cipher_strength"`
	JA3Fingerprint       string         `json:"ja3_fingerprint,omitempty"`
	JA3SFingerprint      string         `json:"ja3s_fingerprint,omitempty"`
	Source               DiscoverySource `json:"source"`
	ObservedAt           time.Time      `json:"observed_at"`
}
