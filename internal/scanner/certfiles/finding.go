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

// Package certfiles scans hosts for certificate files (PEM, DER, PKCS12, JKS).
package certfiles

import "time"

// CertFileFinding represents a single certificate discovered in a file.
type CertFileFinding struct {
	FingerprintSHA256  string
	SubjectCN          string
	Subject            string // full DN
	IssuerCN           string
	Issuer             string // full DN
	SerialNumber       string
	NotBefore          time.Time
	NotAfter           time.Time
	KeyAlgorithm       string // RSA, ECDSA, Ed25519
	KeySizeBits        int
	SignatureAlgorithm string
	SubjectAltNames    []string
	IsCA               bool
	RawPEM             string // full PEM block if available
	FilePath           string
	StoreType          string // pem, der, pkcs12, jks, macos_keychain

	// --- Scanner metadata (not mapped to discovery types) ---

	FileMode   uint32    // permission bits
	ModifiedAt time.Time // file mtime
	CertIndex  int       // position in multi-cert file (0-based)
}
