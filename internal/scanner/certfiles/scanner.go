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
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/scanner/executil"
)

// Common certificate file extensions and their store types.
var certExtensions = map[string]string{
	".pem": "pem",
	".crt": "pem",
	".cer": "pem",
	".der": "der",
	".p12": "pkcs12",
	".pfx": "pkcs12",
	".jks": "jks",
}

// Standard scan directories for Linux.
var linuxScanDirs = []string{
	"/etc/ssl/certs",
	"/etc/pki/tls/certs",
	"/usr/local/share/ca-certificates",
}

// Scanner discovers certificate files on the host.
type Scanner struct {
	runner executil.CommandRunner
	lookup SPKILookup
}

// New creates a Scanner with the given command runner and SPKI lookup.
// The lookup may be nil during bootstrap; DetectPEMPrivateKey returns
// no observations when lookup is nil.
func New(runner executil.CommandRunner, lookup SPKILookup) *Scanner {
	return &Scanner{runner: runner, lookup: lookup}
}

// ScanDirectories scans standard certificate locations for the current platform.
func (s *Scanner) ScanDirectories(ctx context.Context) ([]CertFileFinding, error) {
	var all []CertFileFinding
	for _, dir := range linuxScanDirs {
		findings, err := s.ScanDirectory(ctx, dir)
		if err != nil {
			log.Warn().Err(err).Str("dir", dir).Msg("cert dir scan failed, skipping")
			continue
		}
		all = append(all, findings...)
	}
	return all, nil
}

// ScanDirectory walks a directory for certificate files.
func (s *Scanner) ScanDirectory(ctx context.Context, root string) ([]CertFileFinding, error) {
	var all []CertFileFinding

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}

		st := detectStoreType(path)
		if st == "" {
			if isPEMFile(path) {
				st = "pem"
			} else {
				return nil
			}
		}

		findings, err := s.ScanFile(ctx, path)
		if err != nil {
			log.Warn().Err(err).Str("path", path).Msg("cert file parse failed, skipping")
			return nil
		}
		all = append(all, findings...)
		return nil
	})

	if err != nil {
		return all, err
	}
	return all, nil
}

// ScanFile parses a single certificate file and returns findings.
func (s *Scanner) ScanFile(ctx context.Context, path string) ([]CertFileFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	info, _ := os.Stat(path)
	var fileMode uint32
	var modTime time.Time
	if info != nil {
		fileMode = uint32(info.Mode().Perm())
		modTime = info.ModTime()
	}

	st := detectStoreType(path)
	if st == "" {
		if hasPEMHeader(data) {
			st = "pem"
		} else {
			st = "der"
		}
	}

	switch st {
	case "pem":
		return s.parsePEMData(data, path, fileMode, modTime)
	case "der":
		return s.parseDERData(data, path, fileMode, modTime)
	case "pkcs12":
		return s.parsePKCS12(ctx, path, fileMode, modTime)
	case "jks":
		return s.parseJKS(ctx, path, fileMode, modTime)
	default:
		return nil, fmt.Errorf("unsupported store type: %s", st)
	}
}

func (s *Scanner) parsePEMData(data []byte, path string, mode uint32, modTime time.Time) ([]CertFileFinding, error) {
	var findings []CertFileFinding
	rest := data
	index := 0

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			index++
			continue
		}

		rawPEM := string(pem.EncodeToMemory(block))
		findings = append(findings, certToFinding(cert, path, "pem", rawPEM, mode, modTime, index))
		index++
	}

	if len(findings) == 0 {
		// Maybe it's DER disguised with a .pem extension.
		return s.parseDERData(data, path, mode, modTime)
	}
	return findings, nil
}

func (s *Scanner) parseDERData(data []byte, path string, mode uint32, modTime time.Time) ([]CertFileFinding, error) {
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("parse DER %s: %w", path, err)
	}
	return []CertFileFinding{certToFinding(cert, path, "der", "", mode, modTime, 0)}, nil
}

func (s *Scanner) parsePKCS12(ctx context.Context, path string, mode uint32, modTime time.Time) ([]CertFileFinding, error) {
	stdout, _, err := s.runner.Run(ctx, "openssl", "pkcs12", "-in", path, "-nokeys", "-passin", "pass:", "-clcerts")
	if err != nil {
		// Password-protected — return partial finding.
		return []CertFileFinding{{
			FilePath:   path,
			StoreType:  "pkcs12",
			FileMode:   mode,
			ModifiedAt: modTime,
		}}, nil
	}

	findings, _ := s.parsePEMData(stdout, path, mode, modTime)
	for i := range findings {
		findings[i].StoreType = "pkcs12"
	}
	return findings, nil
}

func (s *Scanner) parseJKS(ctx context.Context, path string, mode uint32, modTime time.Time) ([]CertFileFinding, error) {
	stdout, _, err := s.runner.Run(ctx, "keytool", "-list", "-keystore", path, "-storepass", "changeit", "-rfc")
	if err != nil {
		return []CertFileFinding{{
			FilePath:   path,
			StoreType:  "jks",
			FileMode:   mode,
			ModifiedAt: modTime,
		}}, nil
	}

	findings, _ := s.parsePEMData(stdout, path, mode, modTime)
	for i := range findings {
		findings[i].StoreType = "jks"
	}
	return findings, nil
}

// certToFinding converts a parsed x509.Certificate to a CertFileFinding.
func certToFinding(cert *x509.Certificate, path, storeType, rawPEM string, mode uint32, modTime time.Time, index int) CertFileFinding {
	fp := sha256.Sum256(cert.Raw)

	var sans []string
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	sans = append(sans, cert.EmailAddresses...)

	return CertFileFinding{
		FingerprintSHA256:  hex.EncodeToString(fp[:]),
		SubjectCN:          cert.Subject.CommonName,
		Subject:            cert.Subject.String(),
		IssuerCN:           cert.Issuer.CommonName,
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.Text(16),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		KeyAlgorithm:       keyAlgorithm(cert),
		KeySizeBits:        keySize(cert),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		SubjectAltNames:    sans,
		IsCA:               cert.IsCA,
		RawPEM:             rawPEM,
		FilePath:           path,
		StoreType:          storeType,
		FileMode:           mode,
		ModifiedAt:         modTime,
		CertIndex:          index,
	}
}

func keyAlgorithm(cert *x509.Certificate) string {
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA"
	case *ecdsa.PublicKey:
		return "ECDSA"
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return "Unknown"
	}
}

func keySize(cert *x509.Certificate) int {
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

// detectStoreType returns the store type based on file extension.
func detectStoreType(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	return certExtensions[ext]
}

// hasPEMHeader checks if data starts with a PEM header.
func hasPEMHeader(data []byte) bool {
	return len(data) > 10 && strings.HasPrefix(string(data), "-----BEGIN")
}

// isPEMFile reads just enough of a file to check for a PEM header.
func isPEMFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 30)
	n, _ := f.Read(buf)
	return strings.HasPrefix(string(buf[:n]), "-----BEGIN")
}
