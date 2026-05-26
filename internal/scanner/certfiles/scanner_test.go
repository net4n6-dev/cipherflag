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
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/scanner/executil"
)

func testdataDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "testdata")
}

func TestScanFile_SinglePEM(t *testing.T) {
	s := New(&executil.OSRunner{}, nil)
	findings, err := s.ScanFile(context.Background(), filepath.Join(testdataDir(), "single.pem"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.FingerprintSHA256 == "" {
		t.Error("expected non-empty fingerprint")
	}
	if f.SubjectCN != "test.example.com" {
		t.Errorf("SubjectCN = %q, want test.example.com", f.SubjectCN)
	}
	if f.KeyAlgorithm != "RSA" {
		t.Errorf("KeyAlgorithm = %q, want RSA", f.KeyAlgorithm)
	}
	if f.KeySizeBits != 2048 {
		t.Errorf("KeySizeBits = %d, want 2048", f.KeySizeBits)
	}
	if f.StoreType != "pem" {
		t.Errorf("StoreType = %q, want pem", f.StoreType)
	}
	if f.CertIndex != 0 {
		t.Errorf("CertIndex = %d, want 0", f.CertIndex)
	}
	if f.RawPEM == "" {
		t.Error("expected RawPEM to be populated")
	}
}

func TestScanFile_BundlePEM(t *testing.T) {
	s := New(&executil.OSRunner{}, nil)
	findings, err := s.ScanFile(context.Background(), filepath.Join(testdataDir(), "bundle.pem"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	if findings[0].CertIndex != 0 {
		t.Errorf("findings[0].CertIndex = %d, want 0", findings[0].CertIndex)
	}
	if findings[1].CertIndex != 1 {
		t.Errorf("findings[1].CertIndex = %d, want 1", findings[1].CertIndex)
	}
	if findings[0].FingerprintSHA256 == findings[1].FingerprintSHA256 {
		t.Error("expected different fingerprints for different certs in bundle")
	}
}

func TestScanFile_SelfSigned(t *testing.T) {
	s := New(&executil.OSRunner{}, nil)
	findings, err := s.ScanFile(context.Background(), filepath.Join(testdataDir(), "selfsigned.pem"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if !findings[0].IsCA {
		t.Error("expected IsCA = true for self-signed CA")
	}
}

func TestScanFile_NonExistent(t *testing.T) {
	s := New(&executil.OSRunner{}, nil)
	_, err := s.ScanFile(context.Background(), "/nonexistent/path.pem")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

func TestScanDirectory_FindsCerts(t *testing.T) {
	s := New(&executil.OSRunner{}, nil)
	findings, err := s.ScanDirectory(context.Background(), testdataDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// testdata has single.pem (1 cert), bundle.pem (2 certs), selfsigned.pem (1 cert) = 4 findings
	if len(findings) < 3 {
		t.Errorf("got %d findings, expected at least 3", len(findings))
	}
}

func TestDetectStoreType(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/etc/ssl/certs/ca.pem", "pem"},
		{"/etc/ssl/certs/ca.crt", "pem"},
		{"/etc/ssl/certs/ca.cer", "pem"},
		{"/etc/ssl/certs/ca.der", "der"},
		{"/etc/ssl/certs/ca.p12", "pkcs12"},
		{"/etc/ssl/certs/ca.pfx", "pkcs12"},
		{"/etc/ssl/certs/ca.jks", "jks"},
		{"/etc/ssl/certs/ca.unknown", ""},
	}

	for _, tt := range tests {
		got := detectStoreType(tt.path)
		if got != tt.want {
			t.Errorf("detectStoreType(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestScanFile_PKCS12_PasswordProtected(t *testing.T) {
	tmpDir := t.TempDir()
	p12Path := filepath.Join(tmpDir, "encrypted.p12")
	if err := os.WriteFile(p12Path, []byte("fake pkcs12 data"), 0600); err != nil {
		t.Fatalf("create fixture: %v", err)
	}

	runner := executil.NewTestRunner()
	runner.AddCommand("openssl pkcs12 -in "+p12Path+" -nokeys -passin pass: -clcerts", executil.CommandResult{
		Stderr:   []byte("Mac verify error: invalid password?\n"),
		ExitCode: 1,
	})

	s := New(runner, nil)
	findings, err := s.ScanFile(context.Background(), p12Path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (partial)", len(findings))
	}

	f := findings[0]
	if f.FilePath != p12Path {
		t.Errorf("FilePath = %q", f.FilePath)
	}
	if f.StoreType != "pkcs12" {
		t.Errorf("StoreType = %q, want pkcs12", f.StoreType)
	}
	if f.FingerprintSHA256 != "" {
		t.Errorf("expected empty fingerprint for password-protected store, got %q", f.FingerprintSHA256)
	}
	if f.SubjectCN != "" {
		t.Error("expected empty SubjectCN for partial finding")
	}
}

func TestScanFile_PKCS12_Unlocked(t *testing.T) {
	pemData, err := os.ReadFile(filepath.Join(testdataDir(), "single.pem"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	tmpDir := t.TempDir()
	p12Path := filepath.Join(tmpDir, "unlocked.p12")
	if err := os.WriteFile(p12Path, []byte("fake pkcs12 data"), 0600); err != nil {
		t.Fatalf("create fixture: %v", err)
	}

	runner := executil.NewTestRunner()
	runner.AddCommand("openssl pkcs12 -in "+p12Path+" -nokeys -passin pass: -clcerts", executil.CommandResult{
		Stdout: pemData,
	})

	s := New(runner, nil)
	findings, err := s.ScanFile(context.Background(), p12Path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].StoreType != "pkcs12" {
		t.Errorf("StoreType = %q, want pkcs12", findings[0].StoreType)
	}
	if findings[0].SubjectCN != "test.example.com" {
		t.Errorf("SubjectCN = %q, want test.example.com", findings[0].SubjectCN)
	}
	if findings[0].FingerprintSHA256 == "" {
		t.Error("expected non-empty fingerprint for unlocked store")
	}
}

func TestScanFile_JKS_PasswordProtected(t *testing.T) {
	tmpDir := t.TempDir()
	jksPath := filepath.Join(tmpDir, "encrypted.jks")
	if err := os.WriteFile(jksPath, []byte("fake jks data"), 0600); err != nil {
		t.Fatalf("create fixture: %v", err)
	}

	runner := executil.NewTestRunner()
	runner.AddCommand("keytool -list -keystore "+jksPath+" -storepass changeit -rfc", executil.CommandResult{
		Stderr:   []byte("keytool error: java.security.UnrecoverableKeyException\n"),
		ExitCode: 1,
	})

	s := New(runner, nil)
	findings, err := s.ScanFile(context.Background(), jksPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (partial)", len(findings))
	}

	f := findings[0]
	if f.FilePath != jksPath {
		t.Errorf("FilePath = %q", f.FilePath)
	}
	if f.StoreType != "jks" {
		t.Errorf("StoreType = %q, want jks", f.StoreType)
	}
	if f.FingerprintSHA256 != "" {
		t.Errorf("expected empty fingerprint for password-protected store, got %q", f.FingerprintSHA256)
	}
}

func TestScanFile_JKS_Unlocked(t *testing.T) {
	pemData, err := os.ReadFile(filepath.Join(testdataDir(), "single.pem"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	tmpDir := t.TempDir()
	jksPath := filepath.Join(tmpDir, "unlocked.jks")
	if err := os.WriteFile(jksPath, []byte("fake jks data"), 0600); err != nil {
		t.Fatalf("create fixture: %v", err)
	}

	runner := executil.NewTestRunner()
	runner.AddCommand("keytool -list -keystore "+jksPath+" -storepass changeit -rfc", executil.CommandResult{
		Stdout: pemData,
	})

	s := New(runner, nil)
	findings, err := s.ScanFile(context.Background(), jksPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].StoreType != "jks" {
		t.Errorf("StoreType = %q, want jks", findings[0].StoreType)
	}
	if findings[0].FingerprintSHA256 == "" {
		t.Error("expected non-empty fingerprint for unlocked store")
	}
}
