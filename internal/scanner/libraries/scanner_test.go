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

package libraries

import (
	"context"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/scanner/executil"
)

func TestScanWithManager_Dpkg(t *testing.T) {
	runner := executil.NewTestRunner()
	runner.AddCommand(
		`dpkg-query -W -f ${Package}\t${Version}\t${Source}\t${Architecture}\n openssl libssl3 libssl1.1 libgnutls30 libnss3 libgcrypt20 libsodium23 libwolfssl-dev`,
		executil.CommandResult{
			Stdout: []byte("libssl3\t3.0.14-1ubuntu1\topenssl\tamd64\nlibgnutls30\t3.7.9-5\tgnutls28\tamd64\n"),
		},
	)

	s := New(runner)
	findings, err := s.ScanWithManager(context.Background(), "dpkg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}

	if findings[0].LibraryName != "openssl" {
		t.Errorf("findings[0].LibraryName = %q, want openssl", findings[0].LibraryName)
	}
	if findings[0].Version != "3.0.14-1ubuntu1" {
		t.Errorf("findings[0].Version = %q", findings[0].Version)
	}
	if findings[0].PackageName != "libssl3" {
		t.Errorf("findings[0].PackageName = %q", findings[0].PackageName)
	}
	if findings[0].PackageManager != "dpkg" {
		t.Errorf("findings[0].PackageManager = %q", findings[0].PackageManager)
	}
	if findings[0].Architecture != "amd64" {
		t.Errorf("findings[0].Architecture = %q", findings[0].Architecture)
	}

	if findings[1].LibraryName != "gnutls" {
		t.Errorf("findings[1].LibraryName = %q, want gnutls", findings[1].LibraryName)
	}
}

func TestScanWithManager_Rpm(t *testing.T) {
	runner := executil.NewTestRunner()
	runner.AddCommand(
		`rpm -q --queryformat %{NAME}\t%{VERSION}-%{RELEASE}\t%{RELEASE}\t%{ARCH}\n openssl openssl-libs gnutls nss libgcrypt libsodium wolfssl`,
		executil.CommandResult{
			Stdout: []byte("openssl\t3.0.7-27.el9\t27.el9\tx86_64\nopenssl-libs\t3.0.7-27.el9\t27.el9\tx86_64\n"),
		},
	)

	s := New(runner)
	findings, err := s.ScanWithManager(context.Background(), "rpm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	if findings[0].LibraryName != "openssl" {
		t.Errorf("findings[0].LibraryName = %q", findings[0].LibraryName)
	}
	if findings[0].PackageManager != "rpm" {
		t.Errorf("findings[0].PackageManager = %q", findings[0].PackageManager)
	}
}

func TestScanWithManager_Brew(t *testing.T) {
	runner := executil.NewTestRunner()
	runner.AddCommand(
		"brew list --versions openssl libsodium wolfssl gnutls nss libgcrypt",
		executil.CommandResult{
			Stdout: []byte("openssl 3.3.1\nlibsodium 1.0.20\n"),
		},
	)

	s := New(runner)
	findings, err := s.ScanWithManager(context.Background(), "brew")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	if findings[0].LibraryName != "openssl" {
		t.Errorf("findings[0].LibraryName = %q", findings[0].LibraryName)
	}
	if findings[0].Version != "3.3.1" {
		t.Errorf("findings[0].Version = %q", findings[0].Version)
	}
	if findings[0].PackageManager != "brew" {
		t.Errorf("findings[0].PackageManager = %q", findings[0].PackageManager)
	}
	if findings[1].LibraryName != "libsodium" {
		t.Errorf("findings[1].LibraryName = %q", findings[1].LibraryName)
	}
}

func TestScanWithManager_UnknownManager(t *testing.T) {
	runner := executil.NewTestRunner()
	s := New(runner)
	_, err := s.ScanWithManager(context.Background(), "unknown")
	if err == nil {
		t.Fatal("expected error for unknown manager")
	}
}

func TestScanHost_FallsThrough(t *testing.T) {
	runner := executil.NewTestRunner()
	// All package managers fail (not configured) — falls through to binary fallback.
	runner.AddCommand("openssl version", executil.CommandResult{
		Stdout: []byte("OpenSSL 3.0.14 4 Jun 2024\n"),
	})

	s := New(runner)
	findings, err := s.ScanHost(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (binary fallback)", len(findings))
	}
	if findings[0].LibraryName != "openssl" {
		t.Errorf("findings[0].LibraryName = %q", findings[0].LibraryName)
	}
	if findings[0].Version != "3.0.14" {
		t.Errorf("findings[0].Version = %q", findings[0].Version)
	}
	if findings[0].PackageManager != "binary" {
		t.Errorf("findings[0].PackageManager = %q, want binary", findings[0].PackageManager)
	}
}
