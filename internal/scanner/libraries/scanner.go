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
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/normalize"
	"github.com/net4n6-dev/cipherflag/internal/scanner/executil"
)

// Curated crypto package names per package manager.
var (
	debPackages  = []string{"openssl", "libssl3", "libssl1.1", "libgnutls30", "libnss3", "libgcrypt20", "libsodium23", "libwolfssl-dev"}
	rpmPackages  = []string{"openssl", "openssl-libs", "gnutls", "nss", "libgcrypt", "libsodium", "wolfssl"}
	brewPackages = []string{"openssl", "libsodium", "wolfssl", "gnutls", "nss", "libgcrypt"}
	apkPackages  = []string{"openssl", "libssl3", "gnutls", "nss", "libgcrypt", "libsodium", "wolfssl"}
	pacPackages  = []string{"openssl", "gnutls", "nss", "libgcrypt", "libsodium", "wolfssl"}
)

// Scanner discovers installed cryptographic libraries.
type Scanner struct {
	runner executil.CommandRunner
}

// New creates a Scanner with the given command runner.
func New(runner executil.CommandRunner) *Scanner {
	return &Scanner{runner: runner}
}

// ScanHost detects the platform's package managers and queries for crypto libraries.
// Tries managers in order: dpkg, rpm, apk, pacman, brew. If none succeed, falls
// back to binary detection.
func (s *Scanner) ScanHost(ctx context.Context) ([]LibraryFinding, error) {
	managers := []string{"dpkg", "rpm", "apk", "pacman", "brew"}
	for _, mgr := range managers {
		findings, err := s.ScanWithManager(ctx, mgr)
		if err != nil {
			log.Debug().Err(err).Str("manager", mgr).Msg("package manager unavailable, trying next")
			continue
		}
		if len(findings) > 0 {
			return findings, nil
		}
	}
	return s.binaryFallback(ctx)
}

// ScanWithManager queries a specific package manager for crypto libraries.
func (s *Scanner) ScanWithManager(ctx context.Context, mgr string) ([]LibraryFinding, error) {
	switch mgr {
	case "dpkg":
		return s.scanDpkg(ctx)
	case "rpm":
		return s.scanRpm(ctx)
	case "apk":
		return s.scanApk(ctx)
	case "pacman":
		return s.scanPacman(ctx)
	case "brew":
		return s.scanBrew(ctx)
	default:
		return nil, fmt.Errorf("unknown package manager: %s", mgr)
	}
}

func (s *Scanner) scanDpkg(ctx context.Context) ([]LibraryFinding, error) {
	args := append([]string{"-W", "-f", `${Package}\t${Version}\t${Source}\t${Architecture}\n`}, debPackages...)
	stdout, _, err := s.runner.Run(ctx, "dpkg-query", args...)
	if err != nil {
		return nil, err
	}
	return parseTSV(string(stdout), "dpkg"), nil
}

func (s *Scanner) scanRpm(ctx context.Context) ([]LibraryFinding, error) {
	args := append([]string{"-q", "--queryformat", `%{NAME}\t%{VERSION}-%{RELEASE}\t%{RELEASE}\t%{ARCH}\n`}, rpmPackages...)
	stdout, _, err := s.runner.Run(ctx, "rpm", args...)
	if err != nil {
		return nil, err
	}
	return parseTSV(string(stdout), "rpm"), nil
}

func (s *Scanner) scanApk(ctx context.Context) ([]LibraryFinding, error) {
	args := append([]string{"info", "-v"}, apkPackages...)
	stdout, _, err := s.runner.Run(ctx, "apk", args...)
	if err != nil {
		return nil, err
	}

	var findings []LibraryFinding
	for _, line := range strings.Split(strings.TrimSpace(string(stdout)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, version := parseApkLine(line)
		if name == "" {
			continue
		}
		findings = append(findings, LibraryFinding{
			LibraryName:    normalize.LibraryName(name),
			Version:        version,
			PackageName:    name,
			PackageManager: "apk",
		})
	}
	return findings, nil
}

func (s *Scanner) scanPacman(ctx context.Context) ([]LibraryFinding, error) {
	args := append([]string{"-Q"}, pacPackages...)
	stdout, _, err := s.runner.Run(ctx, "pacman", args...)
	if err != nil {
		return nil, err
	}

	var findings []LibraryFinding
	for _, line := range strings.Split(strings.TrimSpace(string(stdout)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		findings = append(findings, LibraryFinding{
			LibraryName:    normalize.LibraryName(fields[0]),
			Version:        fields[1],
			PackageName:    fields[0],
			PackageManager: "pacman",
		})
	}
	return findings, nil
}

func (s *Scanner) scanBrew(ctx context.Context) ([]LibraryFinding, error) {
	args := append([]string{"list", "--versions"}, brewPackages...)
	stdout, _, err := s.runner.Run(ctx, "brew", args...)
	if err != nil {
		return nil, err
	}

	var findings []LibraryFinding
	for _, line := range strings.Split(strings.TrimSpace(string(stdout)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		findings = append(findings, LibraryFinding{
			LibraryName:    normalize.LibraryName(fields[0]),
			Version:        fields[1],
			PackageName:    fields[0],
			PackageManager: "brew",
		})
	}
	return findings, nil
}

func (s *Scanner) binaryFallback(ctx context.Context) ([]LibraryFinding, error) {
	var findings []LibraryFinding

	stdout, _, err := s.runner.Run(ctx, "openssl", "version")
	if err == nil {
		version := parseOpenSSLVersion(string(stdout))
		if version != "" {
			findings = append(findings, LibraryFinding{
				LibraryName:    "openssl",
				Version:        version,
				PackageName:    "openssl",
				PackageManager: "binary",
			})
		}
	}

	return findings, nil
}

// parseTSV parses tab-separated output (dpkg-query and rpm formats).
// Expected format per line: name\tversion\t[source]\t[arch]
func parseTSV(output string, pkgManager string) []LibraryFinding {
	var findings []LibraryFinding
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		version := fields[1]

		f := LibraryFinding{
			LibraryName:    normalize.LibraryName(name),
			Version:        version,
			PackageName:    name,
			PackageManager: pkgManager,
		}
		if len(fields) >= 3 {
			f.SourceRepo = fields[2]
		}
		if len(fields) >= 4 {
			f.Architecture = fields[3]
		}
		findings = append(findings, f)
	}
	return findings
}

// parseApkLine splits "openssl-3.0.14-r0" into ("openssl", "3.0.14-r0").
func parseApkLine(line string) (string, string) {
	for i := len(line) - 1; i > 0; i-- {
		if line[i] == '-' && i+1 < len(line) && line[i+1] >= '0' && line[i+1] <= '9' {
			return line[:i], line[i+1:]
		}
	}
	return line, ""
}

// parseOpenSSLVersion extracts the version from "OpenSSL 3.0.14 4 Jun 2024".
func parseOpenSSLVersion(output string) string {
	fields := strings.Fields(strings.TrimSpace(output))
	if len(fields) >= 2 && strings.EqualFold(fields[0], "OpenSSL") {
		return fields[1]
	}
	return ""
}
