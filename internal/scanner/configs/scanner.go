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

package configs

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/scanner/executil"
	"github.com/net4n6-dev/cipherflag/internal/scanner/truststore"
)

// Scanner discovers crypto configuration files on the host.
type Scanner struct {
	runner executil.CommandRunner
}

// New creates a Scanner with the given command runner.
func New(runner executil.CommandRunner) *Scanner {
	return &Scanner{runner: runner}
}

// ScanAll scans all known config file locations for the current platform.
func (s *Scanner) ScanAll(ctx context.Context) ([]ConfigFinding, error) {
	var all []ConfigFinding

	sshdPaths := []string{"/etc/ssh/sshd_config"}
	for _, p := range sshdPaths {
		if f, err := s.ScanSSHDConfig(ctx, p); err == nil && f != nil {
			all = append(all, *f)
		}
	}

	opensslPaths := []string{"/etc/ssl/openssl.cnf", "/etc/pki/tls/openssl.cnf"}
	for _, p := range opensslPaths {
		if f, err := s.ScanOpenSSLConfig(ctx, p); err == nil && f != nil {
			all = append(all, *f)
		}
	}

	javaPaths := findJavaSecurityPaths(ctx, s.runner)
	for _, p := range javaPaths {
		if f, err := s.ScanJavaSecurity(ctx, p); err == nil && f != nil {
			all = append(all, *f)
		}
	}

	nginxPaths := []string{"/etc/nginx/nginx.conf"}
	for _, p := range nginxPaths {
		if f, err := s.ScanNginxSSL(ctx, p); err == nil && f != nil {
			all = append(all, *f)
		}
	}

	apachePaths := []string{"/etc/apache2/sites-enabled/default-ssl.conf", "/etc/httpd/conf.d/ssl.conf"}
	for _, p := range apachePaths {
		if f, err := s.ScanApacheSSL(ctx, p); err == nil && f != nil {
			all = append(all, *f)
		}
	}

	return all, nil
}

// trustBundleGlobs are path patterns expanded via filepath.Glob before
// scanning. They augment truststore.TrustBundlePaths with versioned cluster
// layouts (e.g. /etc/postgresql/15/main/postgresql.conf).
var trustBundleGlobs = []string{
	"/etc/postgresql/*/main/postgresql.conf",
}

// ScanTrustBundles walks all known nginx, Apache, and PostgreSQL config paths
// (same set as ScanAll plus postgres), calls ParseTrustBundleDirectives on
// each present file, and returns a flat slice of TrustBundleRefs. Missing
// paths are silently skipped (logged at debug). This method is separate from
// ScanAll so callers can pass the refs directly to
// truststore.IngestAppConfigBundles without re-parsing the config files.
func (s *Scanner) ScanTrustBundles(_ context.Context, paths []string) []truststore.TrustBundleRef {
	// Expand globs into the path list.
	all := make([]string, len(paths))
	copy(all, paths)
	for _, g := range trustBundleGlobs {
		matches, err := filepath.Glob(g)
		if err != nil {
			log.Debug().Err(err).Str("glob", g).Msg("configs: trust bundle glob error")
			continue
		}
		all = append(all, matches...)
	}

	var out []truststore.TrustBundleRef
	for _, p := range all {
		if _, err := os.Stat(p); err != nil {
			log.Debug().Str("path", p).Msg("configs: trust bundle path not present, skipping")
			continue
		}
		refs := truststore.ParseTrustBundleDirectives(p)
		out = append(out, refs...)
	}
	return out
}

// ScanSSHDConfig parses sshd_config and its Include directory.
func (s *Scanner) ScanSSHDConfig(_ context.Context, path string) (*ConfigFinding, error) {
	settings, rawContent, err := parseSSHDConfig(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	info, _ := os.Stat(path)
	return &ConfigFinding{
		ConfigType: "sshd_config",
		FilePath:   path,
		Settings:   settings,
		RawContent: rawContent,
		ModifiedAt: fileModTime(info),
		FileMode:   fileMode(info),
	}, nil
}

// ScanOpenSSLConfig parses an openssl.cnf file.
func (s *Scanner) ScanOpenSSLConfig(_ context.Context, path string) (*ConfigFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	settings := parseOpenSSLCnf(string(data))
	info, _ := os.Stat(path)
	return &ConfigFinding{
		ConfigType: "openssl_cnf",
		FilePath:   path,
		Settings:   settings,
		RawContent: string(data),
		ModifiedAt: fileModTime(info),
		FileMode:   fileMode(info),
	}, nil
}

// ScanJavaSecurity parses a java.security file.
func (s *Scanner) ScanJavaSecurity(_ context.Context, path string) (*ConfigFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	settings := parseJavaProperties(string(data))
	info, _ := os.Stat(path)
	return &ConfigFinding{
		ConfigType: "java_security",
		FilePath:   path,
		Settings:   settings,
		RawContent: string(data),
		ModifiedAt: fileModTime(info),
		FileMode:   fileMode(info),
	}, nil
}

// ScanNginxSSL parses nginx config for SSL directives.
func (s *Scanner) ScanNginxSSL(_ context.Context, path string) (*ConfigFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	settings := parseNginxSSL(string(data))
	info, _ := os.Stat(path)
	return &ConfigFinding{
		ConfigType: "nginx_ssl",
		FilePath:   path,
		Settings:   settings,
		RawContent: string(data),
		ModifiedAt: fileModTime(info),
		FileMode:   fileMode(info),
	}, nil
}

// ScanApacheSSL parses Apache config for SSL directives.
func (s *Scanner) ScanApacheSSL(_ context.Context, path string) (*ConfigFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	settings := parseApacheSSL(string(data))
	info, _ := os.Stat(path)
	return &ConfigFinding{
		ConfigType: "apache_ssl",
		FilePath:   path,
		Settings:   settings,
		RawContent: string(data),
		ModifiedAt: fileModTime(info),
		FileMode:   fileMode(info),
	}, nil
}

// --- Parsers ---

func parseSSHDConfig(path string) (map[string]string, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}

	settings := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "Include ") {
			pattern := strings.TrimPrefix(line, "Include ")
			pattern = strings.TrimSpace(pattern)
			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join(filepath.Dir(path), pattern)
			}
			includeSettings := expandSSHDIncludes(pattern)
			for k, v := range includeSettings {
				settings[k] = v
			}
			continue
		}

		key, value := parseSSHDLine(line)
		if key != "" {
			settings[key] = value
		}
	}

	return settings, string(data), nil
}

func expandSSHDIncludes(pattern string) map[string]string {
	settings := make(map[string]string)
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return settings
	}
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, value := parseSSHDLine(line)
			if key != "" {
				settings[key] = value
			}
		}
	}
	return settings
}

func parseSSHDLine(line string) (string, string) {
	line = strings.Replace(line, "=", " ", 1)
	parts := strings.SplitN(line, " ", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}

func parseOpenSSLCnf(content string) map[string]string {
	settings := make(map[string]string)
	currentSection := ""
	hasFIPS := false

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.Trim(line, "[]")
			currentSection = strings.TrimSpace(currentSection)
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch {
		case currentSection == "req" && (key == "default_bits" || key == "default_md"):
			settings[key] = value
		case currentSection == "fips_sect" && key == "activate" && value == "1":
			hasFIPS = true
		}
	}

	if hasFIPS {
		settings["fips"] = "enabled"
	}
	return settings
}

func parseJavaProperties(content string) map[string]string {
	settings := make(map[string]string)
	interestKeys := []string{
		"jdk.tls.disabledAlgorithms",
		"keystore.type",
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if strings.HasPrefix(key, "security.provider.") {
			settings[key] = value
			continue
		}

		for _, ik := range interestKeys {
			if key == ik {
				settings[key] = value
				break
			}
		}
	}
	return settings
}

func parseNginxSSL(content string) map[string]string {
	settings := make(map[string]string)
	sslDirectives := []string{
		"ssl_protocols", "ssl_ciphers", "ssl_certificate",
		"ssl_prefer_server_ciphers",
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSuffix(line, ";")

		for _, directive := range sslDirectives {
			if strings.HasPrefix(line, directive+" ") || strings.HasPrefix(line, directive+"\t") {
				value := strings.TrimSpace(strings.TrimPrefix(line, directive))
				settings[directive] = value
			}
		}
	}
	return settings
}

func parseApacheSSL(content string) map[string]string {
	settings := make(map[string]string)
	apacheDirectives := []string{
		"SSLEngine", "SSLProtocol", "SSLCipherSuite", "SSLCertificateFile",
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		for _, directive := range apacheDirectives {
			if strings.HasPrefix(line, directive+" ") || strings.HasPrefix(line, directive+"\t") {
				value := strings.TrimSpace(strings.TrimPrefix(line, directive))
				settings[directive] = value
			}
		}
	}
	return settings
}

// --- Helpers ---

func findJavaSecurityPaths(_ context.Context, _ executil.CommandRunner) []string {
	var paths []string

	javaHome := os.Getenv("JAVA_HOME")
	if javaHome != "" {
		p := filepath.Join(javaHome, "conf", "security", "java.security")
		if _, err := os.Stat(p); err == nil {
			paths = append(paths, p)
		}
	}

	matches, _ := filepath.Glob("/usr/lib/jvm/*/conf/security/java.security")
	paths = append(paths, matches...)

	return paths
}

func fileModTime(info os.FileInfo) time.Time {
	if info == nil {
		return time.Time{}
	}
	return info.ModTime()
}

func fileMode(info os.FileInfo) uint32 {
	if info == nil {
		return 0
	}
	return uint32(info.Mode().Perm())
}
