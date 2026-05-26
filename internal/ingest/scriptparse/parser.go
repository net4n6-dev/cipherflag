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

// Package scriptparse parses newline-delimited JSON (NDJSON) output produced
// by CipherFlag discovery scripts into a DiscoveryResult.
package scriptparse

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
)

// ParseError describes a single line that could not be parsed.
type ParseError struct {
	Line   int
	Input  string
	Reason string
}

func (e ParseError) Error() string {
	return fmt.Sprintf("line %d: %s", e.Line, e.Reason)
}

// ParseNDJSON reads newline-delimited JSON from reader and returns a
// DiscoveryResult containing all parsed assets. Lines that fail to parse
// are collected as ParseErrors but do not stop parsing. The returned error
// is non-nil only for fatal I/O failures; individual line errors are
// returned in the []ParseError slice.
func ParseNDJSON(reader io.Reader, source string, hostname string) (*ingest.DiscoveryResult, []ParseError, error) {
	result := &ingest.DiscoveryResult{
		Source:    source,
		Hostname:  hostname,
		Timestamp: time.Now(),
	}

	var parseErrors []ParseError
	lineNum := 0
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()

		// Skip blank lines (including whitespace-only lines).
		if strings.TrimSpace(raw) == "" {
			continue
		}

		// Unmarshal into a generic map to inspect the type field.
		var obj map[string]any
		if err := json.Unmarshal([]byte(raw), &obj); err != nil {
			parseErrors = append(parseErrors, ParseError{
				Line:   lineNum,
				Input:  raw,
				Reason: fmt.Sprintf("malformed JSON: %v", err),
			})
			continue
		}

		assetType, _ := obj["type"].(string)

		switch assetType {
		case "certificate":
			cert, err := mapCertificate(obj, source)
			if err != nil {
				parseErrors = append(parseErrors, ParseError{Line: lineNum, Input: raw, Reason: err.Error()})
				continue
			}
			result.Certificates = append(result.Certificates, *cert)

		case "ssh_key":
			key, err := mapSSHKey(obj, source)
			if err != nil {
				parseErrors = append(parseErrors, ParseError{Line: lineNum, Input: raw, Reason: err.Error()})
				continue
			}
			result.SSHKeys = append(result.SSHKeys, *key)

		case "library":
			lib, err := mapLibrary(obj, source)
			if err != nil {
				parseErrors = append(parseErrors, ParseError{Line: lineNum, Input: raw, Reason: err.Error()})
				continue
			}
			result.Libraries = append(result.Libraries, *lib)

		case "config":
			cfg, err := mapConfig(obj, source)
			if err != nil {
				parseErrors = append(parseErrors, ParseError{Line: lineNum, Input: raw, Reason: err.Error()})
				continue
			}
			result.Configs = append(result.Configs, *cfg)

		default:
			reason := fmt.Sprintf("unknown asset type %q", assetType)
			if assetType == "" {
				reason = "missing or empty \"type\" field"
			}
			parseErrors = append(parseErrors, ParseError{Line: lineNum, Input: raw, Reason: reason})
		}
	}

	if err := scanner.Err(); err != nil {
		return result, parseErrors, fmt.Errorf("scanner error: %w", err)
	}

	return result, parseErrors, nil
}

// ---------------------------------------------------------------------------
// Type-specific mappers
// ---------------------------------------------------------------------------

func mapCertificate(obj map[string]any, source string) (*dedup.CertDiscovery, error) {
	fp := stringField(obj, "fingerprint_sha256")
	if fp == "" {
		return nil, fmt.Errorf("missing required field: fingerprint_sha256")
	}

	notBefore, err := parseRFC3339Field(obj, "not_before")
	if err != nil {
		return nil, fmt.Errorf("invalid not_before: %w", err)
	}
	notAfter, err := parseRFC3339Field(obj, "not_after")
	if err != nil {
		return nil, fmt.Errorf("invalid not_after: %w", err)
	}

	return &dedup.CertDiscovery{
		FingerprintSHA256:  fp,
		SubjectCN:          stringField(obj, "subject_cn"),
		IssuerCN:           stringField(obj, "issuer_cn"),
		SerialNumber:       stringField(obj, "serial_number"),
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		KeyAlgorithm:       stringField(obj, "key_algorithm"),
		KeySizeBits:        intField(obj, "key_size"),
		SignatureAlgorithm: stringField(obj, "signature_algorithm"),
		FilePath:           stringField(obj, "file_path"),
		StoreType:          stringField(obj, "store_type"),
		Source:             source,
	}, nil
}

func mapSSHKey(obj map[string]any, source string) (*dedup.SSHKeyDiscovery, error) {
	fp := stringField(obj, "file_path")
	if fp == "" {
		return nil, fmt.Errorf("missing required field: file_path")
	}

	return &dedup.SSHKeyDiscovery{
		FingerprintSHA256: stringField(obj, "fingerprint_sha256"),
		KeyType:           stringField(obj, "key_type"),
		KeySizeBits:       intField(obj, "key_size"),
		FilePath:          fp,
		OwnerUser:         stringField(obj, "owner"),
		IsProtected:       boolField(obj, "is_protected"),
		IsAuthorized:      boolField(obj, "is_authorized"),
		GrantsRoot:        boolField(obj, "grants_root"),
		Source:            source,
	}, nil
}

func mapLibrary(obj map[string]any, source string) (*dedup.LibraryDiscovery, error) {
	name := stringField(obj, "name")
	if name == "" {
		return nil, fmt.Errorf("missing required field: name")
	}
	version := stringField(obj, "version")
	if version == "" {
		return nil, fmt.Errorf("missing required field: version")
	}

	return &dedup.LibraryDiscovery{
		LibraryName:    name,
		Version:        version,
		PackageName:    stringField(obj, "package_name"),
		PackageManager: stringField(obj, "package_manager"),
		InstallPath:    stringField(obj, "install_path"),
		Source:         source,
	}, nil
}

func mapConfig(obj map[string]any, source string) (*dedup.ConfigDiscovery, error) {
	configType := stringField(obj, "config_type")
	if configType == "" {
		return nil, fmt.Errorf("missing required field: config_type")
	}
	filePath := stringField(obj, "file_path")
	if filePath == "" {
		return nil, fmt.Errorf("missing required field: file_path")
	}

	settings, err := stringMapField(obj, "settings")
	if err != nil {
		return nil, fmt.Errorf("invalid settings: %w", err)
	}

	return &dedup.ConfigDiscovery{
		ConfigType: configType,
		FilePath:   filePath,
		Settings:   settings,
		Source:     source,
	}, nil
}

// ---------------------------------------------------------------------------
// Field extraction helpers
// ---------------------------------------------------------------------------

func stringField(obj map[string]any, key string) string {
	v, _ := obj[key].(string)
	return v
}

func boolField(obj map[string]any, key string) bool {
	v, _ := obj[key].(bool)
	return v
}

// intField handles both integer JSON numbers and float64 (Go's default for
// JSON numbers decoded into any).
func intField(obj map[string]any, key string) int {
	switch v := obj[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	}
	return 0
}

func parseRFC3339Field(obj map[string]any, key string) (time.Time, error) {
	s := stringField(obj, key)
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, s)
}

// stringMapField converts a nested map[string]any into map[string]string.
// Returns nil map (not an error) when the key is absent.
func stringMapField(obj map[string]any, key string) (map[string]string, error) {
	raw, ok := obj[key]
	if !ok || raw == nil {
		return nil, nil
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected object, got %T", raw)
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("settings value for key %q is not a string (got %T)", k, v)
		}
		out[k] = s
	}
	return out, nil
}
