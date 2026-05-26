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

package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/net4n6-dev/cipherflag/internal/analysis/pqc"
)

// WeakAlgoOccurrence is a single (asset, algorithm) pairing flagged
// by the PQC taxonomy as Vulnerable or Weakened. Powers AQ-AH-01 —
// *"where is RSA-1024 / SHA-1 / 3DES / DSA / MD5 still in use?"*
//
// One asset can contribute multiple occurrences (e.g. a certificate
// with both key_algorithm=rsa + key_size_bits=1024 and
// signature_algorithm=sha1WithRSAEncryption emits two rows). The
// frontend groups by (AlgorithmCanonical, Classification) to produce
// the per-algorithm hit-list operators use as an audit driver.
type WeakAlgoOccurrence struct {
	AssetType           string            `json:"asset_type"`
	AssetID             string            `json:"asset_id"`
	Label               string            `json:"label"`
	AlgorithmRaw        string            `json:"algorithm_raw"`
	AlgorithmCanonical  string            `json:"algorithm_canonical"`
	Classification      pqc.QuantumStatus `json:"classification"`
	KeySizeBits         int               `json:"key_size_bits,omitempty"`
	HostID              string            `json:"host_id,omitempty"`
	Detail              string            `json:"detail,omitempty"`
}

// WeakAlgoFilter narrows the scan. Zero-valued filter returns every
// Weakened + Vulnerable occurrence across all five supported asset
// types — the default audit view.
type WeakAlgoFilter struct {
	// IncludeVulnerable + IncludeWeakened default to true when both
	// are false (so the zero-valued filter is useful).
	IncludeVulnerable bool
	IncludeWeakened   bool
	// AssetTypes limits the walk. Empty = all supported types.
	AssetTypes []string
	// Limit caps the total returned occurrences. 0 = no cap.
	Limit int
}

// ListWeakAlgorithmOccurrences walks the asset tables that directly
// carry algorithm spellings (certificates, ssh_keys, crypto_libraries,
// protocol_endpoints, crypto_configs) and emits one row per flagged
// (asset, algorithm) pair. Assets without a weak algorithm contribute
// zero rows.
//
// Classification is driven entirely by internal/analysis/pqc — so
// taxonomy updates flow through here without code changes. RSA-1024
// is flagged via a key-size guard (pqc.Classify treats raw "rsa" as
// Vulnerable regardless of bits; the ≤2047 check augments that to
// match what operators read in vendor guidance like NIST SP 800-131A).
func (s *PostgresStore) ListWeakAlgorithmOccurrences(ctx context.Context, filter WeakAlgoFilter) ([]WeakAlgoOccurrence, error) {
	// Default both classifications when caller leaves them off.
	if !filter.IncludeVulnerable && !filter.IncludeWeakened {
		filter.IncludeVulnerable = true
		filter.IncludeWeakened = true
	}

	include := func(t string) bool {
		if len(filter.AssetTypes) == 0 {
			return true
		}
		for _, x := range filter.AssetTypes {
			if x == t {
				return true
			}
		}
		return false
	}

	wantStatus := func(st pqc.QuantumStatus) bool {
		switch st {
		case pqc.QuantumVulnerable:
			return filter.IncludeVulnerable
		case pqc.QuantumWeakened:
			return filter.IncludeWeakened
		}
		return false
	}

	var out []WeakAlgoOccurrence

	// Append occurrence, honouring limit.
	append1 := func(occ WeakAlgoOccurrence) bool {
		if !wantStatus(occ.Classification) {
			return true
		}
		out = append(out, occ)
		if filter.Limit > 0 && len(out) >= filter.Limit {
			return false
		}
		return true
	}

	if include("certificate") {
		if ok, err := s.scanCertificatesForWeakAlgo(ctx, append1); err != nil {
			return nil, fmt.Errorf("weak-algo certificates: %w", err)
		} else if !ok {
			return out, nil
		}
	}
	if include("ssh_key") {
		if ok, err := s.scanSSHKeysForWeakAlgo(ctx, append1); err != nil {
			return nil, fmt.Errorf("weak-algo ssh_keys: %w", err)
		} else if !ok {
			return out, nil
		}
	}
	if include("crypto_library") {
		if ok, err := s.scanLibrariesForWeakAlgo(ctx, append1); err != nil {
			return nil, fmt.Errorf("weak-algo crypto_libraries: %w", err)
		} else if !ok {
			return out, nil
		}
	}
	if include("protocol_endpoint") {
		if ok, err := s.scanProtocolEndpointsForWeakAlgo(ctx, append1); err != nil {
			return nil, fmt.Errorf("weak-algo protocol_endpoints: %w", err)
		} else if !ok {
			return out, nil
		}
	}
	if include("crypto_config") {
		if ok, err := s.scanCryptoConfigsForWeakAlgo(ctx, append1); err != nil {
			return nil, fmt.Errorf("weak-algo crypto_configs: %w", err)
		} else if !ok {
			return out, nil
		}
	}
	return out, nil
}

// scanCertificatesForWeakAlgo emits occurrences for certificates
// whose key_algorithm OR signature_algorithm classifies as
// vulnerable/weakened. Also catches RSA-1024 (key size
// insufficient per NIST SP 800-131A) as an explicit Vulnerable
// row even though the classifier treats "rsa" as Vulnerable
// already — surfacing the key size gives operators the exact
// remediation target ("rotate to rsa-2048+"). Emit order within
// one cert is key_algo first, then sig_algo (alphabetical by
// field name for stability).
func (s *PostgresStore) scanCertificatesForWeakAlgo(ctx context.Context, emit func(WeakAlgoOccurrence) bool) (bool, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT fingerprint_sha256,
		       COALESCE(NULLIF(subject_cn, ''), fingerprint_sha256) AS label,
		       COALESCE(key_algorithm, '') AS key_algorithm,
		       COALESCE(signature_algorithm, '') AS signature_algorithm,
		       COALESCE(key_size_bits, 0) AS key_size_bits
		FROM certificates
	`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var fp, label, keyAlg, sigAlg string
		var keyBits int
		if err := rows.Scan(&fp, &label, &keyAlg, &sigAlg, &keyBits); err != nil {
			return false, err
		}
		for _, entry := range []struct{ raw, field string }{
			{keyAlg, "key_algorithm"},
			{sigAlg, "signature_algorithm"},
		} {
			if entry.raw == "" {
				continue
			}
			cls := pqc.Classify(entry.raw)
			if cls.Status != pqc.QuantumVulnerable && cls.Status != pqc.QuantumWeakened {
				continue
			}
			occ := WeakAlgoOccurrence{
				AssetType:          "certificate",
				AssetID:            fp,
				Label:              label,
				AlgorithmRaw:       entry.raw,
				AlgorithmCanonical: cls.Canonical,
				Classification:     cls.Status,
				KeySizeBits:        keyBits,
				Detail:             entry.field,
			}
			if !emit(occ) {
				return false, nil
			}
		}
		// RSA-1024 explicit flag — surface the key-size as the
		// remediation lever. The classifier already returned Vulnerable
		// for the base "rsa" spelling, so this row is additive context
		// rather than a second vulnerability count.
		if strings.EqualFold(keyAlg, "rsa") && keyBits > 0 && keyBits < 2048 {
			occ := WeakAlgoOccurrence{
				AssetType:          "certificate",
				AssetID:            fp,
				Label:              label,
				AlgorithmRaw:       fmt.Sprintf("rsa-%d", keyBits),
				AlgorithmCanonical: "rsa",
				Classification:     pqc.QuantumVulnerable,
				KeySizeBits:        keyBits,
				Detail:             "rsa key size below NIST SP 800-131A minimum (2048)",
			}
			if !emit(occ) {
				return false, nil
			}
		}
	}
	return true, rows.Err()
}

func (s *PostgresStore) scanSSHKeysForWeakAlgo(ctx context.Context, emit func(WeakAlgoOccurrence) bool) (bool, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, host_id::text,
		       COALESCE(NULLIF(file_path, ''), id::text) AS label,
		       key_type,
		       COALESCE(key_size_bits, 0) AS key_size_bits
		FROM ssh_keys
	`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, hostID, label, keyType string
		var keyBits int
		if err := rows.Scan(&id, &hostID, &label, &keyType, &keyBits); err != nil {
			return false, err
		}
		if keyType == "" {
			continue
		}
		cls := pqc.Classify(keyType)
		if cls.Status != pqc.QuantumVulnerable && cls.Status != pqc.QuantumWeakened {
			continue
		}
		occ := WeakAlgoOccurrence{
			AssetType:          "ssh_key",
			AssetID:            id,
			Label:              label,
			AlgorithmRaw:       keyType,
			AlgorithmCanonical: cls.Canonical,
			Classification:     cls.Status,
			KeySizeBits:        keyBits,
			HostID:             hostID,
		}
		if !emit(occ) {
			return false, nil
		}
		// SSH-RSA with small key size — same rationale as certs above.
		if strings.EqualFold(cls.Canonical, "rsa") && keyBits > 0 && keyBits < 2048 {
			occ := WeakAlgoOccurrence{
				AssetType:          "ssh_key",
				AssetID:            id,
				Label:              label,
				AlgorithmRaw:       fmt.Sprintf("rsa-%d", keyBits),
				AlgorithmCanonical: "rsa",
				Classification:     pqc.QuantumVulnerable,
				KeySizeBits:        keyBits,
				HostID:             hostID,
				Detail:             "ssh rsa key size below NIST SP 800-131A minimum (2048)",
			}
			if !emit(occ) {
				return false, nil
			}
		}
	}
	return true, rows.Err()
}

// scanLibrariesForWeakAlgo flags crypto_libraries by name only —
// a library's algorithm surface is emergent from its API usage, not
// its package name. True "library uses MD5" evidence lives in B3
// scanner findings, which this method does NOT walk (emit path is
// asset_health_reports.findings, handled separately). What we CAN
// flag here: libraries whose name IS a known-vulnerable primitive
// (openssl-0.9.x era binaries named "md5", "des3", etc. — rare but
// real in legacy inventories).
func (s *PostgresStore) scanLibrariesForWeakAlgo(ctx context.Context, emit func(WeakAlgoOccurrence) bool) (bool, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, host_id::text, library_name, version
		FROM crypto_libraries
	`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, hostID, name, version string
		if err := rows.Scan(&id, &hostID, &name, &version); err != nil {
			return false, err
		}
		cls := pqc.Classify(name)
		if cls.Status != pqc.QuantumVulnerable && cls.Status != pqc.QuantumWeakened {
			continue
		}
		label := name
		if version != "" {
			label = name + " " + version
		}
		occ := WeakAlgoOccurrence{
			AssetType:          "crypto_library",
			AssetID:            id,
			Label:              label,
			AlgorithmRaw:       name,
			AlgorithmCanonical: cls.Canonical,
			Classification:     cls.Status,
			HostID:             hostID,
			Detail:             "library name classifies as weak primitive",
		}
		if !emit(occ) {
			return false, nil
		}
	}
	return true, rows.Err()
}

func (s *PostgresStore) scanProtocolEndpointsForWeakAlgo(ctx context.Context, emit func(WeakAlgoOccurrence) bool) (bool, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, COALESCE(host_id::text, '') AS host_id,
		       server_ip, server_port, protocol,
		       min_tls_version_seen,
		       has_sshv1, has_null_export_cipher,
		       weak_kex_seen, weak_cipher_seen, weak_mac_seen
		FROM protocol_endpoints
	`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, hostID, serverIP, protocol string
		var port int
		var minTLS *string
		var hasSSHv1, hasNullExport bool
		var weakKex, weakCipher, weakMAC []string
		if err := rows.Scan(&id, &hostID, &serverIP, &port, &protocol, &minTLS, &hasSSHv1, &hasNullExport, &weakKex, &weakCipher, &weakMAC); err != nil {
			return false, err
		}
		label := fmt.Sprintf("%s:%d (%s)", serverIP, port, protocol)

		// SSHv1 — explicit Vulnerable flag.
		if hasSSHv1 {
			if !emit(WeakAlgoOccurrence{
				AssetType:          "protocol_endpoint",
				AssetID:            id,
				Label:              label,
				AlgorithmRaw:       "sshv1",
				AlgorithmCanonical: "sshv1",
				Classification:     pqc.QuantumVulnerable,
				HostID:             hostID,
				Detail:             "endpoint negotiates SSH protocol v1 (deprecated, cryptographically broken)",
			}) {
				return false, nil
			}
		}
		// NULL / EXPORT cipher observed.
		if hasNullExport {
			if !emit(WeakAlgoOccurrence{
				AssetType:          "protocol_endpoint",
				AssetID:            id,
				Label:              label,
				AlgorithmRaw:       "null-or-export-cipher",
				AlgorithmCanonical: "null-or-export-cipher",
				Classification:     pqc.QuantumVulnerable,
				HostID:             hostID,
				Detail:             "endpoint negotiates NULL or EXPORT cipher suite",
			}) {
				return false, nil
			}
		}
		// TLS version below 1.2 seen.
		if minTLS != nil && (*minTLS == "TLSv1" || *minTLS == "TLSv1.1" || *minTLS == "SSLv3" || *minTLS == "SSLv2") {
			if !emit(WeakAlgoOccurrence{
				AssetType:          "protocol_endpoint",
				AssetID:            id,
				Label:              label,
				AlgorithmRaw:       *minTLS,
				AlgorithmCanonical: strings.ToLower(*minTLS),
				Classification:     pqc.QuantumVulnerable,
				HostID:             hostID,
				Detail:             "endpoint negotiates TLS below 1.2 — deprecated per PCI DSS 4.0 and NIST SP 800-52",
			}) {
				return false, nil
			}
		}
		// Per-algorithm weak rows (one per observed weak value).
		for _, raw := range weakKex {
			if !emitEndpointWeakAlgo(id, label, hostID, raw, "weak KEX observed", emit) {
				return false, nil
			}
		}
		for _, raw := range weakCipher {
			if !emitEndpointWeakAlgo(id, label, hostID, raw, "weak cipher observed", emit) {
				return false, nil
			}
		}
		for _, raw := range weakMAC {
			if !emitEndpointWeakAlgo(id, label, hostID, raw, "weak MAC observed", emit) {
				return false, nil
			}
		}
	}
	return true, rows.Err()
}

// emitEndpointWeakAlgo classifies raw through pqc. Unknown-but-
// named-as-weak values are emitted as Vulnerable since the server
// listed them in a `weak_*` array — that listing IS the evidence.
func emitEndpointWeakAlgo(id, label, hostID, raw, detail string, emit func(WeakAlgoOccurrence) bool) bool {
	if raw == "" {
		return true
	}
	cls := pqc.Classify(raw)
	status := cls.Status
	canonical := cls.Canonical
	if status != pqc.QuantumVulnerable && status != pqc.QuantumWeakened {
		// The DB flagged this as weak — respect that even when the
		// taxonomy hasn't caught up yet. Operators see the value
		// verbatim with a "taxonomy-pending" remediation hint.
		status = pqc.QuantumVulnerable
		if canonical == "" {
			canonical = strings.ToLower(raw)
		}
	}
	return emit(WeakAlgoOccurrence{
		AssetType:          "protocol_endpoint",
		AssetID:            id,
		Label:              label,
		AlgorithmRaw:       raw,
		AlgorithmCanonical: canonical,
		Classification:     status,
		HostID:             hostID,
		Detail:             detail,
	})
}

// scanCryptoConfigsForWeakAlgo walks crypto_configs.settings JSONB
// looking for known weak cipher/protocol names. Settings schema
// varies by config_type (nginx/apache/envoy/openssl/etc.) — we flatten
// any string values we find, classify each, and emit hits. False
// positives are possible (a config file mentioning MD5 in a comment
// would hit); operators triage via the detail path. The per-type
// settings parsers that would give us exact semantics are follow-on
// work; for the AQ-AH-01 MVP, flat substring matching is enough
// because operators primarily want to know "which config files even
// MENTION MD5" as a first-pass audit driver.
func (s *PostgresStore) scanCryptoConfigsForWeakAlgo(ctx context.Context, emit func(WeakAlgoOccurrence) bool) (bool, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, host_id::text, config_type, file_path, settings
		FROM crypto_configs
	`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	// Canonical weak primitives to substring-search for. Intentionally
	// conservative — these are names whose appearance in a TLS or SSH
	// config is almost always a finding, not a false positive.
	needles := []string{"md5", "sha1", "rc4", "des", "3des", "export", "null-cipher", "sslv2", "sslv3", "tlsv1.0", "tlsv1.1"}
	for rows.Next() {
		var id, hostID, cfgType, filePath, settingsJSON string
		if err := rows.Scan(&id, &hostID, &cfgType, &filePath, &settingsJSON); err != nil {
			return false, err
		}
		blob := strings.ToLower(settingsJSON)
		label := cfgType + " @ " + filePath
		seen := map[string]bool{}
		for _, needle := range needles {
			if !strings.Contains(blob, needle) || seen[needle] {
				continue
			}
			seen[needle] = true
			cls := pqc.Classify(needle)
			status := cls.Status
			canonical := cls.Canonical
			if status != pqc.QuantumVulnerable && status != pqc.QuantumWeakened {
				status = pqc.QuantumVulnerable
				if canonical == "" {
					canonical = needle
				}
			}
			if !emit(WeakAlgoOccurrence{
				AssetType:          "crypto_config",
				AssetID:            id,
				Label:              label,
				AlgorithmRaw:       needle,
				AlgorithmCanonical: canonical,
				Classification:     status,
				HostID:             hostID,
				Detail:             fmt.Sprintf("config settings reference %q (substring match; triage before ticketing)", needle),
			}) {
				return false, nil
			}
		}
	}
	return true, rows.Err()
}
