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

package cbomimport

import (
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
)

// ComponentKind is the classified category of a CBOM component.
type ComponentKind int

const (
	KindSkipped ComponentKind = iota
	KindCertificate
	KindSSHKey
	KindLibrary
	KindConfig
)

// Skipped reason strings returned in ClassifiedComponent.SkipReason.
const (
	ReasonNonCryptoLibrary      = "non_crypto_library"
	ReasonUnrecognisedComponent = "unrecognised_component_type"
	ReasonMissingFingerprint    = "missing_fingerprint"
	ReasonMalformedComponent    = "malformed_component"
)

// ClassifiedComponent is the output of dispatching one cdx.Component.
// Kind indicates what came out; the matching field is populated, the
// others are nil. For KindSkipped, SkipReason is set and all asset
// pointers are nil.
type ClassifiedComponent struct {
	Kind       ComponentKind
	SkipReason string
	BOMRef     string // preserved from the source component for provenance

	Cert   *dedup.CertDiscovery
	SSHKey *dedup.SSHKeyDiscovery
	Lib    *dedup.LibraryDiscovery
	Config *dedup.ConfigDiscovery
}

// ClassifyComponent inspects a CycloneDX component and returns a
// ClassifiedComponent. Classification order:
//  1. BOMRef prefix (our own exports: cert:/sshkey:/lib:/config:/algo:)
//  2. CryptoProperties.AssetType (foreign CBOMs)
//  3. Type == ComponentTypeLibrary + name in allowlist
//  4. Everything else → Skipped (unrecognised)
func ClassifyComponent(c cdx.Component) ClassifiedComponent {
	out := ClassifiedComponent{BOMRef: c.BOMRef}

	// 1. BOMRef prefix (our own exports)
	switch {
	case strings.HasPrefix(c.BOMRef, "cert:"):
		return classifyCert(c, strings.TrimPrefix(c.BOMRef, "cert:"), out)
	case strings.HasPrefix(c.BOMRef, "sshkey:"):
		return classifySSHKey(c, strings.TrimPrefix(c.BOMRef, "sshkey:"), out)
	case strings.HasPrefix(c.BOMRef, "lib:"):
		return classifyLibrary(c, out)
	case strings.HasPrefix(c.BOMRef, "config:"):
		return classifyConfig(c, out)
	case strings.HasPrefix(c.BOMRef, "algo:"):
		out.Kind = KindSkipped
		out.SkipReason = ReasonUnrecognisedComponent // algorithms are synthetic, not scorable
		return out
	}

	// 2. CryptoProperties.AssetType (foreign CBOMs)
	if c.CryptoProperties != nil {
		switch c.CryptoProperties.AssetType {
		case cdx.CryptoAssetTypeCertificate:
			fp := fingerprintFromHashes(c.Hashes)
			return classifyCert(c, fp, out)
		case cdx.CryptoAssetTypeRelatedCryptoMaterial:
			fp := fingerprintFromHashes(c.Hashes)
			return classifySSHKey(c, fp, out)
		case cdx.CryptoAssetTypeProtocol:
			return classifyConfig(c, out)
		case cdx.CryptoAssetTypeAlgorithm:
			out.Kind = KindSkipped
			out.SkipReason = ReasonUnrecognisedComponent
			return out
		}
	}

	// 3. Library by type + name
	if c.Type == cdx.ComponentTypeLibrary {
		return classifyLibrary(c, out)
	}

	// 4. Default
	out.Kind = KindSkipped
	out.SkipReason = ReasonUnrecognisedComponent
	return out
}

func classifyCert(c cdx.Component, fingerprint string, out ClassifiedComponent) ClassifiedComponent {
	if fingerprint == "" {
		out.Kind = KindSkipped
		out.SkipReason = ReasonMissingFingerprint
		return out
	}
	cert := &dedup.CertDiscovery{
		FingerprintSHA256: strings.ToLower(fingerprint),
	}
	if c.CryptoProperties != nil && c.CryptoProperties.CertificateProperties != nil {
		cp := c.CryptoProperties.CertificateProperties
		cert.SubjectCN = cp.SubjectName
		cert.IssuerCN = cp.IssuerName
		if t, err := time.Parse(time.RFC3339, cp.NotValidBefore); err == nil {
			cert.NotBefore = t
		}
		if t, err := time.Parse(time.RFC3339, cp.NotValidAfter); err == nil {
			cert.NotAfter = t
		}
	}
	out.Kind = KindCertificate
	out.Cert = cert
	return out
}

func classifySSHKey(c cdx.Component, fingerprint string, out ClassifiedComponent) ClassifiedComponent {
	if fingerprint == "" {
		out.Kind = KindSkipped
		out.SkipReason = ReasonMissingFingerprint
		return out
	}
	k := &dedup.SSHKeyDiscovery{
		FingerprintSHA256: strings.ToLower(fingerprint),
	}
	if c.CryptoProperties != nil && c.CryptoProperties.RelatedCryptoMaterialProperties != nil {
		rp := c.CryptoProperties.RelatedCryptoMaterialProperties
		k.KeyType = sshKeyTypeFromAlgoRef(string(rp.AlgorithmRef))
		if rp.Size != nil {
			k.KeySizeBits = *rp.Size
		}
	}
	out.Kind = KindSSHKey
	out.SSHKey = k
	return out
}

func classifyLibrary(c cdx.Component, out ClassifiedComponent) ClassifiedComponent {
	if !IsCryptoLibrary(c.Name) {
		out.Kind = KindSkipped
		out.SkipReason = ReasonNonCryptoLibrary
		return out
	}
	if c.Version == "" {
		out.Kind = KindSkipped
		out.SkipReason = ReasonMalformedComponent
		return out
	}
	out.Kind = KindLibrary
	out.Lib = &dedup.LibraryDiscovery{
		LibraryName: strings.ToLower(c.Name),
		Version:     c.Version,
	}
	return out
}

func classifyConfig(c cdx.Component, out ClassifiedComponent) ClassifiedComponent {
	// A valid config component must have ProtocolProperties (so we can
	// determine config_type) and a non-empty BOMRef (so the synthetic
	// FilePath is unique enough for dedup).
	if c.CryptoProperties == nil || c.CryptoProperties.ProtocolProperties == nil {
		out.Kind = KindSkipped
		out.SkipReason = ReasonMalformedComponent
		return out
	}
	if c.BOMRef == "" {
		out.Kind = KindSkipped
		out.SkipReason = ReasonMalformedComponent
		return out
	}
	cfg := &dedup.ConfigDiscovery{
		Settings: map[string]string{},
	}
	cfg.ConfigType = configTypeFromProtocol(c.CryptoProperties.ProtocolProperties.Type)
	if cfg.ConfigType == "" {
		cfg.ConfigType = "unknown"
	}
	// FilePath is the per-host dedup key for configs; use a deterministic
	// synthetic path derived from the BOMRef (imports never have a real
	// filesystem path).
	cfg.FilePath = "cbom:" + c.BOMRef
	out.Kind = KindConfig
	out.Config = cfg
	return out
}

// fingerprintFromHashes extracts the SHA-256 hash value from a component's
// Hashes slice, or returns "" when not present.
func fingerprintFromHashes(hashes *[]cdx.Hash) string {
	if hashes == nil {
		return ""
	}
	for _, h := range *hashes {
		if h.Algorithm == cdx.HashAlgoSHA256 {
			return h.Value
		}
	}
	return ""
}

// sshKeyTypeFromAlgoRef reverses the mapping used in export:
//
//	"algo:ed25519"    → "ssh-ed25519"
//	"algo:rsa"        → "ssh-rsa"
//	"algo:ecdsa-p256" → "ecdsa-sha2-nistp256"
func sshKeyTypeFromAlgoRef(ref string) string {
	ref = strings.TrimPrefix(ref, "algo:")
	switch ref {
	case "ed25519":
		return "ssh-ed25519"
	case "rsa":
		return "ssh-rsa"
	case "ecdsa-p256":
		return "ecdsa-sha2-nistp256"
	case "ecdsa-p384":
		return "ecdsa-sha2-nistp384"
	case "ecdsa-p521":
		return "ecdsa-sha2-nistp521"
	default:
		return ref
	}
}

// configTypeFromProtocol reverses configProtocolType from export/cbom/mapper.go.
func configTypeFromProtocol(p cdx.CryptoProtocolType) string {
	switch p {
	case cdx.CryptoProtocolTypeSSH:
		return "sshd"
	case cdx.CryptoProtocolTypeTLS:
		return "openssl"
	case cdx.CryptoProtocolTypeIPSec:
		return "ipsec"
	default:
		return ""
	}
}
