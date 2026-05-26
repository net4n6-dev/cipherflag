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

package cbom

import (
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/analysis/pqc"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

// buildBOMRefSet returns a set of all BOMRefs present in the component slice.
// Used to detect unresolved dependency refs after computeDependencies.
func buildBOMRefSet(components []cdx.Component) map[string]bool {
	m := make(map[string]bool, len(components))
	for _, c := range components {
		if c.BOMRef != "" {
			m[c.BOMRef] = true
		}
	}
	return m
}

// annotateUnresolvedAndInferred walks the dependency edges and adds
// Property annotations to the source component when:
//   - cipherflag:dep.unresolved=true — at least one dependsOn ref points
//     to a BOMRef not present in this BOM (e.g. an issuing CA outside
//     the application's scope). Signals consumers that cross-BOM stitching
//     is needed to fully resolve the chain.
//   - cipherflag:dep.confidence=inferred — the component is a cert that
//     has at least one parent link with LinkConfidence=="inferred". Signals
//     that the chain link was derived heuristically (CN match), not from
//     AKI/SKI byte equality.
//
// The function modifies the components slice in-place and returns it.
func annotateUnresolvedAndInferred(
	components []cdx.Component,
	deps []cdx.Dependency,
	inBom map[string]bool,
	lookup IssuanceLookupForCBOM,
) []cdx.Component {
	for _, d := range deps {
		if d.Dependencies == nil {
			continue
		}
		var hasUnresolved, hasInferred bool
		for _, ref := range *d.Dependencies {
			if !inBom[ref] {
				hasUnresolved = true
			}
		}
		if fp := strings.TrimPrefix(d.Ref, "cert:"); fp != d.Ref {
			for _, p := range lookup.ListParentsForCertCBOM(fp) {
				if p.LinkConfidence == "inferred" {
					hasInferred = true
					break
				}
			}
		}
		if !hasUnresolved && !hasInferred {
			continue
		}
		idx := indexOfBOMRef(components, d.Ref)
		if idx < 0 {
			continue
		}
		if components[idx].Properties == nil {
			components[idx].Properties = &[]cdx.Property{}
		}
		if hasUnresolved {
			*components[idx].Properties = append(*components[idx].Properties,
				cdx.Property{Name: "cipherflag:dep.unresolved", Value: "true"})
		}
		if hasInferred {
			*components[idx].Properties = append(*components[idx].Properties,
				cdx.Property{Name: "cipherflag:dep.confidence", Value: "inferred"})
		}
	}
	return components
}

// indexOfBOMRef returns the index of the first component with the given BOMRef,
// or -1 if not found.
func indexOfBOMRef(components []cdx.Component, ref string) int {
	for i, c := range components {
		if c.BOMRef == ref {
			return i
		}
	}
	return -1
}

// logUnresolvedDeps emits a single WARN log when more than 10% of components
// that have Properties carry the cipherflag:dep.unresolved=true annotation.
// This is an operator signal that the inventory is missing PKI sources (CT-log
// backfill, additional certificate scanners) and cross-BOM stitching will fail
// for a significant fraction of the chain.
func logUnresolvedDeps(components []cdx.Component, bomScope string) {
	var total, unresolved int
	for _, c := range components {
		if c.Properties == nil {
			continue
		}
		total++
		for _, p := range *c.Properties {
			if p.Name == "cipherflag:dep.unresolved" && p.Value == "true" {
				unresolved++
				break
			}
		}
	}
	if total == 0 {
		return
	}
	ratio := float64(unresolved) / float64(total)
	if ratio < 0.10 {
		return
	}
	log.Warn().
		Str("bom_scope", bomScope).
		Int("unresolved", unresolved).
		Int("total", total).
		Float64("ratio", ratio).
		Msg("CBOM emitted with >10% unresolved external dependency refs — consider ingesting more PKI sources (CT backfill, additional certificate scanners)")
}

// certToComponent converts a Certificate + its health report to a CycloneDX component.
func certToComponent(cert *model.Certificate, r *model.AssetHealthReport) cdx.Component {
	props := buildCipherFlagProps(r)
	cp := &cdx.CertificateProperties{
		SubjectName:           cert.Subject.Full,
		IssuerName:            cert.Issuer.Full,
		NotValidBefore:        cert.NotBefore.UTC().Format(time.RFC3339),
		NotValidAfter:         cert.NotAfter.UTC().Format(time.RFC3339),
		SignatureAlgorithmRef: cdx.BOMReference(bomRefForAlgo(string(cert.SignatureAlgorithm))),
		SubjectPublicKeyRef:   cdx.BOMReference("key:" + cert.FingerprintSHA256),
		CertificateFormat:     "X.509",
		CertificateExtension:  "pem",
	}
	return cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		BOMRef: "cert:" + cert.FingerprintSHA256,
		Name:   cert.Subject.CommonName,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:             cdx.CryptoAssetTypeCertificate,
			CertificateProperties: cp,
		},
		Properties: &props,
	}
}

// sshKeyToComponent converts an SSHKey + health report to a CycloneDX component.
func sshKeyToComponent(key *model.SSHKey, r *model.AssetHealthReport) cdx.Component {
	size := key.KeySizeBits
	props := buildCipherFlagProps(r)
	rp := &cdx.RelatedCryptoMaterialProperties{
		Type:         cdx.RelatedCryptoMaterialTypePublicKey,
		AlgorithmRef: cdx.BOMReference(bomRefForSSHKeyType(key.KeyType)),
		Size:         &size,
		CreationDate: key.FirstSeen.UTC().Format(time.RFC3339),
		State:        sshKeyState(key),
	}
	name := "SSH key " + key.FingerprintSHA256
	if len(key.FingerprintSHA256) > 16 {
		name = "SSH key " + key.FingerprintSHA256[:16]
	}
	return cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		BOMRef: "sshkey:" + key.FingerprintSHA256,
		Name:   name,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:                       cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: rp,
		},
		Properties: &props,
	}
}

// libToComponent converts a CryptoLibrary + health report to a CycloneDX component.
func libToComponent(lib *model.CryptoLibrary, r *model.AssetHealthReport) cdx.Component {
	props := buildCipherFlagProps(r)
	return cdx.Component{
		Type:       cdx.ComponentTypeLibrary,
		BOMRef:     "lib:" + lib.ID,
		Name:       lib.LibraryName,
		Version:    lib.Version,
		Properties: &props,
	}
}

// configToComponent converts a CryptoConfig + health report to a CycloneDX component.
func configToComponent(cfg *model.CryptoConfig, r *model.AssetHealthReport) cdx.Component {
	props := buildCipherFlagProps(r)
	suites := extractCiphers(cfg.Settings)
	pp := &cdx.CryptoProtocolProperties{
		Type:         configProtocolType(cfg.ConfigType),
		CipherSuites: suites,
	}
	return cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		BOMRef: "config:" + cfg.ID,
		Name:   cfg.ConfigType + " @ " + cfg.FilePath,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:          cdx.CryptoAssetTypeProtocol,
			ProtocolProperties: pp,
		},
		Properties: &props,
	}
}

// algoToComponent produces a deduplicated algorithm component from a
// raw algorithm name. Resolves the raw string through the PQC catalog
// (canonical lookup + synonym fallback); when the name is not in the
// taxonomy the component is STILL emitted so the inventory doesn't
// lose data, but is annotated with
// `cipherflag:algo.canonical_match=false` so auditors and CBOM
// consumers can filter to drifted names without parsing strings.
//
// Known (catalog-resolved) names omit the property — its presence is
// the drift signal.
//
// Canonical names are always lowercase (pqc.Canonical normalises via
// strings.ToLower). That convention is load-bearing for downstream
// assertions — e.g. CBOM consumers compare `c.Name == "md5"`, not
// `"MD5"`. Preserve casing only for uncatalogued names, where the
// drifted component's spelling helps the operator grep for source.
func algoToComponent(rawName string) cdx.Component {
	canonical, ok := canonicalName(rawName)
	name := canonical
	bomRef := "algo:" + canonical
	var props *[]cdx.Property
	if !ok {
		// Preserve the caller's spelling for operator grep-ability;
		// lowercase the BOMRef so intra-BOM dedup stays stable even
		// when two upstream paths pass different casings of the same
		// unknown name.
		name = rawName
		bomRef = "algo:" + strings.ToLower(rawName)
		props = &[]cdx.Property{
			{Name: "cipherflag:algo.canonical_match", Value: "false"},
		}
	}
	classification := pqc.Classify(rawName)
	ap := &cdx.CryptoAlgorithmProperties{
		Primitive: primitiveFromClassification(classification),
	}

	// NIST quantum security level — only for PQC (SecurityLevel > 0).
	// The library field is *int; pqc.Classification.SecurityLevel is uint8.
	if classification.SecurityLevel > 0 {
		level := int(classification.SecurityLevel)
		ap.NistQuantumSecurityLevel = &level
	}

	// Parameter set identifier — derived from canonical name for
	// PQC and curve-parameterised classical algorithms.
	if paramSet := parameterSetID(canonical); paramSet != "" {
		ap.ParameterSetIdentifier = paramSet
	}

	// Crypto functions from category.
	if funcs := cryptoFunctionsForCategory(classification.Category); len(funcs) > 0 {
		ap.CryptoFunctions = &funcs
	}

	// OID lives on CryptoProperties (not AlgorithmProperties) in
	// cyclonedx-go v0.10.0 — omit when unknown.
	cp := &cdx.CryptoProperties{
		AssetType:           cdx.CryptoAssetTypeAlgorithm,
		AlgorithmProperties: ap,
	}
	if oid, ok := pqc.OID(canonical); ok {
		cp.OID = oid
	}

	return cdx.Component{
		Type:             cdx.ComponentTypeCryptographicAsset,
		BOMRef:           bomRef,
		Name:             name,
		CryptoProperties: cp,
		Properties:       props,
	}
}

// algoContext carries optional call-site context that enriches the
// algorithm component beyond what the raw name alone can provide.
// The zero value (nil pointer) is always valid — callers that have no
// context pass nil and algoToComponentWithContext behaves identically to
// algoToComponent.
type algoContext struct {
	// TLSSuite is the IANA TLS cipher suite name (e.g. "TLS_AES_128_GCM_SHA256").
	// When non-empty, the suite is decomposed and the bulk-cipher mode is
	// applied to the CryptoAlgorithmProperties.Mode field.
	TLSSuite string
}

// algoToComponentWithContext is the context-aware variant of algoToComponent.
// It delegates to algoToComponent for all base fields, then enriches the
// component using information in ctx:
//
//   - ctx.TLSSuite → populates CryptoAlgorithmProperties.Mode for symmetric
//     block-cipher algorithms when the suite specifies a mode (GCM, CBC, …).
//     Stream ciphers (ChaCha20-Poly1305) and hash/KEX/sig algorithms emit
//     no mode even when a suite is present.
//
// Callers in the protocol-component emit path use this function; the
// standalone algorithm-component emit path continues to use algoToComponent.
func algoToComponentWithContext(rawName string, ctx *algoContext) cdx.Component {
	c := algoToComponent(rawName)
	if ctx == nil || ctx.TLSSuite == "" {
		return c
	}
	d := DecomposeTLSSuite(ctx.TLSSuite)
	if d.Mode != "" && c.CryptoProperties != nil && c.CryptoProperties.AlgorithmProperties != nil {
		c.CryptoProperties.AlgorithmProperties.Mode = mapModeStringToCDX(d.Mode)
	}
	return c
}

// mapModeStringToCDX converts a lowercase mode token (from SuiteDecomposition.Mode)
// to the corresponding CycloneDX CryptoAlgorithmMode constant.
// Returns the empty string (omitted in JSON/XML) for any unrecognised token.
func mapModeStringToCDX(s string) cdx.CryptoAlgorithmMode {
	switch s {
	case "gcm":
		return cdx.CryptoAlgorithmModeGCM
	case "cbc":
		return cdx.CryptoAlgorithmModeCBC
	case "ccm":
		return cdx.CryptoAlgorithmModeCCM
	case "ctr":
		return cdx.CryptoAlgorithmModeCTR
	case "ecb":
		return cdx.CryptoAlgorithmModeECB
	case "cfb":
		return cdx.CryptoAlgorithmModeCFB
	case "ofb":
		return cdx.CryptoAlgorithmModeOFB
	default:
		return "" // unknown or stream cipher — omit
	}
}

// paddingFromSigAlg derives the CycloneDX padding enum and an optional
// detail string from an X.509 certificate signature algorithm.
//
// RSA signatures using PKCS#1 v1.5 map to CryptoPaddingPKCS1v15 with no
// extra detail. ECDSA and EdDSA algorithms use no padding — empty values
// are returned and the caller must omit the padding field. RSA-PSS would
// return CryptoPaddingOther + "pss", but no current model constant exists
// for RSA-PSS; this branch is included for forward compatibility.
//
// The returned detail string, when non-empty, should be emitted as a
// cipherflag:padding.detail Property on the algorithm component.
func paddingFromSigAlg(sigAlg model.SignatureAlgorithm) (cdx.CryptoPadding, string) {
	switch sigAlg {
	case model.SigSHA256WithRSA,
		model.SigSHA384WithRSA,
		model.SigSHA512WithRSA,
		model.SigSHA1WithRSA,
		model.SigMD5WithRSA:
		return cdx.CryptoPaddingPKCS1v15, ""
	default:
		// ECDSA, EdDSA, Unknown — no padding concept applies.
		return "", ""
	}
}

// certSigAlgoComponent builds an algorithm component for the cert's
// SignatureAlgorithm, enriched with the CryptoPadding derived from the
// signature scheme. This is the wiring point for Task 10 padding support:
// the cert emit path calls this function instead of bare algoToComponent
// when it needs to produce the algorithm component alongside the cert.
//
// The returned component has the same BOMRef as algoToComponent would
// produce for the same raw algorithm string, ensuring deduplication across
// BOMs that mix cert and protocol components referencing the same algorithm.
func certSigAlgoComponent(cert *model.Certificate) cdx.Component {
	c := algoToComponent(string(cert.SignatureAlgorithm))
	padding, detail := paddingFromSigAlg(cert.SignatureAlgorithm)
	if padding != "" && c.CryptoProperties != nil && c.CryptoProperties.AlgorithmProperties != nil {
		c.CryptoProperties.AlgorithmProperties.Padding = padding
		if detail != "" {
			prop := cdx.Property{
				Name:  "cipherflag:padding.detail",
				Value: detail,
			}
			if c.Properties == nil {
				c.Properties = &[]cdx.Property{prop}
			} else {
				*c.Properties = append(*c.Properties, prop)
			}
		}
	}
	return c
}

// canonicalName is the package-private wrapper over pqc.Canonical used
// by algoToComponent and the validator tests. Keeps the drift-detection
// surface colocated with the emit path.
func canonicalName(raw string) (string, bool) {
	return pqc.Canonical(raw)
}

// logAlgorithmDrift emits a single WARN log when ≥1 algorithm
// component in the assembled BOM carries the canonical-match=false
// drift signal. Gives operators a visible signal at export time —
// property-level annotation alone requires inspecting every component.
// bomScope is a short human label for the log ("scope:<name>",
// "application:<tag>", "repo:<id>") so operators can correlate.
func logAlgorithmDrift(components []cdx.Component, bomScope string) {
	var drifted []string
	for _, c := range components {
		if c.Properties == nil {
			continue
		}
		for _, p := range *c.Properties {
			if p.Name == "cipherflag:algo.canonical_match" && p.Value == "false" {
				drifted = append(drifted, c.Name)
				break
			}
		}
	}
	if len(drifted) == 0 {
		return
	}
	log.Warn().
		Str("bom_scope", bomScope).
		Strs("uncatalogued_algorithms", drifted).
		Int("count", len(drifted)).
		Msg("CBOM emitted with uncatalogued algorithm names — PQC taxonomy drift; consider extending internal/analysis/pqc/catalog.go or synonyms.go")
}

// deduplicateAlgoRefs removes duplicate BOM references from a slice.
func deduplicateAlgoRefs(refs []string) []string {
	seen := make(map[string]struct{}, len(refs))
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		if _, ok := seen[r]; !ok {
			seen[r] = struct{}{}
			out = append(out, r)
		}
	}
	return out
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func bomRefForAlgo(rawAlgo string) string {
	c := pqc.Classify(rawAlgo)
	if c.Canonical != "" {
		return "algo:" + c.Canonical
	}
	return "algo:" + strings.ToLower(rawAlgo)
}

// bomRefForSSHKeyType resolves an SSH key-type identifier (ssh-rsa,
// ecdsa-sha2-nistp256, ssh-ed25519, etc.) to its algorithm BOMRef.
//
// Routes through pqc.Canonical so the ref matches the one
// algoToComponent will emit for the same name — if the two sides
// disagree, the SSH key's AlgorithmRef dangles against a BOMRef that
// isn't in the same BOM. Prior to v1.3.7 this function hardcoded a
// switch that used synonym spellings (e.g. "algo:ecdsa-p256") while
// v1.3.5's algoToComponent canonicalised to "algo:ecdsa"; the
// reference was broken for every ECDSA + Ed448 SSH key.
//
// Unknown key types still return a lowercased-raw ref so the drift
// shows up in the BOM (and the uncatalogued-algo WARN log) rather
// than being silently dropped.
func bomRefForSSHKeyType(keyType string) string {
	if canonical, ok := pqc.Canonical(keyType); ok {
		return "algo:" + canonical
	}
	return "algo:" + strings.ToLower(keyType)
}

func sshKeyState(key *model.SSHKey) cdx.CryptoKeyState {
	if key.DiscoveryStatus == "active" {
		return cdx.CryptoKeyStateActive
	}
	return cdx.CryptoKeyStateSuspended
}

func configProtocolType(configType string) cdx.CryptoProtocolType {
	switch strings.ToLower(configType) {
	case "ssh", "sshd":
		return cdx.CryptoProtocolTypeSSH
	case "tls", "https", "nginx", "apache":
		return cdx.CryptoProtocolTypeTLS
	case "ipsec":
		return cdx.CryptoProtocolTypeIPSec
	default:
		return cdx.CryptoProtocolTypeOther
	}
}

// extractCiphers reads cipher suite names from a Settings map.
// Checks common keys: "Ciphers", "ssl_ciphers", "CipherSuites".
func extractCiphers(settings map[string]string) *[]cdx.CipherSuite {
	keys := []string{"Ciphers", "ssl_ciphers", "CipherSuites", "cipher_suites"}
	for _, k := range keys {
		if v, ok := settings[k]; ok && v != "" {
			parts := strings.Split(v, ":")
			suites := make([]cdx.CipherSuite, 0, len(parts))
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" {
					suites = append(suites, cdx.CipherSuite{Name: p})
				}
			}
			if len(suites) > 0 {
				return &suites
			}
		}
	}
	return nil
}

func primitiveFromClassification(c pqc.Classification) cdx.CryptoPrimitive {
	// ed25519, ed448, and ecdsa are signature algorithms even though catalogued as Asymmetric
	switch c.Canonical {
	case "ed25519", "ed448", "ecdsa", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521":
		return cdx.CryptoPrimitiveSignature
	}
	switch c.Category {
	case pqc.CategoryAsymmetric:
		return cdx.CryptoPrimitivePKE
	case pqc.CategorySignature:
		return cdx.CryptoPrimitiveSignature
	case pqc.CategorySymmetric:
		return cdx.CryptoPrimitiveBlockCipher
	case pqc.CategoryHash:
		return cdx.CryptoPrimitiveHash
	case pqc.CategoryKEX:
		return cdx.CryptoPrimitiveKeyAgree
	case pqc.CategoryKDF:
		return cdx.CryptoPrimitiveKDF
	case pqc.CategoryPQCKEM:
		return cdx.CryptoPrimitiveKEM
	case pqc.CategoryPQCSig:
		return cdx.CryptoPrimitiveSignature
	default:
		return cdx.CryptoPrimitiveUnknown
	}
}

// parameterSetID derives the standard parameter-set identifier for an
// algorithm canonical name. Returns empty string when the canonical name
// has no meaningful parameter-set labelling (e.g. bare "rsa", "sha256").
//
// PQC names encode the parameter set directly (ml-kem-768 → ML-KEM-768
// per FIPS 203 naming). ECDSA curve variants and AES key-size variants
// are also parameterised and get the uppercase form.
func parameterSetID(canonical string) string {
	if strings.HasPrefix(canonical, "ml-kem-") ||
		strings.HasPrefix(canonical, "ml-dsa-") ||
		strings.HasPrefix(canonical, "slh-dsa-") {
		return strings.ToUpper(canonical)
	}
	if strings.HasPrefix(canonical, "rsa-") {
		return strings.ToUpper(canonical)
	}
	if strings.HasPrefix(canonical, "ecdsa-") {
		return strings.ToUpper(canonical)
	}
	if strings.HasPrefix(canonical, "aes-") {
		return strings.ToUpper(canonical)
	}
	return ""
}

// cryptoFunctionsForCategory maps a pqc.Category to the standard set of
// CycloneDX CryptoFunction values for that algorithm family.
//
// Constants are from cyclonedx-go v0.10.0:
//   - CryptoFunctionKeyderive  (not KeyDerive or KeyDerivation)
//   - CryptoFunctionKeygen     (not KeyGen)
func cryptoFunctionsForCategory(c pqc.Category) []cdx.CryptoFunction {
	switch c {
	case pqc.CategorySignature, pqc.CategoryPQCSig:
		return []cdx.CryptoFunction{cdx.CryptoFunctionSign, cdx.CryptoFunctionVerify}
	case pqc.CategoryPQCKEM:
		return []cdx.CryptoFunction{
			cdx.CryptoFunctionEncapsulate,
			cdx.CryptoFunctionDecapsulate,
			cdx.CryptoFunctionKeygen,
		}
	case pqc.CategorySymmetric:
		return []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt}
	case pqc.CategoryHash:
		return []cdx.CryptoFunction{cdx.CryptoFunctionDigest}
	case pqc.CategoryKDF:
		return []cdx.CryptoFunction{cdx.CryptoFunctionKeyderive}
	case pqc.CategoryKEX:
		return []cdx.CryptoFunction{cdx.CryptoFunctionKeygen}
	case pqc.CategoryAsymmetric:
		// RSA and classical asymmetric: multi-purpose (sign, verify,
		// encrypt, decrypt, keygen).
		return []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
			cdx.CryptoFunctionEncrypt,
			cdx.CryptoFunctionDecrypt,
			cdx.CryptoFunctionKeygen,
		}
	}
	return nil
}
