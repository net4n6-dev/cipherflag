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
	"sort"
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/stretchr/testify/require"
)

func emptyReport() *model.AssetHealthReport {
	return &model.AssetHealthReport{
		Grade: "A", Score: 100, RiskScore: 0,
		PQCStatus: "safe", ScoredAt: time.Now(),
		Compliance: map[string]string{}, RiskFactors: map[string]int{},
	}
}

func TestCertToComponent_BOMRef(t *testing.T) {
	cert := &model.Certificate{
		FingerprintSHA256: "abc123",
		Subject:           model.DistinguishedName{CommonName: "example.com", Full: "CN=example.com"},
		Issuer:            model.DistinguishedName{Full: "CN=MyCA"},
		NotBefore:         time.Now().Add(-time.Hour),
		NotAfter:          time.Now().Add(365 * 24 * time.Hour),
		SignatureAlgorithm: model.SigSHA256WithRSA,
	}
	c := certToComponent(cert, emptyReport())
	if c.BOMRef != "cert:abc123" {
		t.Errorf("BOMRef = %q, want cert:abc123", c.BOMRef)
	}
	if c.Type != cdx.ComponentTypeCryptographicAsset {
		t.Errorf("Type = %v, want ComponentTypeCryptographicAsset", c.Type)
	}
	if c.CryptoProperties == nil || c.CryptoProperties.CertificateProperties == nil {
		t.Fatal("CertificateProperties must be set")
	}
	if c.CryptoProperties.CertificateProperties.CertificateFormat != "X.509" {
		t.Errorf("CertificateFormat = %q, want X.509", c.CryptoProperties.CertificateProperties.CertificateFormat)
	}
}

func TestCertToComponent_SubjectPublicKeyRef(t *testing.T) {
	cert := &model.Certificate{
		FingerprintSHA256: "fp1",
		SignatureAlgorithm: model.SigECDSAWithSHA256,
	}
	c := certToComponent(cert, emptyReport())
	if c.CryptoProperties.CertificateProperties.SubjectPublicKeyRef != "key:fp1" {
		t.Errorf("SubjectPublicKeyRef = %q, want key:fp1",
			c.CryptoProperties.CertificateProperties.SubjectPublicKeyRef)
	}
}

func TestSSHKeyToComponent_BOMRef(t *testing.T) {
	key := &model.SSHKey{
		FingerprintSHA256: "sha256:abc",
		KeyType:           "ssh-ed25519",
		KeySizeBits:       256,
		FirstSeen:         time.Now(),
		DiscoveryStatus:   "active",
	}
	c := sshKeyToComponent(key, emptyReport())
	if c.BOMRef != "sshkey:sha256:abc" {
		t.Errorf("BOMRef = %q, want sshkey:sha256:abc", c.BOMRef)
	}
	if c.CryptoProperties == nil || c.CryptoProperties.RelatedCryptoMaterialProperties == nil {
		t.Fatal("RelatedCryptoMaterialProperties must be set")
	}
	rp := c.CryptoProperties.RelatedCryptoMaterialProperties
	if rp.Type != cdx.RelatedCryptoMaterialTypePublicKey {
		t.Errorf("Type = %v, want PublicKey", rp.Type)
	}
	if rp.Size == nil || *rp.Size != 256 {
		t.Errorf("Size = %v, want 256", rp.Size)
	}
}

func TestSSHKeyToComponent_State(t *testing.T) {
	active := &model.SSHKey{FingerprintSHA256: "fp", DiscoveryStatus: "active"}
	c := sshKeyToComponent(active, emptyReport())
	if c.CryptoProperties.RelatedCryptoMaterialProperties.State != cdx.CryptoKeyStateActive {
		t.Errorf("expected active state")
	}

	inactive := &model.SSHKey{FingerprintSHA256: "fp", DiscoveryStatus: "stale"}
	c2 := sshKeyToComponent(inactive, emptyReport())
	if c2.CryptoProperties.RelatedCryptoMaterialProperties.State == cdx.CryptoKeyStateActive {
		t.Errorf("stale key should not be active")
	}
}

func TestLibToComponent_BOMRef(t *testing.T) {
	lib := &model.CryptoLibrary{
		ID: "lib-uuid-1", LibraryName: "openssl", Version: "3.0.8",
	}
	c := libToComponent(lib, emptyReport())
	if c.BOMRef != "lib:lib-uuid-1" {
		t.Errorf("BOMRef = %q, want lib:lib-uuid-1", c.BOMRef)
	}
	if c.Type != cdx.ComponentTypeLibrary {
		t.Errorf("Type = %v, want ComponentTypeLibrary", c.Type)
	}
	if c.Version != "3.0.8" {
		t.Errorf("Version = %q, want 3.0.8", c.Version)
	}
}

func TestConfigToComponent_BOMRef(t *testing.T) {
	cfg := &model.CryptoConfig{
		ID:         "cfg-uuid-1",
		ConfigType: "sshd",
		FilePath:   "/etc/ssh/sshd_config",
		Settings:   map[string]string{"Ciphers": "aes256-gcm"},
	}
	c := configToComponent(cfg, emptyReport())
	if c.BOMRef != "config:cfg-uuid-1" {
		t.Errorf("BOMRef = %q, want config:cfg-uuid-1", c.BOMRef)
	}
	if !strings.Contains(c.Name, "/etc/ssh/sshd_config") {
		t.Errorf("Name %q should contain file path", c.Name)
	}
	if c.CryptoProperties == nil || c.CryptoProperties.ProtocolProperties == nil {
		t.Fatal("ProtocolProperties must be set for config component")
	}
}

func TestAlgoToComponent_BOMRef(t *testing.T) {
	// v1.3.5 canonical-name validation: "rsa-2048" is a synonym for
	// canonical "rsa" (key size is a CycloneDX parameterSet field,
	// not part of the algorithm name). Pre-v1.3.5 this test pinned
	// the buggy behaviour where the synonym leaked into BOMRef/Name.
	c := algoToComponent("rsa-2048")
	if c.BOMRef != "algo:rsa" {
		t.Errorf("BOMRef = %q, want algo:rsa (v1.3.5 canonical normalisation)", c.BOMRef)
	}
	if c.Type != cdx.ComponentTypeCryptographicAsset {
		t.Errorf("Type = %v, want CryptographicAsset", c.Type)
	}
	if c.CryptoProperties == nil || c.CryptoProperties.AlgorithmProperties == nil {
		t.Fatal("AlgorithmProperties must be set")
	}
}

func TestCollectAlgorithms_Deduplication(t *testing.T) {
	refs := []string{"algo:rsa", "algo:sha256", "algo:rsa"} // rsa appears twice
	unique := deduplicateAlgoRefs(refs)
	if len(unique) != 2 {
		t.Errorf("expected 2 unique algo refs, got %d: %v", len(unique), unique)
	}
}

// ── annotateUnresolvedAndInferred unit tests ─────────────────────────────────

func TestAnnotateUnresolved_MarksComponentWhenRefMissing(t *testing.T) {
	// cert:leaf depends on cert:missing-ca which is NOT in the BOM.
	components := []cdx.Component{
		{
			BOMRef: "cert:leaf",
			CryptoProperties: &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeCertificate,
			},
		},
	}
	deps := []cdx.Dependency{
		{Ref: "cert:leaf", Dependencies: &[]string{"cert:missing-ca"}},
	}
	inBom := map[string]bool{"cert:leaf": true}

	out := annotateUnresolvedAndInferred(components, deps, inBom, emptyIssuanceLookup{})

	found := false
	for _, p := range *out[0].Properties {
		if p.Name == "cipherflag:dep.unresolved" && p.Value == "true" {
			found = true
		}
	}
	if !found {
		t.Error("expected cipherflag:dep.unresolved=true on cert:leaf")
	}
}

func TestAnnotateUnresolved_NoAnnotationWhenAllRefsPresent(t *testing.T) {
	components := []cdx.Component{
		{BOMRef: "cert:leaf", CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeCertificate}},
		{BOMRef: "cert:ca"},
	}
	deps := []cdx.Dependency{
		{Ref: "cert:leaf", Dependencies: &[]string{"cert:ca"}},
	}
	inBom := map[string]bool{"cert:leaf": true, "cert:ca": true}

	out := annotateUnresolvedAndInferred(components, deps, inBom, emptyIssuanceLookup{})

	// cert:leaf should have no Properties (nil or empty).
	for _, c := range out {
		if c.BOMRef != "cert:leaf" {
			continue
		}
		if c.Properties == nil {
			break
		}
		for _, p := range *c.Properties {
			if p.Name == "cipherflag:dep.unresolved" {
				t.Errorf("unexpected cipherflag:dep.unresolved property on cert:leaf; all refs are in BOM")
			}
		}
	}
}

func TestAnnotateInferred_MarksComponentWhenLinkIsInferred(t *testing.T) {
	components := []cdx.Component{
		{BOMRef: "cert:leaf", CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeCertificate}},
		{BOMRef: "cert:ca"},
	}
	deps := []cdx.Dependency{
		{Ref: "cert:leaf", Dependencies: &[]string{"cert:ca"}},
	}
	inBom := map[string]bool{"cert:leaf": true, "cert:ca": true}
	lookup := stubIssuanceLookup{
		parents: map[string][]parentLink{
			"leaf": {{parent: "ca", method: "cn_match", confidence: "inferred"}},
		},
	}

	out := annotateUnresolvedAndInferred(components, deps, inBom, lookup)

	found := false
	for _, c := range out {
		if c.BOMRef != "cert:leaf" || c.Properties == nil {
			continue
		}
		for _, p := range *c.Properties {
			if p.Name == "cipherflag:dep.confidence" && p.Value == "inferred" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected cipherflag:dep.confidence=inferred on cert:leaf")
	}
}

func TestAnnotateInferred_NoAnnotationWhenLinkIsAttested(t *testing.T) {
	components := []cdx.Component{
		{BOMRef: "cert:leaf", CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeCertificate}},
		{BOMRef: "cert:ca"},
	}
	deps := []cdx.Dependency{
		{Ref: "cert:leaf", Dependencies: &[]string{"cert:ca"}},
	}
	inBom := map[string]bool{"cert:leaf": true, "cert:ca": true}
	lookup := stubIssuanceLookup{
		parents: map[string][]parentLink{
			"leaf": {{parent: "ca", method: "aki_ski_match", confidence: "attested"}},
		},
	}

	out := annotateUnresolvedAndInferred(components, deps, inBom, lookup)

	for _, c := range out {
		if c.BOMRef != "cert:leaf" || c.Properties == nil {
			continue
		}
		for _, p := range *c.Properties {
			if p.Name == "cipherflag:dep.confidence" {
				t.Errorf("unexpected cipherflag:dep.confidence property for attested link")
			}
		}
	}
}

// ── Task 7: OID / NQSL / ParameterSetIdentifier / CryptoFunctions ───────────

func TestAlgoToComponent_PopulatesOIDAndNQSL(t *testing.T) {
	c := algoToComponent("ml-kem-768")
	require.NotNil(t, c.CryptoProperties)
	require.NotNil(t, c.CryptoProperties.AlgorithmProperties)
	ap := c.CryptoProperties.AlgorithmProperties
	// OID lives on CryptoProperties, not AlgorithmProperties.
	require.Equal(t, "2.16.840.1.101.3.4.4.2", c.CryptoProperties.OID)
	require.NotNil(t, ap.NistQuantumSecurityLevel)
	require.Equal(t, 3, *ap.NistQuantumSecurityLevel)
	require.Equal(t, "ML-KEM-768", ap.ParameterSetIdentifier)
}

func TestAlgoToComponent_ClassicalRSAHasOIDNoNQSL(t *testing.T) {
	c := algoToComponent("rsa")
	ap := c.CryptoProperties.AlgorithmProperties
	require.Equal(t, "1.2.840.113549.1.1.1", c.CryptoProperties.OID)
	require.Nil(t, ap.NistQuantumSecurityLevel,
		"classical algorithms must omit nistQuantumSecurityLevel (nil pointer, not zero value)")
}

func TestAlgoToComponent_CryptoFunctionsForKEM(t *testing.T) {
	c := algoToComponent("ml-kem-768")
	ap := c.CryptoProperties.AlgorithmProperties
	require.NotNil(t, ap.CryptoFunctions)
	funcs := *ap.CryptoFunctions
	sort.Slice(funcs, func(i, j int) bool { return string(funcs[i]) < string(funcs[j]) })
	require.Equal(t, []cdx.CryptoFunction{
		cdx.CryptoFunctionDecapsulate,
		cdx.CryptoFunctionEncapsulate,
		cdx.CryptoFunctionKeygen,
	}, funcs)
}

func TestAlgoToComponent_CryptoFunctionsForRSA(t *testing.T) {
	c := algoToComponent("rsa")
	ap := c.CryptoProperties.AlgorithmProperties
	require.NotNil(t, ap.CryptoFunctions)
	funcs := *ap.CryptoFunctions
	sort.Slice(funcs, func(i, j int) bool { return string(funcs[i]) < string(funcs[j]) })
	// RSA is multi-purpose: signing + encryption + keygen.
	require.Contains(t, funcs, cdx.CryptoFunctionSign)
	require.Contains(t, funcs, cdx.CryptoFunctionVerify)
	require.Contains(t, funcs, cdx.CryptoFunctionEncrypt)
	require.Contains(t, funcs, cdx.CryptoFunctionDecrypt)
	require.Contains(t, funcs, cdx.CryptoFunctionKeygen)
}

func TestAlgoToComponent_UnknownAlgoOmitsOID(t *testing.T) {
	c := algoToComponent("never-heard-of-it")
	ap := c.CryptoProperties.AlgorithmProperties
	require.Empty(t, c.CryptoProperties.OID, "unknown algorithm should omit OID field (not empty string)")
	require.Nil(t, ap.NistQuantumSecurityLevel)
}

// ── Task 10: mode + padding on Algorithm components ──────────────────────────

func TestAlgoToComponent_ModeFromSuiteContext(t *testing.T) {
	// When the algorithm component is constructed in a TLS suite context,
	// the mode is set from suite decomposition.
	c := algoToComponentWithContext("aes-128", &algoContext{TLSSuite: "TLS_AES_128_GCM_SHA256"})
	require.NotNil(t, c.CryptoProperties)
	require.NotNil(t, c.CryptoProperties.AlgorithmProperties)
	ap := c.CryptoProperties.AlgorithmProperties
	require.Equal(t, cdx.CryptoAlgorithmModeGCM, ap.Mode)
}

func TestAlgoToComponent_ModeFromSuiteContext_CBC(t *testing.T) {
	c := algoToComponentWithContext("aes-128", &algoContext{TLSSuite: "TLS_RSA_WITH_AES_128_CBC_SHA"})
	ap := c.CryptoProperties.AlgorithmProperties
	require.Equal(t, cdx.CryptoAlgorithmModeCBC, ap.Mode)
}

func TestAlgoToComponent_NoModeWhenStandalone(t *testing.T) {
	c := algoToComponentWithContext("aes-128", nil)
	ap := c.CryptoProperties.AlgorithmProperties
	require.Empty(t, ap.Mode, "standalone AES observation has no mode")
}

func TestAlgoToComponent_NoModeWhenSuiteHasNoMode(t *testing.T) {
	// CHACHA20_POLY1305 has no block-cipher mode; Mode must remain empty.
	c := algoToComponentWithContext("chacha20-poly1305", &algoContext{TLSSuite: "TLS_CHACHA20_POLY1305_SHA256"})
	ap := c.CryptoProperties.AlgorithmProperties
	require.Empty(t, ap.Mode, "ChaCha20-Poly1305 has no block-cipher mode")
}

func TestPaddingFromSigAlg_PKCS1v15(t *testing.T) {
	cases := []model.SignatureAlgorithm{
		model.SigSHA256WithRSA,
		model.SigSHA384WithRSA,
		model.SigSHA512WithRSA,
		model.SigSHA1WithRSA,
		model.SigMD5WithRSA,
	}
	for _, alg := range cases {
		padding, detail := paddingFromSigAlg(alg)
		require.Equal(t, cdx.CryptoPaddingPKCS1v15, padding, "sig alg %q should yield PKCS1v15", alg)
		require.Empty(t, detail, "PKCS1v15 padding carries no extra detail for %q", alg)
	}
}

func TestPaddingFromSigAlg_ECDSAAndEdDSAYieldNoPadding(t *testing.T) {
	cases := []model.SignatureAlgorithm{
		model.SigECDSAWithSHA256,
		model.SigECDSAWithSHA384,
		model.SigEd25519Sig,
		model.SigUnknown,
	}
	for _, alg := range cases {
		padding, detail := paddingFromSigAlg(alg)
		require.Empty(t, padding, "sig alg %q should yield empty padding", alg)
		require.Empty(t, detail)
	}
}

func TestCertSigAlgoComponent_PaddingSet(t *testing.T) {
	cert := &model.Certificate{
		FingerprintSHA256:  "abc",
		SignatureAlgorithm: model.SigSHA256WithRSA,
	}
	c := certSigAlgoComponent(cert)
	require.NotNil(t, c.CryptoProperties)
	require.NotNil(t, c.CryptoProperties.AlgorithmProperties)
	ap := c.CryptoProperties.AlgorithmProperties
	require.Equal(t, cdx.CryptoPaddingPKCS1v15, ap.Padding,
		"SHA256WithRSA should set PKCS1v15 padding on the algo component")
	// No padding.detail property for PKCS1v15.
	if c.Properties != nil {
		for _, p := range *c.Properties {
			require.NotEqual(t, "cipherflag:padding.detail", p.Name,
				"PKCS1v15 must not emit padding.detail property")
		}
	}
}

func TestCertSigAlgoComponent_NoPaddingForECDSA(t *testing.T) {
	cert := &model.Certificate{
		FingerprintSHA256:  "def",
		SignatureAlgorithm: model.SigECDSAWithSHA256,
	}
	c := certSigAlgoComponent(cert)
	ap := c.CryptoProperties.AlgorithmProperties
	require.Empty(t, ap.Padding, "ECDSA does not use padding")
}
