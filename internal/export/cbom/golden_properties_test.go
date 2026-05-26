//go:build integration

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
	"path/filepath"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

// Property tests for the L4-E CBOM golden-suite. These run on the
// live *cdx.BOM (before marshalling) so they catch shape regressions
// independently of the byte goldens in scope_rich.json /
// application_rich.json / repo_rich.json.
//
// Adaptations from the original plan (2026-05-16-l4-e-cbom-golden-suite.md
// Task 8) were necessary because the implementation discoveries during
// Tasks 5-7 revealed that:
//
//   (a) The production emit path does NOT add a
//       `cipherflag:fingerprint_sha256` property to certificate
//       components. The cert fingerprint is encoded in the BOMRef
//       (`cert:<fingerprint>`) per mapper.go:144. Property 1 below
//       adapts to that reality.
//
//   (b) The rich seed (seedPKIScenarioForCBOMRich) inserts NO SSH
//       keys, so no `related-crypto-material` components are emitted
//       (those come from sshKeyToComponent in mapper.go:155). The
//       original Property 5 — iterating related-crypto-material refs
//       — would be vacuous. We instead walk the BOM's dependency graph
//       and assert every `cert:` reference there resolves to a cert
//       component, with one documented exception:
//       cert:cbom-rich-shadow-issuer-1 is the orphan-CA dangling-ref
//       case the rich seed exercises on purpose (the issuer has a
//       health report but no asset_provenance row, so the cert is
//       excluded from scope-by-host enumeration; cf.
//       cbom_testhelper_rich_test.go:262-275 and the discussion in
//       Task 8's plan note).
//
// Property 2's "at least one AlgorithmProperties field is populated"
// will trivially hold in current emit code (mapper.go:246-248 always
// sets Primitive, even to CryptoPrimitiveUnknown), but the assertion
// guards against a regression that deletes that initialisation.

// shadowIssuerDanglingRef is the single tolerated dangling cert-ref in
// the rich-seed BOM dependencies. See the package comment above.
const shadowIssuerDanglingRef = "cert:cbom-rich-shadow-issuer-1"

// certFingerprints extracts the set of cert fingerprints from a BOM by
// reading BOMRefs of every Component whose CryptoProperties.AssetType
// is "certificate". Returns the fingerprint substring after the "cert:"
// prefix (mapper.go:144 emits `BOMRef: "cert:" + cert.FingerprintSHA256`).
// Used by Property 4 to compare full-scope vs app-scope cert sets.
func certFingerprints(bom *cdx.BOM) map[string]struct{} {
	out := map[string]struct{}{}
	if bom == nil || bom.Components == nil {
		return out
	}
	for _, c := range *bom.Components {
		if c.CryptoProperties == nil || c.CryptoProperties.AssetType != cdx.CryptoAssetTypeCertificate {
			continue
		}
		fp := strings.TrimPrefix(c.BOMRef, "cert:")
		if fp == "" || fp == c.BOMRef {
			continue // missing or unprefixed BOMRef — skip
		}
		out[fp] = struct{}{}
	}
	return out
}

// TestProperty_CertificatesHaveFingerprint asserts every certificate
// component in the rich-seed full-scope BOM has a non-empty fingerprint
// encoded in its BOMRef (`cert:<fp>`).
//
// Plan note: the original Property 1 asserted on a
// `cipherflag:fingerprint_sha256` property that does not exist in the
// production emit path. The cert fingerprint is encoded in the BOMRef
// per mapper.go:144 — that is the load-bearing place where downstream
// consumers (cert_issuance lookup, BOM dependency edges, etc.) recover
// the fingerprint. The adapted assertion catches the same class of
// regression — "a cert component must carry an identifying fingerprint".
//
// Expected: 7 certs (rich seed has 8, but shadow-issuer-1 has a health
// report but no asset_provenance row, so it is excluded from
// scope-by-host enumeration; see cbom_testhelper_rich_test.go:262-275).
func TestProperty_CertificatesHaveFingerprint(t *testing.T) {
	ctx, st := withGoldenDB(t)
	seed := seedPKIScenarioForCBOMRich(t, ctx, st)

	gen := &Generator{}
	bom, err := gen.Generate(ctx, st, &Scope{
		HostIDs: []string{seed.HostA.String(), seed.HostB.String(), seed.HostC.String()},
	})
	require.NoError(t, err, "TestProperty_CertificatesHaveFingerprint: Generate")
	require.NotNil(t, bom.Components, "TestProperty_CertificatesHaveFingerprint: nil Components")

	var certCount int
	for _, c := range *bom.Components {
		if c.CryptoProperties == nil || c.CryptoProperties.AssetType != cdx.CryptoAssetTypeCertificate {
			continue
		}
		certCount++
		fp := strings.TrimPrefix(c.BOMRef, "cert:")
		require.NotEqual(t, c.BOMRef, fp,
			"TestProperty_CertificatesHaveFingerprint: cert component %q has BOMRef %q missing the cert: prefix",
			c.Name, c.BOMRef)
		require.NotEmpty(t, fp,
			"TestProperty_CertificatesHaveFingerprint: cert component %q has empty fingerprint after cert: prefix",
			c.Name)
	}
	require.GreaterOrEqual(t, certCount, 7,
		"TestProperty_CertificatesHaveFingerprint: rich seed should emit at least 7 certs (got %d)", certCount)
}

// TestProperty_AlgorithmsHaveAtLeastOneField asserts every algorithm
// component carries a non-nil CryptoAlgorithmProperties with at least
// one populated field. The fields checked are the full set defined in
// cyclonedx-go v0.10.0's CryptoAlgorithmProperties struct (lines 351-362
// of cyclonedx.go).
//
// In current emit code (mapper.go:246-248) Primitive is always set,
// even to CryptoPrimitiveUnknown for un-classified algorithms — so this
// assertion is a guard against a future regression that deletes that
// initialisation rather than a check of any borderline behaviour today.
func TestProperty_AlgorithmsHaveAtLeastOneField(t *testing.T) {
	ctx, st := withGoldenDB(t)
	seed := seedPKIScenarioForCBOMRich(t, ctx, st)

	gen := &Generator{}
	bom, err := gen.Generate(ctx, st, &Scope{
		HostIDs: []string{seed.HostA.String(), seed.HostB.String(), seed.HostC.String()},
	})
	require.NoError(t, err, "TestProperty_AlgorithmsHaveAtLeastOneField: Generate")
	require.NotNil(t, bom.Components, "TestProperty_AlgorithmsHaveAtLeastOneField: nil Components")

	var algoCount int
	for _, c := range *bom.Components {
		if c.CryptoProperties == nil || c.CryptoProperties.AssetType != cdx.CryptoAssetTypeAlgorithm {
			continue
		}
		algoCount++
		ap := c.CryptoProperties.AlgorithmProperties
		require.NotNil(t, ap,
			"TestProperty_AlgorithmsHaveAtLeastOneField: algorithm component %q (BOMRef %s) has nil AlgorithmProperties",
			c.Name, c.BOMRef)

		// At least one of the AlgorithmProperties fields must be populated.
		// Cover the full set from cyclonedx-go v0.10.0 cyclonedx.go:351-362.
		populated := false
		if ap.Primitive != "" {
			populated = true
		}
		if ap.ParameterSetIdentifier != "" {
			populated = true
		}
		if ap.Curve != "" {
			populated = true
		}
		if ap.ExecutionEnvironment != "" {
			populated = true
		}
		if ap.ImplementationPlatform != "" {
			populated = true
		}
		if ap.CertificationLevel != nil && len(*ap.CertificationLevel) > 0 {
			populated = true
		}
		if ap.Mode != "" {
			populated = true
		}
		if ap.Padding != "" {
			populated = true
		}
		if ap.CryptoFunctions != nil && len(*ap.CryptoFunctions) > 0 {
			populated = true
		}
		if ap.ClassicalSecurityLevel != nil {
			populated = true
		}
		if ap.NistQuantumSecurityLevel != nil {
			populated = true
		}
		require.True(t, populated,
			"TestProperty_AlgorithmsHaveAtLeastOneField: algorithm component %q (BOMRef %s) has AlgorithmProperties with NO populated field",
			c.Name, c.BOMRef)
	}
	require.GreaterOrEqual(t, algoCount, 1,
		"TestProperty_AlgorithmsHaveAtLeastOneField: rich seed should emit at least one algorithm component (got %d)", algoCount)
}

// TestProperty_CanonicaliseIsIdempotent asserts that JCS canonicalisation
// is idempotent: applying it to already-canonical bytes produces the same
// bytes. This is a structural invariant of the JSF signature pipeline —
// if Canonicalize is not idempotent, signature verification on the
// already-canonical bytes a consumer received would fail because they
// would re-canonicalize and get a different byte string than the one
// the signer signed.
func TestProperty_CanonicaliseIsIdempotent(t *testing.T) {
	ctx, st := withGoldenDB(t)
	seed := seedPKIScenarioForCBOMRich(t, ctx, st)

	gen := &Generator{}
	bom, err := gen.Generate(ctx, st, &Scope{
		HostIDs: []string{seed.HostA.String(), seed.HostB.String(), seed.HostC.String()},
	})
	require.NoError(t, err, "TestProperty_CanonicaliseIsIdempotent: Generate")

	signer, err := NewFileSigner(filepath.Join(goldenDir, "fixture-signing.key"))
	require.NoError(t, err, "TestProperty_CanonicaliseIsIdempotent: NewFileSigner")
	require.NoError(t, SignBOM(bom, signer), "TestProperty_CanonicaliseIsIdempotent: SignBOM")

	raw, err := MarshalSignedBOM(bom)
	require.NoError(t, err, "TestProperty_CanonicaliseIsIdempotent: MarshalSignedBOM")

	canon1, err := Canonicalize(raw)
	require.NoError(t, err, "TestProperty_CanonicaliseIsIdempotent: Canonicalize #1")
	canon2, err := Canonicalize(canon1)
	require.NoError(t, err, "TestProperty_CanonicaliseIsIdempotent: Canonicalize #2")

	require.Equal(t, string(canon1), string(canon2),
		"TestProperty_CanonicaliseIsIdempotent: Canonicalize should be idempotent — input bytes were not stable")
}

// TestProperty_AppScopeIsSubset asserts that the cert-set emitted by
// GenerateForApplication(app-1) is a strict subset of the cert-set
// emitted by full-scope Generate over the rich seed's three hosts. This
// is the structural invariant behind the app-scope filter: an app
// should never surface a cert that doesn't appear in the full inventory,
// AND the filter should actually narrow the scope (i.e., the filter is
// doing something).
//
// Per the rich seed, app-1 claims leaf-1 + leaf-2 (line 308-309), so
// the expected cert-set is {leaf-1, leaf-2} — strictly smaller than the
// full 7-cert set.
func TestProperty_AppScopeIsSubset(t *testing.T) {
	ctx, st := withGoldenDB(t)
	seed := seedPKIScenarioForCBOMRich(t, ctx, st)

	gen := &Generator{}
	fullBOM, err := gen.Generate(ctx, st, &Scope{
		HostIDs: []string{seed.HostA.String(), seed.HostB.String(), seed.HostC.String()},
	})
	require.NoError(t, err, "TestProperty_AppScopeIsSubset: Generate")
	appBOM, err := gen.GenerateForApplication(ctx, st, seed.App1Tag)
	require.NoError(t, err, "TestProperty_AppScopeIsSubset: GenerateForApplication")

	full := certFingerprints(fullBOM)
	app := certFingerprints(appBOM)

	require.NotEmpty(t, app,
		"TestProperty_AppScopeIsSubset: app scope produced no cert components (app-1 should have leaf-1, leaf-2)")

	for fp := range app {
		_, ok := full[fp]
		require.True(t, ok,
			"TestProperty_AppScopeIsSubset: app-scope produced fingerprint %q not in full-scope BOM", fp)
	}
	require.Less(t, len(app), len(full),
		"TestProperty_AppScopeIsSubset: app-scope (%d certs) should be a STRICT subset of full-scope (%d certs)",
		len(app), len(full))
}

// TestProperty_RelatedCryptoMaterialRefIntegrity asserts that every
// `cert:<fp>` reference appearing in the BOM's dependency graph resolves
// to a Certificate Component in the same BOM, with one documented
// exception (shadow-issuer-1).
//
// Plan adaptation: the original Property 5 walked
// `related-crypto-material` components and verified that their
// `relatedCryptoMaterialProperties.id` resolves to a cert. Because the
// rich seed inserts no SSH keys, the BOM contains no
// related-crypto-material components, which would make that test
// vacuous. Equivalent-spirit assertion: dependency-graph cert-refs
// must resolve. This catches the same class of regression (dangling
// cert pointer) using the dependency edges the rich seed actually
// exercises.
//
// Documented exception: cert:cbom-rich-shadow-issuer-1 appears in the
// dependsOn list of shadow-leaf-1 (because cert_issuance resolved it
// via AKI/SKI match) but is itself excluded from the BOM components
// list (no asset_provenance row → outside scope-by-host). The rich
// seed exercises this orphan-CA case deliberately
// (cbom_testhelper_rich_test.go:82-89, 262-275).
func TestProperty_RelatedCryptoMaterialRefIntegrity(t *testing.T) {
	ctx, st := withGoldenDB(t)
	seed := seedPKIScenarioForCBOMRich(t, ctx, st)

	gen := &Generator{}
	bom, err := gen.Generate(ctx, st, &Scope{
		HostIDs: []string{seed.HostA.String(), seed.HostB.String(), seed.HostC.String()},
	})
	require.NoError(t, err, "TestProperty_RelatedCryptoMaterialRefIntegrity: Generate")
	require.NotNil(t, bom.Components, "TestProperty_RelatedCryptoMaterialRefIntegrity: nil Components")

	// Build the set of cert BOMRefs present in the BOM.
	certBoms := map[string]struct{}{}
	for _, c := range *bom.Components {
		if c.CryptoProperties != nil && c.CryptoProperties.AssetType == cdx.CryptoAssetTypeCertificate {
			certBoms[c.BOMRef] = struct{}{}
		}
	}
	require.NotEmpty(t, certBoms,
		"TestProperty_RelatedCryptoMaterialRefIntegrity: no cert components emitted")

	// (A) Original plan check: every related-crypto-material's
	// `relatedCryptoMaterialProperties.id` must resolve to a cert in
	// the BOM. In the rich seed today there are no such components,
	// so this loop iterates zero times — kept for completeness so the
	// invariant fires automatically once SSH keys are added to the
	// rich seed (e.g. for L4-F).
	for _, c := range *bom.Components {
		if c.CryptoProperties == nil || c.CryptoProperties.AssetType != cdx.CryptoAssetTypeRelatedCryptoMaterial {
			continue
		}
		rcm := c.CryptoProperties.RelatedCryptoMaterialProperties
		if rcm == nil || rcm.ID == "" {
			continue
		}
		_, ok := certBoms[rcm.ID]
		require.True(t, ok,
			"TestProperty_RelatedCryptoMaterialRefIntegrity: related-crypto-material %q references cert bomRef %q that is not present in the BOM",
			c.Name, rcm.ID)
	}

	// (B) Adapted check: walk the dependency graph and assert every
	// cert: reference in dependsOn resolves to a cert component,
	// excepting the documented orphan-CA case.
	if bom.Dependencies != nil {
		for _, dep := range *bom.Dependencies {
			if dep.Dependencies == nil {
				continue
			}
			for _, child := range *dep.Dependencies {
				if !strings.HasPrefix(child, "cert:") {
					continue
				}
				if child == shadowIssuerDanglingRef {
					// Documented exception — see package comment.
					continue
				}
				_, ok := certBoms[child]
				require.True(t, ok,
					"TestProperty_RelatedCryptoMaterialRefIntegrity: dependency edge %q -> %q references cert that is not present in the BOM",
					dep.Ref, child)
			}
		}
	}
}
