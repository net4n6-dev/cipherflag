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
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestComputeDependencies_CertHasKeyAndSigAlgoEdges(t *testing.T) {
	components := []cdx.Component{
		{
			BOMRef: "cert:abc",
			CryptoProperties: &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeCertificate,
				CertificateProperties: &cdx.CertificateProperties{
					SignatureAlgorithmRef: cdx.BOMReference("algo:sha256-rsa"),
					SubjectPublicKeyRef:   cdx.BOMReference("key:abc"),
				},
			},
		},
		{BOMRef: "key:abc"},
		{BOMRef: "algo:sha256-rsa"},
	}
	deps := computeDependencies(components, emptyIssuanceLookup{}, allInScope)
	require.Len(t, deps, 1, "exactly one dependency entry for cert:abc")
	require.Equal(t, "cert:abc", deps[0].Ref)
	sort.Strings(*deps[0].Dependencies)
	require.Equal(t, []string{"algo:sha256-rsa", "key:abc"}, *deps[0].Dependencies)
}

func TestComputeDependencies_CrossSignedCertHasMultipleIssuers(t *testing.T) {
	components := []cdx.Component{
		{BOMRef: "cert:leaf", CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeCertificate}},
		{BOMRef: "cert:ca-1"},
		{BOMRef: "cert:ca-2"},
	}
	lookup := stubIssuanceLookup{
		parents: map[string][]parentLink{
			"leaf": {
				{parent: "ca-1", method: "aki_ski_match", confidence: "attested"},
				{parent: "ca-2", method: "cn_match", confidence: "inferred"},
			},
		},
	}
	deps := computeDependencies(components, lookup, allInScope)
	var leafDep cdx.Dependency
	for _, d := range deps {
		if d.Ref == "cert:leaf" {
			leafDep = d
		}
	}
	sort.Strings(*leafDep.Dependencies)
	require.Equal(t, []string{"cert:ca-1", "cert:ca-2"}, *leafDep.Dependencies)
}

func TestComputeDependencies_SSHKeyHasAlgoEdge(t *testing.T) {
	components := []cdx.Component{
		{
			BOMRef: "sshkey:fp",
			CryptoProperties: &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
				RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
					AlgorithmRef: cdx.BOMReference("algo:ed25519"),
				},
			},
		},
		{BOMRef: "algo:ed25519"},
	}
	deps := computeDependencies(components, emptyIssuanceLookup{}, allInScope)
	require.Len(t, deps, 1)
	require.Equal(t, "sshkey:fp", deps[0].Ref)
	require.Equal(t, []string{"algo:ed25519"}, *deps[0].Dependencies)
}

func TestComputeDependencies_DeterministicOrdering(t *testing.T) {
	components := []cdx.Component{
		{BOMRef: "cert:b", CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeCertificate, CertificateProperties: &cdx.CertificateProperties{SubjectPublicKeyRef: cdx.BOMReference("key:b")}}},
		{BOMRef: "cert:a", CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeCertificate, CertificateProperties: &cdx.CertificateProperties{SubjectPublicKeyRef: cdx.BOMReference("key:a")}}},
		{BOMRef: "key:a"},
		{BOMRef: "key:b"},
	}
	deps1 := computeDependencies(components, emptyIssuanceLookup{}, allInScope)
	deps2 := computeDependencies(components, emptyIssuanceLookup{}, allInScope)
	require.Equal(t, deps1, deps2, "computeDependencies output must be deterministic")
	// First entry should be cert:a (alphabetic by ref).
	require.Equal(t, "cert:a", deps1[0].Ref)
	require.Equal(t, "cert:b", deps1[1].Ref)
}

func TestComputeDependencies_ProtocolDecomposesToAlgoEdges(t *testing.T) {
	components := []cdx.Component{
		{
			BOMRef: "config:proto-1",
			CryptoProperties: &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeProtocol,
				ProtocolProperties: &cdx.CryptoProtocolProperties{
					Type:    cdx.CryptoProtocolTypeTLS,
					Version: "1.2",
					CipherSuites: &[]cdx.CipherSuite{
						{Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
					},
				},
			},
		},
		{BOMRef: "algo:aes-128"},
		{BOMRef: "algo:sha256"},
		{BOMRef: "algo:ecdhe"},
		{BOMRef: "algo:rsa"},
	}
	deps := computeDependencies(components, emptyIssuanceLookup{}, allInScope)
	var protoDep cdx.Dependency
	for _, d := range deps {
		if d.Ref == "config:proto-1" {
			protoDep = d
		}
	}
	require.NotEmpty(t, protoDep.Dependencies, "protocol component should emit algo deps")
	refs := *protoDep.Dependencies
	sort.Strings(refs)
	require.Equal(t, []string{"algo:aes-128", "algo:ecdhe", "algo:rsa", "algo:sha256"}, refs)
}

// ── Test helpers ──

type parentLink struct {
	parent     string
	method     string
	confidence string
}

type stubIssuanceLookup struct {
	parents map[string][]parentLink
}

func (s stubIssuanceLookup) ListParentsForCertCBOM(certFp string) []ParentLinkForCBOM {
	out := []ParentLinkForCBOM{}
	for _, p := range s.parents[certFp] {
		out = append(out, ParentLinkForCBOM{
			ParentFingerprint: p.parent,
			LinkMethod:        p.method,
			LinkConfidence:    p.confidence,
		})
	}
	return out
}

type emptyIssuanceLookup struct{}

func (emptyIssuanceLookup) ListParentsForCertCBOM(string) []ParentLinkForCBOM {
	return nil
}

func allInScope(string) bool { return true }
