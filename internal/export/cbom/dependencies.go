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

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// ParentLinkForCBOM is the minimal view of an issuance link the CBOM
// dependencies emit needs. Distinct from hostdeps.ParentLink to avoid
// pulling the analysis package into the export path; the caller adapts.
type ParentLinkForCBOM struct {
	ParentFingerprint string
	LinkMethod        string // 'aki_ski_match' | 'cn_match' | 'self_signed'
	LinkConfidence    string // 'attested' | 'inferred'
}

// IssuanceLookupForCBOM is what computeDependencies needs from storage.
// Caller wires it to the SP-1.6 IssuanceLookup adapter or any other
// source.
type IssuanceLookupForCBOM interface {
	ListParentsForCertCBOM(certFingerprint string) []ParentLinkForCBOM
}

// computeDependencies builds the BOM.Dependencies array from the
// assembled component slice. Edges expressed:
//   - cert:X → cert:Y for every cert_issuance row
//   - cert:X → key:X via SubjectPublicKeyRef
//   - cert:X → algo:<sig> via SignatureAlgorithmRef
//   - sshkey:X → algo:<keytype> via AlgorithmRef
//
// inScope returns true if a ref belongs in this BOM's scope. Refs
// outside scope (e.g., issuing CA on a host outside the current
// application's tag) still emit as deps so cross-BOM consumers can
// stitch; orphaned refs (not in any CBOM at all) get the
// cipherflag:dep.unresolved annotation applied separately.
func computeDependencies(
	components []cdx.Component,
	lookup IssuanceLookupForCBOM,
	inScope func(ref string) bool,
) []cdx.Dependency {
	deps := []cdx.Dependency{}

	for _, c := range components {
		if c.CryptoProperties == nil {
			continue
		}
		var children []string
		switch c.CryptoProperties.AssetType {
		case cdx.CryptoAssetTypeCertificate:
			if cp := c.CryptoProperties.CertificateProperties; cp != nil {
				if ref := string(cp.SubjectPublicKeyRef); ref != "" {
					children = append(children, ref)
				}
				if ref := string(cp.SignatureAlgorithmRef); ref != "" {
					children = append(children, ref)
				}
			}
			// SP-1.6 cert_issuance parents — extract fingerprint from BOMRef.
			if fp := strings.TrimPrefix(c.BOMRef, "cert:"); fp != c.BOMRef {
				for _, p := range lookup.ListParentsForCertCBOM(fp) {
					children = append(children, "cert:"+p.ParentFingerprint)
				}
			}
		case cdx.CryptoAssetTypeRelatedCryptoMaterial:
			if rp := c.CryptoProperties.RelatedCryptoMaterialProperties; rp != nil {
				if ref := string(rp.AlgorithmRef); ref != "" {
					children = append(children, ref)
				}
			}
		case cdx.CryptoAssetTypeProtocol:
			if pp := c.CryptoProperties.ProtocolProperties; pp != nil && pp.CipherSuites != nil {
				for _, cs := range *pp.CipherSuites {
					d := DecomposeTLSSuite(cs.Name)
					if !d.Recognized {
						continue
					}
					if d.Bulk != "" {
						children = append(children, "algo:"+d.Bulk)
					}
					if d.Hash != "" {
						children = append(children, "algo:"+d.Hash)
					}
					if d.KEX != "" {
						children = append(children, "algo:"+d.KEX)
					}
					if d.Sig != "" {
						children = append(children, "algo:"+d.Sig)
					}
				}
			}
		}
		if len(children) == 0 {
			continue
		}
		// Dedup + sort for deterministic emit.
		sort.Strings(children)
		children = dedup(children)
		deps = append(deps, cdx.Dependency{
			Ref:          c.BOMRef,
			Dependencies: &children,
		})
	}

	sort.Slice(deps, func(i, j int) bool { return deps[i].Ref < deps[j].Ref })
	return deps
}

func dedup(s []string) []string {
	if len(s) == 0 {
		return s
	}
	out := s[:0]
	prev := ""
	for _, v := range s {
		if v != prev {
			out = append(out, v)
			prev = v
		}
	}
	return out
}
