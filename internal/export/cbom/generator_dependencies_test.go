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
	"context"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/stretchr/testify/require"
)

func TestGenerate_PopulatesDependenciesArray(t *testing.T) {
	ctx := context.Background()
	st := newIntegrationStore(t)
	s := seedPKIScenarioForCBOM(t, ctx, st)

	gen := NewGenerator()
	bom, err := gen.Generate(ctx, st, &Scope{
		Name:       "test-scope",
		AssetTypes: []string{"certificate"},
		HostIDs:    []string{s.HostA.String(), s.HostB.String()},
	})
	require.NoError(t, err)
	require.NotNil(t, bom.Dependencies, "bom.Dependencies must be non-nil after wiring")

	var leafDep *cdx.Dependency
	for i, d := range *bom.Dependencies {
		if d.Ref == "cert:"+s.LeafFP {
			leafDep = &(*bom.Dependencies)[i]
		}
	}
	require.NotNil(t, leafDep, "leaf cert should appear in Dependencies")
	require.NotNil(t, leafDep.Dependencies)
	require.Contains(t, *leafDep.Dependencies, "cert:"+s.CAFP,
		"leaf cert should depend on its issuing CA via cert_issuance")
}

// TestGenerate_AlgoProperties_ExecutionEnvironmentAndCertificationLevel
// verifies that the algorithm emit pipeline wires executionEnvironment and
// certificationLevel from asset_provenance.source values and the FIPS
// validation map.
//
// Scenario A (monomorphic hardware + monomorphic FIPS):
//   - One host, provenance source="aws_kms" for both the cert and the library.
//   - Library is openssl 3.0.8 → FIPS 140-3 L1.
//   - Expected: executionEnvironment=hardware, certificationLevel=[fips140-3-l1].
//
// Scenario B (mixed sources → conservative default, no FIPS library):
//   - Two hosts, cert on host-A with source="file_scanner",
//     cert on host-B with source="aws_kms".
//   - No library in scope.
//   - Expected: executionEnvironment=software-plain-ram, certificationLevel absent.
func TestGenerate_AlgoProperties_ExecutionEnvironmentAndCertificationLevel(t *testing.T) {
	ctx := context.Background()

	t.Run("monomorphic hardware source + FIPS library", func(t *testing.T) {
		st := newIntegrationStore(t)

		hostID := uuid.New()
		_, err := st.Pool().Exec(ctx,
			`INSERT INTO hosts (id, canonical_hostname) VALUES ($1, 'algo-props-host-a')`,
			hostID)
		require.NoError(t, err)

		now := time.Now().UTC()
		const certFP = "algo-props-cert-hw"

		// Seed a certificate (SHA256WithRSA → algo:sha256withrsa).
		cert := &model.Certificate{
			FingerprintSHA256:  certFP,
			Subject:            model.DistinguishedName{CommonName: "algo-props.example.com", Full: "CN=algo-props.example.com"},
			Issuer:             model.DistinguishedName{CommonName: "algo-props.example.com", Full: "CN=algo-props.example.com"},
			SerialNumber:       "algo-props-serial-hw",
			NotBefore:          now.Add(-24 * time.Hour),
			NotAfter:           now.Add(365 * 24 * time.Hour),
			KeyAlgorithm:       model.KeyRSA,
			KeySizeBits:        2048,
			SignatureAlgorithm: model.SigSHA256WithRSA,
			SourceDiscovery:    model.SourceZeekPassive,
			FirstSeen:          now,
			LastSeen:           now,
			IsCA:               true,
			AuthorityKeyID:     []byte{0xA1, 0xB2},
			SubjectKeyID:       []byte{0xA1, 0xB2},
		}
		require.NoError(t, st.UpsertCertificate(ctx, cert))
		_, err = st.Pool().Exec(ctx,
			`INSERT INTO asset_provenance (asset_type, asset_id, source, host_id, first_seen, last_seen)
			 VALUES ('certificate', $1, 'aws_kms', $2, NOW(), NOW())`,
			certFP, hostID)
		require.NoError(t, err)
		require.NoError(t, st.SaveAssetHealthReport(ctx, &model.AssetHealthReport{
			AssetType: "certificate", AssetID: certFP,
			Grade: "A", Score: 90, RiskScore: 5, PQCStatus: "safe",
			ScoredAt: now, Compliance: map[string]string{}, RiskFactors: map[string]int{},
		}))

		// Seed a FIPS-validated library (openssl 3.0.8 → fips140-3-l1).
		lib := &model.CryptoLibrary{
			HostID:          hostID.String(),
			LibraryName:     "openssl",
			Version:         "3.0.8",
			PQCCapable:      true,
			Source:          "aws_kms",
			DiscoveryStatus: "active",
			FirstSeen:       now,
			LastSeen:        now,
		}
		require.NoError(t, st.UpsertCryptoLibrary(ctx, lib))
		_, err = st.Pool().Exec(ctx,
			`INSERT INTO asset_provenance (asset_type, asset_id, source, host_id, first_seen, last_seen)
			 VALUES ('crypto_library', $1, 'aws_kms', $2, NOW(), NOW())`,
			lib.ID, hostID)
		require.NoError(t, err)
		require.NoError(t, st.SaveAssetHealthReport(ctx, &model.AssetHealthReport{
			AssetType: "crypto_library", AssetID: lib.ID,
			Grade: "A", Score: 95, RiskScore: 0, PQCStatus: "safe",
			ScoredAt: now, Compliance: map[string]string{}, RiskFactors: map[string]int{},
		}))

		gen := NewGenerator()
		bom, err := gen.Generate(ctx, st, &Scope{
			Name:    "algo-props-test",
			HostIDs: []string{hostID.String()},
		})
		require.NoError(t, err)
		require.NotNil(t, bom.Components)

		// Find the algo component for sha256withrsa.
		var algoComp *cdx.Component
		for i, c := range *bom.Components {
			if c.BOMRef == "algo:sha256withrsa" {
				algoComp = &(*bom.Components)[i]
				break
			}
		}
		require.NotNil(t, algoComp, "expected algo:sha256withrsa component in BOM")
		require.NotNil(t, algoComp.CryptoProperties)
		require.NotNil(t, algoComp.CryptoProperties.AlgorithmProperties)
		ap := algoComp.CryptoProperties.AlgorithmProperties

		require.Equal(t, cdx.CryptoExecutionEnvironmentHardware, ap.ExecutionEnvironment,
			"all observations from aws_kms → hardware execution environment")

		require.NotNil(t, ap.CertificationLevel,
			"openssl 3.0.8 is FIPS 140-3 L1 → certificationLevel must be set")
		require.Len(t, *ap.CertificationLevel, 1)
		require.Equal(t, cdx.CryptoCertificationLevelFIPS140_3_L1, (*ap.CertificationLevel)[0],
			"monomorphic fips140-3-l1 across all lib observations → fips140-3-l1")
	})

	t.Run("mixed sources + no FIPS library → conservative defaults", func(t *testing.T) {
		st := newIntegrationStore(t)

		hostA := uuid.New()
		hostB := uuid.New()
		_, err := st.Pool().Exec(ctx,
			`INSERT INTO hosts (id, canonical_hostname) VALUES ($1, 'algo-props-host-sw-a'), ($2, 'algo-props-host-sw-b')`,
			hostA, hostB)
		require.NoError(t, err)

		now := time.Now().UTC()
		seedCertWithSource := func(fp, source string, hostID uuid.UUID) {
			t.Helper()
			cert := &model.Certificate{
				FingerprintSHA256:  fp,
				Subject:            model.DistinguishedName{CommonName: fp, Full: "CN=" + fp},
				Issuer:             model.DistinguishedName{CommonName: fp, Full: "CN=" + fp},
				SerialNumber:       fp,
				NotBefore:          now.Add(-24 * time.Hour),
				NotAfter:           now.Add(365 * 24 * time.Hour),
				KeyAlgorithm:       model.KeyRSA,
				KeySizeBits:        2048,
				SignatureAlgorithm: model.SigSHA256WithRSA,
				SourceDiscovery:    model.SourceZeekPassive,
				FirstSeen:          now,
				LastSeen:           now,
				IsCA:               true,
				AuthorityKeyID:     []byte{0xC1, 0xD2},
				SubjectKeyID:       []byte{0xC1, 0xD2},
			}
			require.NoError(t, st.UpsertCertificate(ctx, cert))
			_, err := st.Pool().Exec(ctx,
				`INSERT INTO asset_provenance (asset_type, asset_id, source, host_id, first_seen, last_seen)
				 VALUES ('certificate', $1, $2, $3, NOW(), NOW())`,
				fp, source, hostID)
			require.NoError(t, err)
			require.NoError(t, st.SaveAssetHealthReport(ctx, &model.AssetHealthReport{
				AssetType: "certificate", AssetID: fp,
				Grade: "B", Score: 70, RiskScore: 15, PQCStatus: "safe",
				ScoredAt: now, Compliance: map[string]string{}, RiskFactors: map[string]int{},
			}))
		}
		// Two certs with the same sig algo but different provenance sources.
		seedCertWithSource("algo-props-sw-cert-a", "file_scanner", hostA)
		seedCertWithSource("algo-props-sw-cert-b", "aws_kms", hostB)

		gen := NewGenerator()
		bom, err := gen.Generate(ctx, st, &Scope{
			Name:    "algo-props-mixed",
			HostIDs: []string{hostA.String(), hostB.String()},
		})
		require.NoError(t, err)
		require.NotNil(t, bom.Components)

		var algoComp *cdx.Component
		for i, c := range *bom.Components {
			if c.BOMRef == "algo:sha256withrsa" {
				algoComp = &(*bom.Components)[i]
				break
			}
		}
		require.NotNil(t, algoComp, "expected algo:sha256withrsa in BOM")
		require.NotNil(t, algoComp.CryptoProperties)
		require.NotNil(t, algoComp.CryptoProperties.AlgorithmProperties)
		ap := algoComp.CryptoProperties.AlgorithmProperties

		require.Equal(t, cdx.CryptoExecutionEnvironmentSoftwarePlainRAM, ap.ExecutionEnvironment,
			"mixed file_scanner + aws_kms → conservative software-plain-ram")

		require.Nil(t, ap.CertificationLevel,
			"no library in scope → certificationLevel must be absent")
	})
}

