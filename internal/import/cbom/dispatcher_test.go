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
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestClassifyComponent_CertificateByBOMRef(t *testing.T) {
	c := cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		BOMRef: "cert:abc123def456",
		Name:   "cert.example.com",
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeCertificate,
			CertificateProperties: &cdx.CertificateProperties{
				SubjectName:    "CN=example",
				IssuerName:     "CN=issuer",
				NotValidBefore: "2024-01-01T00:00:00Z",
				NotValidAfter:  "2025-01-01T00:00:00Z",
			},
		},
	}
	got := ClassifyComponent(c)
	if got.Kind != KindCertificate {
		t.Errorf("Kind = %v, want Certificate", got.Kind)
	}
	if got.Cert == nil {
		t.Fatal("Cert must be populated")
	}
	if got.Cert.FingerprintSHA256 != "abc123def456" {
		t.Errorf("Fingerprint = %q, want abc123def456", got.Cert.FingerprintSHA256)
	}
}

func TestClassifyComponent_SSHKeyByBOMRef(t *testing.T) {
	c := cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		BOMRef: "sshkey:xyz789",
		Name:   "ssh key",
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type:         cdx.RelatedCryptoMaterialTypePublicKey,
				AlgorithmRef: cdx.BOMReference("algo:ed25519"),
			},
		},
	}
	got := ClassifyComponent(c)
	if got.Kind != KindSSHKey {
		t.Errorf("Kind = %v, want SSHKey", got.Kind)
	}
	if got.SSHKey == nil {
		t.Fatal("SSHKey must be populated")
	}
	if got.SSHKey.FingerprintSHA256 != "xyz789" {
		t.Errorf("Fingerprint = %q, want xyz789", got.SSHKey.FingerprintSHA256)
	}
	if got.SSHKey.KeyType != "ssh-ed25519" {
		t.Errorf("KeyType = %q, want ssh-ed25519", got.SSHKey.KeyType)
	}
}

func TestClassifyComponent_Library_Crypto(t *testing.T) {
	c := cdx.Component{
		Type:    cdx.ComponentTypeLibrary,
		BOMRef:  "lib:openssl-id",
		Name:    "openssl",
		Version: "3.0.14",
	}
	got := ClassifyComponent(c)
	if got.Kind != KindLibrary {
		t.Errorf("Kind = %v, want Library", got.Kind)
	}
	if got.Lib == nil {
		t.Fatal("Lib must be populated")
	}
	if got.Lib.LibraryName != "openssl" || got.Lib.Version != "3.0.14" {
		t.Errorf("got %+v", got.Lib)
	}
}

func TestClassifyComponent_Library_NonCrypto_Skipped(t *testing.T) {
	c := cdx.Component{
		Type:    cdx.ComponentTypeLibrary,
		Name:    "lodash",
		Version: "4.17.21",
	}
	got := ClassifyComponent(c)
	if got.Kind != KindSkipped {
		t.Errorf("Kind = %v, want Skipped", got.Kind)
	}
	if got.SkipReason != ReasonNonCryptoLibrary {
		t.Errorf("SkipReason = %q, want %q", got.SkipReason, ReasonNonCryptoLibrary)
	}
}

func TestClassifyComponent_Library_MissingVersion_Skipped(t *testing.T) {
	c := cdx.Component{
		Type: cdx.ComponentTypeLibrary,
		Name: "openssl",
	}
	got := ClassifyComponent(c)
	if got.Kind != KindSkipped {
		t.Errorf("Kind = %v, want Skipped", got.Kind)
	}
	if got.SkipReason != ReasonMalformedComponent {
		t.Errorf("SkipReason = %q", got.SkipReason)
	}
}

func TestClassifyComponent_Algorithm_Skipped(t *testing.T) {
	c := cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		BOMRef: "algo:ed25519",
		Name:   "ed25519",
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm,
		},
	}
	got := ClassifyComponent(c)
	if got.Kind != KindSkipped {
		t.Errorf("Kind = %v, want Skipped (algorithms are synthetic)", got.Kind)
	}
}

func TestClassifyComponent_UnrecognisedType_Skipped(t *testing.T) {
	c := cdx.Component{
		Type: cdx.ComponentTypeApplication,
		Name: "some-app",
	}
	got := ClassifyComponent(c)
	if got.Kind != KindSkipped {
		t.Errorf("Kind = %v, want Skipped", got.Kind)
	}
	if got.SkipReason != ReasonUnrecognisedComponent {
		t.Errorf("SkipReason = %q", got.SkipReason)
	}
}

func TestClassifyComponent_CertMissingFingerprint_Skipped(t *testing.T) {
	// Cert without a BOMRef prefix and no SHA-256 hash — skipped.
	c := cdx.Component{
		Type: cdx.ComponentTypeCryptographicAsset,
		Name: "orphan-cert",
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:             cdx.CryptoAssetTypeCertificate,
			CertificateProperties: &cdx.CertificateProperties{SubjectName: "CN=x"},
		},
	}
	got := ClassifyComponent(c)
	if got.Kind != KindSkipped {
		t.Errorf("Kind = %v, want Skipped", got.Kind)
	}
	if got.SkipReason != ReasonMissingFingerprint {
		t.Errorf("SkipReason = %q, want %q", got.SkipReason, ReasonMissingFingerprint)
	}
}

func TestClassifyComponent_CertFromSHA256Hash(t *testing.T) {
	// Foreign CBOM: cert via CryptoProperties + SHA-256 hash (no BOMRef prefix).
	c := cdx.Component{
		Type: cdx.ComponentTypeCryptographicAsset,
		Name: "foreign.example.com",
		Hashes: &[]cdx.Hash{
			{Algorithm: cdx.HashAlgoSHA256, Value: "deadbeef"},
		},
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeCertificate,
			CertificateProperties: &cdx.CertificateProperties{
				SubjectName:    "CN=foreign",
				NotValidBefore: "2024-01-01T00:00:00Z",
				NotValidAfter:  "2025-01-01T00:00:00Z",
			},
		},
	}
	got := ClassifyComponent(c)
	if got.Kind != KindCertificate {
		t.Errorf("Kind = %v, want Certificate", got.Kind)
	}
	if got.Cert.FingerprintSHA256 != "deadbeef" {
		t.Errorf("Fingerprint = %q, want deadbeef", got.Cert.FingerprintSHA256)
	}
}

func TestClassifyComponent_ConfigWithProtocolProperties(t *testing.T) {
	c := cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		BOMRef: "config:my-sshd-config",
		Name:   "sshd",
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeProtocol,
			ProtocolProperties: &cdx.CryptoProtocolProperties{
				Type: cdx.CryptoProtocolTypeSSH,
			},
		},
	}
	got := ClassifyComponent(c)
	if got.Kind != KindConfig {
		t.Errorf("Kind = %v, want Config", got.Kind)
	}
	if got.Config == nil {
		t.Fatal("Config must be populated")
	}
	if got.Config.ConfigType != "sshd" {
		t.Errorf("ConfigType = %q, want sshd", got.Config.ConfigType)
	}
	if got.Config.FilePath != "cbom:config:my-sshd-config" {
		t.Errorf("FilePath = %q, want cbom:config:my-sshd-config", got.Config.FilePath)
	}
}

func TestClassifyComponent_ConfigMissingProtocolProperties_Skipped(t *testing.T) {
	// Foreign CBOM with AssetType=Protocol but no ProtocolProperties.
	c := cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		BOMRef: "config:orphan",
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeProtocol,
		},
	}
	got := ClassifyComponent(c)
	if got.Kind != KindSkipped {
		t.Errorf("Kind = %v, want Skipped", got.Kind)
	}
	if got.SkipReason != ReasonMalformedComponent {
		t.Errorf("SkipReason = %q, want %q", got.SkipReason, ReasonMalformedComponent)
	}
}

func TestClassifyComponent_ConfigMissingBOMRef_Skipped(t *testing.T) {
	// Component with ProtocolProperties but empty BOMRef — would collide
	// in the crypto_configs unique index (host_id, file_path="cbom:").
	c := cdx.Component{
		Type: cdx.ComponentTypeCryptographicAsset,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeProtocol,
			ProtocolProperties: &cdx.CryptoProtocolProperties{
				Type: cdx.CryptoProtocolTypeSSH,
			},
		},
	}
	got := ClassifyComponent(c)
	if got.Kind != KindSkipped {
		t.Errorf("Kind = %v, want Skipped", got.Kind)
	}
	if got.SkipReason != ReasonMalformedComponent {
		t.Errorf("SkipReason = %q, want %q", got.SkipReason, ReasonMalformedComponent)
	}
}
