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

package compliance

import (
	"strings"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

func TestFIPS_Cert_FailOnEd25519(t *testing.T) {
	cert := &model.Certificate{KeyAlgorithm: model.KeyAlgorithm("Ed25519")}
	r := &model.AssetHealthReport{}
	if got := evaluateFIPS140_3Certificate(r, cert); got != StatusFail {
		t.Errorf("Ed25519 cert → %s, want fail (not FIPS-approved)", got)
	}
}

func TestFIPS_Cert_PassOnRSA(t *testing.T) {
	cert := &model.Certificate{
		KeyAlgorithm:       model.KeyAlgorithm("RSA"),
		SignatureAlgorithm: model.SignatureAlgorithm("SHA256-RSA"),
	}
	r := &model.AssetHealthReport{}
	if got := evaluateFIPS140_3Certificate(r, cert); got != StatusPass {
		t.Errorf("RSA cert with SHA256 → %s, want pass", got)
	}
}

func TestFIPS_Cert_FailOnSHA1Signature(t *testing.T) {
	cert := &model.Certificate{
		KeyAlgorithm:       model.KeyAlgorithm("RSA"),
		SignatureAlgorithm: model.SignatureAlgorithm("SHA1-RSA"),
	}
	r := &model.AssetHealthReport{}
	if got := evaluateFIPS140_3Certificate(r, cert); got != StatusFail {
		t.Errorf("SHA1-RSA cert → %s, want fail", got)
	}
}

func TestFIPS_Cert_FailOnHighCryptoFinding(t *testing.T) {
	cert := &model.Certificate{
		KeyAlgorithm:       model.KeyAlgorithm("RSA"),
		SignatureAlgorithm: model.SignatureAlgorithm("SHA256-RSA"),
	}
	r := &model.AssetHealthReport{
		Findings: []model.HealthFinding{{Severity: model.SeverityHigh, Category: model.CategoryKeyStrength}},
	}
	if got := evaluateFIPS140_3Certificate(r, cert); got != StatusFail {
		t.Errorf("High in KeyStrength → %s, want fail", got)
	}
}

func TestFIPS_Cert_PartialOnMediumCryptoFinding(t *testing.T) {
	cert := &model.Certificate{
		KeyAlgorithm:       model.KeyAlgorithm("RSA"),
		SignatureAlgorithm: model.SignatureAlgorithm("SHA256-RSA"),
	}
	r := &model.AssetHealthReport{
		Findings: []model.HealthFinding{{Severity: model.SeverityMedium, Category: model.CategoryKeyStrength}},
	}
	if got := evaluateFIPS140_3Certificate(r, cert); got != StatusPartial {
		t.Errorf("Medium in KeyStrength → %s, want partial", got)
	}
}

func TestFIPS_SSH_FailOnEd25519(t *testing.T) {
	k := &model.SSHKey{KeyType: "ssh-ed25519"}
	r := &model.AssetHealthReport{}
	if got := evaluateFIPS140_3SSHKey(r, k); got != StatusFail {
		t.Errorf("ssh-ed25519 → %s, want fail", got)
	}
}

func TestFIPS_SSH_FailOnSSH001(t *testing.T) {
	k := &model.SSHKey{KeyType: "ssh-rsa"}
	r := &model.AssetHealthReport{
		Findings: []model.HealthFinding{{RuleID: "SSH-001"}},
	}
	if got := evaluateFIPS140_3SSHKey(r, k); got != StatusFail {
		t.Errorf("SSH-001 → %s, want fail", got)
	}
}

func TestFIPS_SSH_PassOnECDSANistP256(t *testing.T) {
	k := &model.SSHKey{KeyType: "ecdsa-sha2-nistp256"}
	r := &model.AssetHealthReport{}
	if got := evaluateFIPS140_3SSHKey(r, k); got != StatusPass {
		t.Errorf("ecdsa-sha2-nistp256 → %s, want pass", got)
	}
}

func TestFIPS_SSH_PartialOnSSH003(t *testing.T) {
	k := &model.SSHKey{KeyType: "ssh-rsa"}
	r := &model.AssetHealthReport{
		Findings: []model.HealthFinding{{RuleID: "SSH-003"}},
	}
	if got := evaluateFIPS140_3SSHKey(r, k); got != StatusPartial {
		t.Errorf("SSH-003 alone → %s, want partial", got)
	}
}

func TestFIPS_Library_PassOnLIB005(t *testing.T) {
	r := &model.AssetHealthReport{
		Findings: []model.HealthFinding{{RuleID: "LIB-005"}},
	}
	if got := evaluateFIPS140_3Library(r); got != StatusPass {
		t.Errorf("LIB-005 → %s, want pass", got)
	}
}

func TestFIPS_Library_FailWithoutLIB005(t *testing.T) {
	r := &model.AssetHealthReport{
		Findings: []model.HealthFinding{{RuleID: "LIB-004"}},
	}
	if got := evaluateFIPS140_3Library(r); got != StatusFail {
		t.Errorf("no LIB-005 → %s, want fail", got)
	}
}

func TestFIPS_Config_FailOnCFG001(t *testing.T) {
	r := &model.AssetHealthReport{
		Findings: []model.HealthFinding{{RuleID: "CFG-001"}},
	}
	if got := evaluateFIPS140_3Config(r); got != StatusFail {
		t.Errorf("CFG-001 → %s, want fail", got)
	}
}

func TestFIPS_Config_FailOnCFG003(t *testing.T) {
	r := &model.AssetHealthReport{
		Findings: []model.HealthFinding{{RuleID: "CFG-003"}},
	}
	if got := evaluateFIPS140_3Config(r); got != StatusFail {
		t.Errorf("CFG-003 → %s, want fail", got)
	}
}

func TestFIPS_Config_PartialOnMedium(t *testing.T) {
	r := &model.AssetHealthReport{
		Findings: []model.HealthFinding{{Severity: model.SeverityMedium, Category: model.CategoryGovernance, RuleID: "CFG-002"}},
	}
	if got := evaluateFIPS140_3Config(r); got != StatusPartial {
		t.Errorf("CFG-002 (Medium) → %s, want partial", got)
	}
}

func TestFIPS_Config_PassOnEmpty(t *testing.T) {
	if got := evaluateFIPS140_3Config(&model.AssetHealthReport{}); got != StatusPass {
		t.Errorf("empty → %s, want pass", got)
	}
}

func TestFIPS_Cert_PassOnSHA384Signature(t *testing.T) {
	cert := &model.Certificate{
		KeyAlgorithm:       model.KeyAlgorithm("RSA"),
		SignatureAlgorithm: model.SignatureAlgorithm("SHA384-RSA"),
	}
	r := &model.AssetHealthReport{}
	if got := evaluateFIPS140_3Certificate(r, cert); got != StatusPass {
		t.Errorf("SHA384-RSA cert → %s, want pass (regression: used to fail due to hashKey[3] check)", got)
	}
}

func TestFIPS_Cert_PassOnSHA512Signature(t *testing.T) {
	cert := &model.Certificate{
		KeyAlgorithm:       model.KeyAlgorithm("RSA"),
		SignatureAlgorithm: model.SignatureAlgorithm("SHA512-RSA"),
	}
	r := &model.AssetHealthReport{}
	if got := evaluateFIPS140_3Certificate(r, cert); got != StatusPass {
		t.Errorf("SHA512-RSA cert → %s, want pass", got)
	}
}

func TestFIPS_Cert_PassOnSHA3_256Signature(t *testing.T) {
	cert := &model.Certificate{
		KeyAlgorithm:       model.KeyAlgorithm("RSA"),
		SignatureAlgorithm: model.SignatureAlgorithm("SHA3-256-RSA"),
	}
	r := &model.AssetHealthReport{}
	if got := evaluateFIPS140_3Certificate(r, cert); got != StatusPass {
		t.Errorf("SHA3-256-RSA cert → %s, want pass (hyphen-preserved SHA3 variant)", got)
	}
}

func TestFIPS_Cert_PassOnAlreadyHyphenatedHash(t *testing.T) {
	cert := &model.Certificate{
		KeyAlgorithm:       model.KeyAlgorithm("RSA"),
		SignatureAlgorithm: model.SignatureAlgorithm("sha-256-RSA"),
	}
	r := &model.AssetHealthReport{}
	if got := evaluateFIPS140_3Certificate(r, cert); got != StatusPass {
		t.Errorf("already-hyphenated sha-256-RSA → %s, want pass", got)
	}
}

func TestFIPS_ApprovedLookupNormalisesInput(t *testing.T) {
	if !fipsApprovedKeyAlgorithms[strings.ToLower(strings.TrimSpace("  RSA "))] {
		t.Error("RSA (whitespaced) should lookup after normalise")
	}
	if !fipsApprovedSSHKeyTypes["ssh-rsa"] {
		t.Error("ssh-rsa should be approved")
	}
	if fipsApprovedSSHKeyTypes["ssh-ed25519"] {
		t.Error("ssh-ed25519 MUST NOT be approved (not on FIPS list)")
	}
}

// Regression tests using actual model.Sig* constants — these are what
// every real ingest path produces, so these must pass or we break FIPS
// evaluation in production.
func TestFIPS_Cert_ModelConst_SHA256WithRSA_Passes(t *testing.T) {
	cert := &model.Certificate{
		KeyAlgorithm:       model.KeyRSA,
		SignatureAlgorithm: model.SigSHA256WithRSA,
	}
	if got := evaluateFIPS140_3Certificate(&model.AssetHealthReport{}, cert); got != StatusPass {
		t.Errorf("SigSHA256WithRSA → %s, want pass", got)
	}
}

func TestFIPS_Cert_ModelConst_SHA384WithRSA_Passes(t *testing.T) {
	cert := &model.Certificate{
		KeyAlgorithm:       model.KeyRSA,
		SignatureAlgorithm: model.SigSHA384WithRSA,
	}
	if got := evaluateFIPS140_3Certificate(&model.AssetHealthReport{}, cert); got != StatusPass {
		t.Errorf("SigSHA384WithRSA → %s, want pass", got)
	}
}

func TestFIPS_Cert_ModelConst_SHA512WithRSA_Passes(t *testing.T) {
	cert := &model.Certificate{
		KeyAlgorithm:       model.KeyRSA,
		SignatureAlgorithm: model.SigSHA512WithRSA,
	}
	if got := evaluateFIPS140_3Certificate(&model.AssetHealthReport{}, cert); got != StatusPass {
		t.Errorf("SigSHA512WithRSA → %s, want pass", got)
	}
}

func TestFIPS_Cert_ModelConst_ECDSAWithSHA256_Passes(t *testing.T) {
	cert := &model.Certificate{
		KeyAlgorithm:       model.KeyECDSA,
		SignatureAlgorithm: model.SigECDSAWithSHA256,
	}
	if got := evaluateFIPS140_3Certificate(&model.AssetHealthReport{}, cert); got != StatusPass {
		t.Errorf("SigECDSAWithSHA256 → %s, want pass", got)
	}
}

func TestFIPS_Cert_ModelConst_ECDSAWithSHA384_Passes(t *testing.T) {
	cert := &model.Certificate{
		KeyAlgorithm:       model.KeyECDSA,
		SignatureAlgorithm: model.SigECDSAWithSHA384,
	}
	if got := evaluateFIPS140_3Certificate(&model.AssetHealthReport{}, cert); got != StatusPass {
		t.Errorf("SigECDSAWithSHA384 → %s, want pass", got)
	}
}

func TestFIPS_Cert_ModelConst_SHA1WithRSA_Fails(t *testing.T) {
	cert := &model.Certificate{
		KeyAlgorithm:       model.KeyRSA,
		SignatureAlgorithm: model.SigSHA1WithRSA,
	}
	if got := evaluateFIPS140_3Certificate(&model.AssetHealthReport{}, cert); got != StatusFail {
		t.Errorf("SigSHA1WithRSA → %s, want fail (SHA-1 not approved)", got)
	}
}

func TestFIPS_Cert_ModelConst_MD5WithRSA_Fails(t *testing.T) {
	cert := &model.Certificate{
		KeyAlgorithm:       model.KeyRSA,
		SignatureAlgorithm: model.SigMD5WithRSA,
	}
	if got := evaluateFIPS140_3Certificate(&model.AssetHealthReport{}, cert); got != StatusFail {
		t.Errorf("SigMD5WithRSA → %s, want fail (MD5 not approved)", got)
	}
}
