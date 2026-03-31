package analysis

import (
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

func certWith(opts func(*model.Certificate)) *model.Certificate {
	c := &model.Certificate{
		FingerprintSHA256:  "abc123",
		Subject:           model.DistinguishedName{CommonName: "test.example.com"},
		Issuer:            model.DistinguishedName{CommonName: "Test CA", Organization: "Test Org"},
		NotBefore:         time.Now().Add(-30 * 24 * time.Hour),
		NotAfter:          time.Now().Add(180 * 24 * time.Hour),
		KeyAlgorithm:      model.KeyRSA,
		KeySizeBits:       4096,
		SignatureAlgorithm: model.SigSHA256WithRSA,
		IsCA:              false,
		OCSPResponderURLs: []string{"http://ocsp.example.com"},
		CRLDistributionPoints: []string{"http://crl.example.com"},
		SCTs:              []string{"Google Argon"},
	}
	if opts != nil {
		opts(c)
	}
	return c
}

func findRule(report *model.HealthReport, ruleID string) *model.HealthFinding {
	for _, f := range report.Findings {
		if f.RuleID == ruleID {
			return &f
		}
	}
	return nil
}

func TestHealthyCert(t *testing.T) {
	report := ScoreCertificate(certWith(nil))
	if report.Grade != model.GradeAPlus {
		t.Errorf("healthy cert grade = %q, want A+", report.Grade)
	}
	if report.Score < 95 {
		t.Errorf("healthy cert score = %d, want >= 95", report.Score)
	}
}

// ── Expiration rules ──

func TestEXP001_Expired(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.NotAfter = time.Now().Add(-1 * time.Hour)
	}))
	if f := findRule(report, "EXP-001"); f == nil {
		t.Fatal("expected EXP-001 finding")
	}
	if report.Grade != model.GradeF {
		t.Errorf("expired cert grade = %q, want F", report.Grade)
	}
}

func TestEXP002_ExpiresIn7Days(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.NotAfter = time.Now().Add(5 * 24 * time.Hour)
	}))
	if f := findRule(report, "EXP-002"); f == nil {
		t.Fatal("expected EXP-002 finding")
	}
}

func TestEXP003_ExpiresIn30Days(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.NotAfter = time.Now().Add(20 * 24 * time.Hour)
	}))
	if f := findRule(report, "EXP-003"); f == nil {
		t.Fatal("expected EXP-003 finding")
	}
}

func TestEXP004_ExpiresIn90Days(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.NotAfter = time.Now().Add(60 * 24 * time.Hour)
	}))
	if f := findRule(report, "EXP-004"); f == nil {
		t.Fatal("expected EXP-004 finding")
	}
}

func TestEXP005_LongValidity(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.NotBefore = time.Now().Add(-10 * 24 * time.Hour)
		c.NotAfter = time.Now().Add(500 * 24 * time.Hour)
	}))
	if f := findRule(report, "EXP-005"); f == nil {
		t.Fatal("expected EXP-005 finding for >398 day validity")
	}
}

func TestEXP006_200DayValidity(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.NotBefore = time.Now().Add(-10 * 24 * time.Hour)
		c.NotAfter = time.Now().Add(300 * 24 * time.Hour)
	}))
	if f := findRule(report, "EXP-006"); f == nil {
		t.Fatal("expected EXP-006 finding for >200 day validity")
	}
}

// ── Key strength rules ──

func TestKEY001_RSAUnder2048(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.KeySizeBits = 1024
	}))
	if f := findRule(report, "KEY-001"); f == nil {
		t.Fatal("expected KEY-001 finding")
	}
	if report.Grade != model.GradeF {
		t.Errorf("RSA 1024 grade = %q, want F", report.Grade)
	}
}

func TestKEY002_RSA2048(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.KeySizeBits = 2048
	}))
	if f := findRule(report, "KEY-002"); f == nil {
		t.Fatal("expected KEY-002 finding for RSA 2048")
	}
}

func TestKEY003_ECDSAUnder256(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.KeyAlgorithm = model.KeyECDSA
		c.KeySizeBits = 192
	}))
	if f := findRule(report, "KEY-003"); f == nil {
		t.Fatal("expected KEY-003 finding")
	}
}

func TestKEY004_UnknownAlgo(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.KeyAlgorithm = model.KeyUnknown
	}))
	if f := findRule(report, "KEY-004"); f == nil {
		t.Fatal("expected KEY-004 finding")
	}
}

func TestKEY005_RSA3072(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.KeySizeBits = 3072
	}))
	if f := findRule(report, "KEY-005"); f == nil {
		t.Fatal("expected KEY-005 info finding for RSA 3072")
	}
}

// ── Signature rules ──

func TestSIG001_SHA1(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.SignatureAlgorithm = model.SigSHA1WithRSA
	}))
	if f := findRule(report, "SIG-001"); f == nil {
		t.Fatal("expected SIG-001 finding")
	}
	if report.Grade != model.GradeF {
		t.Errorf("SHA1 grade = %q, want F", report.Grade)
	}
}

func TestSIG002_MD5(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.SignatureAlgorithm = model.SigMD5WithRSA
	}))
	if f := findRule(report, "SIG-002"); f == nil {
		t.Fatal("expected SIG-002 finding")
	}
	if report.Grade != model.GradeF {
		t.Errorf("MD5 grade = %q, want F", report.Grade)
	}
}

// ── Chain rules ──

func TestCHN001_SelfSigned(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.Issuer.CommonName = c.Subject.CommonName
	}))
	if f := findRule(report, "CHN-001"); f == nil {
		t.Fatal("expected CHN-001 finding for self-signed")
	}
}

func TestCHN001_SelfSignedCA_NoFinding(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.IsCA = true
		c.Issuer.CommonName = c.Subject.CommonName
	}))
	if f := findRule(report, "CHN-001"); f != nil {
		t.Fatal("self-signed CA should not trigger CHN-001")
	}
}

// ── Revocation rules ──

func TestREV001_NoRevocation(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.OCSPResponderURLs = nil
		c.CRLDistributionPoints = nil
	}))
	if f := findRule(report, "REV-001"); f == nil {
		t.Fatal("expected REV-001 finding")
	}
}

func TestREV002_NoCRL_HasOCSP(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.CRLDistributionPoints = nil
		// OCSP still set
	}))
	// Should NOT trigger REV-002 (has OCSP)
	if f := findRule(report, "REV-002"); f != nil {
		t.Fatal("REV-002 should not trigger when OCSP is present")
	}
}

func TestREV002_NoOCSP_HasCRL(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.OCSPResponderURLs = nil
		// CRL still set
	}))
	if f := findRule(report, "REV-002"); f == nil {
		t.Fatal("expected REV-002 finding when OCSP missing but CRL present")
	}
}

// ── CT rules ──

func TestSCT001_NoSCTs(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.SCTs = nil
	}))
	if f := findRule(report, "SCT-001"); f == nil {
		t.Fatal("expected SCT-001 finding")
	}
}

func TestSCT001_CA_NoFinding(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.IsCA = true
		c.SCTs = nil
	}))
	if f := findRule(report, "SCT-001"); f != nil {
		t.Fatal("CA certs should not trigger SCT-001")
	}
}

// ── Wildcard rules ──

func TestWLD001_WildcardCN(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.Subject.CommonName = "*.example.com"
	}))
	if f := findRule(report, "WLD-001"); f == nil {
		t.Fatal("expected WLD-001 finding for wildcard CN")
	}
}

func TestWLD001_WildcardSAN(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.SubjectAltNames = []string{"*.example.com", "example.com"}
	}))
	if f := findRule(report, "WLD-001"); f == nil {
		t.Fatal("expected WLD-001 finding for wildcard SAN")
	}
}

func TestWLD001_NoWildcard(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.Subject.CommonName = "www.example.com"
		c.SubjectAltNames = []string{"www.example.com"}
	}))
	if f := findRule(report, "WLD-001"); f != nil {
		t.Fatal("non-wildcard should not trigger WLD-001")
	}
}

func TestWLD001_CA_NoFinding(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.IsCA = true
		c.Subject.CommonName = "*.example.com"
	}))
	if f := findRule(report, "WLD-001"); f != nil {
		t.Fatal("CA certs should not trigger WLD-001")
	}
}

// ── Agility rules ──

func TestAGI001_NonACME_LongValidity(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.Issuer.Organization = "DigiCert Inc"
		c.NotBefore = time.Now().Add(-10 * 24 * time.Hour)
		c.NotAfter = time.Now().Add(380 * 24 * time.Hour)
	}))
	if f := findRule(report, "AGI-001"); f == nil {
		t.Fatal("expected AGI-001 finding for non-ACME cert with >1yr validity")
	}
}

func TestAGI001_ACME_NoFinding(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.Issuer.Organization = "Let's Encrypt"
		c.NotBefore = time.Now().Add(-10 * 24 * time.Hour)
		c.NotAfter = time.Now().Add(80 * 24 * time.Hour)
	}))
	if f := findRule(report, "AGI-001"); f != nil {
		t.Fatal("ACME cert with short validity should not trigger AGI-001")
	}
}

// ── Grade scoring ──

func TestGradeAPlus(t *testing.T) {
	report := ScoreCertificate(certWith(nil))
	if report.Score < 95 {
		t.Skipf("healthy cert score %d < 95, can't test A+", report.Score)
	}
	if report.Grade != model.GradeAPlus {
		t.Errorf("grade = %q, want A+", report.Grade)
	}
}

func TestGradeF_ImmediateFail(t *testing.T) {
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.NotAfter = time.Now().Add(-1 * time.Hour) // expired = immediate fail
	}))
	if report.Grade != model.GradeF {
		t.Errorf("expired cert grade = %q, want F", report.Grade)
	}
}

func TestScoreNeverNegative(t *testing.T) {
	// Stack multiple failures
	report := ScoreCertificate(certWith(func(c *model.Certificate) {
		c.NotAfter = time.Now().Add(-1 * time.Hour)
		c.KeySizeBits = 512
		c.SignatureAlgorithm = model.SigMD5WithRSA
	}))
	if report.Score < 0 {
		t.Errorf("score = %d, should never be negative", report.Score)
	}
}
