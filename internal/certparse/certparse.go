package certparse

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/cyberflag-ai/cipherflag/internal/model"
)

// ParsePEM decodes a PEM-encoded certificate and returns a model.Certificate.
func ParsePEM(pemData []byte) (*model.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("certparse: no PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("certparse: unexpected PEM block type %q", block.Type)
	}
	return parseDER(block.Bytes, string(pemData))
}

// ParseDER parses a DER-encoded certificate and returns a model.Certificate.
func ParseDER(derData []byte) (*model.Certificate, error) {
	return parseDER(derData, "")
}

func parseDER(derData []byte, rawPEM string) (*model.Certificate, error) {
	x, err := x509.ParseCertificate(derData)
	if err != nil {
		return nil, fmt.Errorf("certparse: %w", err)
	}

	fp := sha256.Sum256(x.Raw)
	fingerprint := hex.EncodeToString(fp[:])

	now := time.Now()

	cert := &model.Certificate{
		FingerprintSHA256: fingerprint,
		Subject:           mapDN(x.Subject),
		Issuer:            mapDN(x.Issuer),
		SerialNumber:      x.SerialNumber.Text(16),
		NotBefore:         x.NotBefore,
		NotAfter:          x.NotAfter,
		KeyAlgorithm:      mapKeyAlgorithm(x.PublicKey),
		KeySizeBits:       keySize(x.PublicKey),
		SignatureAlgorithm: mapSignatureAlgorithm(x.SignatureAlgorithm),
		SubjectAltNames:   x.DNSNames,
		IsCA:              x.IsCA,
		KeyUsage:          mapKeyUsage(x.KeyUsage),
		ExtendedKeyUsage:  mapExtKeyUsage(x.ExtKeyUsage),
		OCSPResponderURLs: x.OCSPServer,
		CRLDistributionPoints: x.CRLDistributionPoints,
		SourceDiscovery:   model.SourceZeekPassive,
		RawPEM:            rawPEM,
		FirstSeen:         now,
		LastSeen:          now,
	}

	if x.MaxPathLen > 0 || x.MaxPathLenZero {
		pathLen := x.MaxPathLen
		cert.BasicConstraintsPathLen = &pathLen
	}

	return cert, nil
}

func mapDN(name pkix.Name) model.DistinguishedName {
	return model.DistinguishedName{
		CommonName:         name.CommonName,
		Organization:       strings.Join(name.Organization, ", "),
		OrganizationalUnit: strings.Join(name.OrganizationalUnit, ", "),
		Country:            strings.Join(name.Country, ", "),
		State:              strings.Join(name.Province, ", "),
		Locality:           strings.Join(name.Locality, ", "),
		Full:               name.String(),
	}
}

func mapKeyAlgorithm(pub interface{}) model.KeyAlgorithm {
	switch pub.(type) {
	case *rsa.PublicKey:
		return model.KeyRSA
	case *ecdsa.PublicKey:
		return model.KeyECDSA
	case ed25519.PublicKey:
		return model.KeyEd25519
	default:
		return model.KeyUnknown
	}
}

func keySize(pub interface{}) int {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

func mapSignatureAlgorithm(alg x509.SignatureAlgorithm) model.SignatureAlgorithm {
	switch alg {
	case x509.SHA1WithRSA:
		return model.SigSHA1WithRSA
	case x509.SHA256WithRSA:
		return model.SigSHA256WithRSA
	case x509.SHA384WithRSA:
		return model.SigSHA384WithRSA
	case x509.SHA512WithRSA:
		return model.SigSHA512WithRSA
	case x509.ECDSAWithSHA256:
		return model.SigECDSAWithSHA256
	case x509.ECDSAWithSHA384:
		return model.SigECDSAWithSHA384
	case x509.PureEd25519:
		return model.SigEd25519Sig
	case x509.MD5WithRSA:
		return model.SigMD5WithRSA
	default:
		return model.SigUnknown
	}
}

func mapKeyUsage(ku x509.KeyUsage) []string {
	var usages []string
	pairs := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "Digital Signature"},
		{x509.KeyUsageContentCommitment, "Content Commitment"},
		{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
		{x509.KeyUsageDataEncipherment, "Data Encipherment"},
		{x509.KeyUsageKeyAgreement, "Key Agreement"},
		{x509.KeyUsageCertSign, "Certificate Sign"},
		{x509.KeyUsageCRLSign, "CRL Sign"},
		{x509.KeyUsageEncipherOnly, "Encipher Only"},
		{x509.KeyUsageDecipherOnly, "Decipher Only"},
	}
	for _, p := range pairs {
		if ku&p.bit != 0 {
			usages = append(usages, p.name)
		}
	}
	return usages
}

func mapExtKeyUsage(ekus []x509.ExtKeyUsage) []string {
	var usages []string
	for _, eku := range ekus {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "Email Protection")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSP Signing")
		default:
			usages = append(usages, fmt.Sprintf("Unknown(%d)", int(eku)))
		}
	}
	return usages
}
