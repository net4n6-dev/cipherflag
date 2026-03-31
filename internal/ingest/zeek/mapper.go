package zeek

import (
	"strings"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// MapX509ToCertificate converts a parsed Zeek X509Record into a CipherFlag Certificate.
func MapX509ToCertificate(rec *X509Record) *model.Certificate {
	now := time.Now().UTC()

	// Combine all SAN types into a single slice.
	var sans []string
	sans = append(sans, rec.SANsDNS...)
	sans = append(sans, rec.SANsIP...)
	sans = append(sans, rec.SANsEmail...)

	return &model.Certificate{
		FingerprintSHA256: rec.Fingerprint,
		Subject: model.DistinguishedName{
			CommonName:   rec.SubjectCN,
			Organization: rec.SubjectOrg,
			Full:         rec.SubjectFull,
		},
		Issuer: model.DistinguishedName{
			CommonName:   rec.IssuerCN,
			Organization: rec.IssuerOrg,
			Full:         rec.IssuerFull,
		},
		SerialNumber:       rec.Serial,
		NotBefore:          rec.NotValidBefore,
		NotAfter:           rec.NotValidAfter,
		KeyAlgorithm:       mapKeyAlgorithm(rec.KeyAlg, rec.KeyType),
		KeySizeBits:        rec.KeyLength,
		SignatureAlgorithm: mapSigAlgorithm(rec.SigAlg),
		SubjectAltNames:    sans,
		IsCA:               rec.IsCA,
		SourceDiscovery:    model.SourceZeekPassive,
		FirstSeen:          now,
		LastSeen:           now,
	}
}

// MapSSLToObservations converts a parsed Zeek SSLRecord into CertificateObservation entries,
// one per certificate fingerprint in the chain.
func MapSSLToObservations(rec *SSLRecord) []*model.CertificateObservation {
	var observations []*model.CertificateObservation

	tlsVersion := mapTLSVersion(rec.Version)
	cipherStrength := classifyCipherStrength(rec.Cipher)

	for _, fp := range rec.CertChainFPs {
		obs := &model.CertificateObservation{
			CertFingerprint:   fp,
			ServerIP:          rec.ServerIP,
			ServerPort:        rec.ServerPort,
			ServerName:        rec.ServerName,
			ClientIP:          rec.ClientIP,
			NegotiatedVersion: tlsVersion,
			NegotiatedCipher:  rec.Cipher,
			CipherStrength:    cipherStrength,
			JA3Fingerprint:    rec.JA3,
			JA3SFingerprint:   rec.JA3S,
			Source:            model.SourceZeekPassive,
			ObservedAt:        rec.Timestamp,
		}
		observations = append(observations, obs)
	}

	return observations
}

// mapKeyAlgorithm maps Zeek key algorithm and key type strings to the model's KeyAlgorithm.
func mapKeyAlgorithm(alg, keyType string) model.KeyAlgorithm {
	combined := strings.ToLower(alg + " " + keyType)

	switch {
	case strings.Contains(combined, "rsa"):
		return model.KeyRSA
	case strings.Contains(combined, "ec") || strings.Contains(combined, "ecdsa"):
		return model.KeyECDSA
	case strings.Contains(combined, "ed25519"):
		return model.KeyEd25519
	default:
		return model.KeyUnknown
	}
}

// mapSigAlgorithm maps a Zeek signature algorithm string to the model's SignatureAlgorithm.
func mapSigAlgorithm(alg string) model.SignatureAlgorithm {
	lower := strings.ToLower(alg)

	switch {
	case strings.Contains(lower, "sha256") && strings.Contains(lower, "rsa"):
		return model.SigSHA256WithRSA
	case strings.Contains(lower, "sha384") && strings.Contains(lower, "rsa"):
		return model.SigSHA384WithRSA
	case strings.Contains(lower, "sha512") && strings.Contains(lower, "rsa"):
		return model.SigSHA512WithRSA
	case strings.Contains(lower, "sha1") && strings.Contains(lower, "rsa"):
		return model.SigSHA1WithRSA
	case strings.Contains(lower, "md5"):
		return model.SigMD5WithRSA
	case strings.Contains(lower, "ecdsa") && strings.Contains(lower, "sha384"):
		return model.SigECDSAWithSHA384
	case strings.Contains(lower, "ecdsa") && strings.Contains(lower, "sha256"):
		return model.SigECDSAWithSHA256
	case strings.Contains(lower, "ed25519"):
		return model.SigEd25519Sig
	default:
		return model.SigUnknown
	}
}

// mapTLSVersion maps Zeek TLS version strings to the model's TLSVersion.
func mapTLSVersion(v string) model.TLSVersion {
	switch v {
	case "TLSv13", "TLSv1.3":
		return model.TLSVersion13
	case "TLSv12", "TLSv1.2":
		return model.TLSVersion12
	case "TLSv11", "TLSv1.1":
		return model.TLSVersion11
	case "TLSv10", "TLSv1.0", "TLSv1":
		return model.TLSVersion10
	case "SSLv30", "SSLv3":
		return model.TLSVersionSSL30
	default:
		return model.TLSVersionUnk
	}
}

// classifyCipherStrength classifies a TLS cipher suite name into a strength category.
func classifyCipherStrength(cipher string) model.CipherStrength {
	lower := strings.ToLower(cipher)

	switch {
	case strings.Contains(lower, "null") || strings.Contains(lower, "export"):
		return model.StrengthInsecure
	case strings.Contains(lower, "3des") || strings.Contains(lower, "rc4") ||
		strings.Contains(lower, "des_cbc"):
		return model.StrengthWeak
	case strings.Contains(lower, "chacha20") || strings.Contains(lower, "aes_256_gcm") ||
		strings.Contains(lower, "aes256gcm"):
		return model.StrengthBest
	case strings.Contains(lower, "aes_128_gcm") || strings.Contains(lower, "aes128gcm"):
		return model.StrengthStrong
	case strings.Contains(lower, "aes"):
		return model.StrengthAcceptable
	default:
		return model.StrengthUnknown
	}
}
