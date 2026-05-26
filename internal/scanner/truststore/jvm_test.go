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

package truststore

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
)

// makeJKSFixture generates an in-memory JKS bundle with N trusted certs
// and one private-key entry (with a self-signed cert chain).
func makeJKSFixture(t *testing.T, password string) []byte {
	t.Helper()
	ks := keystore.New()
	now := time.Now()

	for i := 0; i < 2; i++ {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 100)),
			Subject:      pkix.Name{CommonName: "trusted-ca"},
			NotBefore:    now, NotAfter: now.Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true,
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		ks.SetTrustedCertificateEntry("trusted-"+string(rune('a'+i)), keystore.TrustedCertificateEntry{
			CreationTime: now,
			Certificate:  keystore.Certificate{Type: "X.509", Content: certDER},
		})
	}

	// One PrivateKeyEntry.
	pkKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject:      pkix.Name{CommonName: "pk-entry"},
		NotBefore:    now, NotAfter: now.Add(time.Hour),
	}
	pkCertDER, _ := x509.CreateCertificate(rand.Reader, pkTmpl, pkTmpl, &pkKey.PublicKey, pkKey)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(pkKey)
	ks.SetPrivateKeyEntry("private-1", keystore.PrivateKeyEntry{
		CreationTime: now,
		PrivateKey:   pkcs8,
		CertificateChain: []keystore.Certificate{{Type: "X.509", Content: pkCertDER}},
	}, []byte(password))

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		t.Fatalf("Store: %v", err)
	}
	return buf.Bytes()
}

func TestMapJKS_SplitsTrustedAndPrivate(t *testing.T) {
	s := &Scanner{jvmPasswords: []string{"changeit"}}
	data := makeJKSFixture(t, "changeit")

	b := bundleObservation{
		Path: "test.jks", Source: "jvm_cacerts", SourceDetail: "test.jks",
		Format: "jks", Data: data,
	}
	trust, priv := s.mapJKS(b)
	if len(trust) != 2 {
		t.Errorf("trust = %d, want 2", len(trust))
	}
	if len(priv) != 1 {
		t.Errorf("priv = %d, want 1", len(priv))
	}
	if len(priv) > 0 && priv[0].Evidence != "jks_private_key_entry" {
		t.Errorf("priv[0].Evidence = %s, want jks_private_key_entry", priv[0].Evidence)
	}
}
