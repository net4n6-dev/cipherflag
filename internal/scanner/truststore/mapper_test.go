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
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func makePEMBundle(t *testing.T, count int) []byte {
	t.Helper()
	var buf bytes.Buffer
	now := time.Now()
	for i := 0; i < count; i++ {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1)),
			Subject:      pkix.Name{CommonName: "ca-" + string(rune('a'+i))},
			NotBefore:    now, NotAfter: now.Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true,
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func TestMapPEM_ParsesEachCertBlock(t *testing.T) {
	data := makePEMBundle(t, 3)
	s := &Scanner{}
	trust, priv := s.mapBundle(bundleObservation{
		Source: "os_bundle", SourceDetail: "test-bundle",
		Format: "pem", Data: data,
	})
	if len(trust) != 3 {
		t.Errorf("trust = %d, want 3", len(trust))
	}
	if len(priv) != 0 {
		t.Errorf("priv = %d, want 0 for PEM bundle", len(priv))
	}
	for i, obs := range trust {
		if obs.Source != "os_bundle" || obs.SourceDetail != "test-bundle" {
			t.Errorf("obs[%d] = %+v, want source=os_bundle / detail=test-bundle", i, obs)
		}
		if len(obs.CAFingerprint) != 64 {
			t.Errorf("obs[%d] CAFingerprint len = %d, want 64", i, len(obs.CAFingerprint))
		}
	}
}

func TestMapDER_SingleCert(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "der-test"},
		NotBefore:    time.Now(), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)

	s := &Scanner{}
	trust, priv := s.mapBundle(bundleObservation{
		Source: "os_bundle", SourceDetail: "test",
		Format: "der", Data: certDER,
	})
	if len(trust) != 1 || len(priv) != 0 {
		t.Errorf("trust=%d priv=%d, want 1/0", len(trust), len(priv))
	}
}
