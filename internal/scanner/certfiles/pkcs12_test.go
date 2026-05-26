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

package certfiles

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func TestDetectPKCS12_EmitsPrivateKey(t *testing.T) {
	dir := t.TempDir()
	p12Path := filepath.Join(dir, "leaf.p12")

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leaf.test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	p12Bytes, _ := pkcs12.Modern.Encode(key, cert, nil, "password")
	os.WriteFile(p12Path, p12Bytes, 0o600)

	obs, err := DetectPKCS12(context.Background(), p12Path, []string{"password"})
	if err != nil {
		t.Fatalf("DetectPKCS12: %v", err)
	}
	if len(obs) != 1 || obs[0].Evidence != "pkcs12_entry" {
		t.Errorf("obs = %+v, want one pkcs12_entry row", obs)
	}
}
