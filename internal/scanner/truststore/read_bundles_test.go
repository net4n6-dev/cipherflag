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
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/stretchr/testify/require"
	pkcs12lib "software.sslmate.com/src/go-pkcs12"
)

// scan-truststore removes rows a scan no longer saw, but only for bundles
// this scan actually read. The discoverers skip what they cannot read (a
// permission error, a locked keychain, a failed probe, a JKS password that
// does not match) without reporting an error, so "the source's discoverer
// did not fail" said nothing: one unreadable bundle, or a run with a
// different JAVA_HOME, would have removed every row for the source. A
// bundle is now reconciled only if it was read, and decoded where it has a
// binary format; everything else is left as it was.

func TestScan_ReadBundlesListsOnlyBundlesActuallyRead(t *testing.T) {
	leaf, key := testCert(t, "p12-leaf", false)
	ca, _ := testCert(t, "p12-ca", true)
	p12, err := pkcs12lib.Modern.Encode(key, leaf, []*x509.Certificate{ca}, "changeit")
	require.NoError(t, err)

	bundles := []bundleObservation{
		{Path: "/etc/ssl/a.pem", Source: "os_bundle", SourceDetail: "/etc/ssl/a.pem", Format: "pem", Data: makePEMBundle(t, 2)},
		// Read, but every CA has been removed: authoritative, so its rows go.
		{Path: "/etc/ssl/empty.pem", Source: "os_bundle", SourceDetail: "/etc/ssl/empty.pem", Format: "pem", Data: []byte{}},
		{Path: "/jvm/ok.p12", Source: "jvm_cacerts", SourceDetail: "/jvm/ok.p12", Format: "pkcs12", Data: p12},
		// Read but not decodable: contents unknown, so not reconciled.
		{Path: "/jvm/wrong-password.jks", Source: "jvm_cacerts", SourceDetail: "/jvm/wrong-password.jks", Format: "jks", Data: makeJKSFixture(t, "other-password")},
		{Path: "/etc/ssl/garbage.der", Source: "os_bundle", SourceDetail: "/etc/ssl/garbage.der", Format: "der", Data: []byte("not der")},
	}
	s := &Scanner{jvmPasswords: []string{"changeit"}}
	s.discoverers = []discoverer{{Name: "fixture", Run: func(context.Context, *Scanner) ([]bundleObservation, error) {
		return bundles, nil
	}}}

	result, err := s.Scan(context.Background())
	require.NoError(t, err)
	require.ElementsMatch(t, []BundleRef{
		{Source: "os_bundle", SourceDetail: "/etc/ssl/a.pem"},
		{Source: "os_bundle", SourceDetail: "/etc/ssl/empty.pem"},
		{Source: "jvm_cacerts", SourceDetail: "/jvm/ok.p12", KeyStore: true},
	}, result.ReadBundles)
}

// makeJKSWithKeyPasswords is a JKS locked with storePassword holding one
// trusted CA and one private-key entry per keyPasswords element, each
// encrypted with that password (keytool allows a key password different
// from the store's).
func makeJKSWithKeyPasswords(t *testing.T, storePassword string, keyPasswords ...string) []byte {
	t.Helper()
	ks := keystore.New()
	now := time.Now()
	ca, _ := testCert(t, "jks-ca", true)
	require.NoError(t, ks.SetTrustedCertificateEntry("ca", keystore.TrustedCertificateEntry{
		CreationTime: now, Certificate: keystore.Certificate{Type: "X.509", Content: ca.Raw},
	}))
	for i, pw := range keyPasswords {
		leaf, key := testCert(t, fmt.Sprintf("jks-key-%d", i), false)
		pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)
		require.NoError(t, ks.SetPrivateKeyEntry(fmt.Sprintf("key-%d", i), keystore.PrivateKeyEntry{
			CreationTime: now, PrivateKey: pkcs8,
			CertificateChain: []keystore.Certificate{{Type: "X.509", Content: leaf.Raw}},
		}, []byte(pw)))
	}
	var buf bytes.Buffer
	require.NoError(t, ks.Store(&buf, []byte(storePassword)))
	return buf.Bytes()
}

// A keystore opens with the store password, but a private-key entry
// encrypted with its own key password does not decode and was skipped
// silently. The keystore still counted as read for its held keys, so the
// holding recorded for that entry by an earlier scan was removed although
// the key is still there. A keystore is now authoritative for its held keys
// only when every private-key entry in it was read; its trusted CAs are
// still reconciled.
func TestScan_KeystoreWithAnUnreadableKeyEntryIsNotAuthoritativeForKeys(t *testing.T) {
	bundles := []bundleObservation{
		// Trusted CA readable, the only key entry not.
		{Path: "/opt/a.jks", Source: "jvm_cacerts", SourceDetail: "/opt/a.jks", Format: "jks",
			Data: makeJKSWithKeyPasswords(t, "changeit", "other-key-password")},
		// One key entry readable, one not.
		{Path: "/opt/b.jks", Source: "jvm_cacerts", SourceDetail: "/opt/b.jks", Format: "jks",
			Data: makeJKSWithKeyPasswords(t, "changeit", "changeit", "other-key-password")},
		// Every key entry readable: authoritative, as before.
		{Path: "/opt/c.jks", Source: "jvm_cacerts", SourceDetail: "/opt/c.jks", Format: "jks",
			Data: makeJKSWithKeyPasswords(t, "changeit", "changeit")},
	}
	s := &Scanner{jvmPasswords: []string{"changeit"}}
	s.discoverers = []discoverer{{Name: "fixture", Run: func(context.Context, *Scanner) ([]bundleObservation, error) {
		return bundles, nil
	}}}

	result, err := s.Scan(context.Background())
	require.NoError(t, err)
	require.ElementsMatch(t, []BundleRef{
		{Source: "jvm_cacerts", SourceDetail: "/opt/a.jks"},
		{Source: "jvm_cacerts", SourceDetail: "/opt/b.jks"},
		{Source: "jvm_cacerts", SourceDetail: "/opt/c.jks", KeyStore: true},
	}, result.ReadBundles)
	keys := map[string]int{}
	for _, k := range result.PrivateKey {
		keys[k.SourceDetail]++
	}
	require.Equal(t, map[string]int{"/opt/b.jks": 1, "/opt/c.jks": 1}, keys, "the readable key entries are still reported")
}

func TestReadAppConfigBundles_ReportsTheBundlesItRead(t *testing.T) {
	dir := t.TempDir()
	readable := filepath.Join(dir, "cas.pem")
	require.NoError(t, os.WriteFile(readable, makePEMBundleN(t, 1), 0o644))
	refs := []TrustBundleRef{
		{Server: "nginx", ConfigPath: "/etc/nginx/a.conf", Directive: "ssl_trusted_certificate", BundlePath: readable},
		{Server: "nginx", ConfigPath: "/etc/nginx/b.conf", Directive: "ssl_trusted_certificate", BundlePath: filepath.Join(dir, "missing.pem")},
	}
	obs, read := ReadAppConfigBundles(refs)
	require.Len(t, obs, 1)
	require.Equal(t, []BundleRef{{Source: "app_config", SourceDetail: "nginx:/etc/nginx/a.conf:ssl_trusted_certificate"}}, read,
		"an unreadable bundle is not reported as read")
}
