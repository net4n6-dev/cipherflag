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
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

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
