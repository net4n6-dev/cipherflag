//go:build integration

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

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/net4n6-dev/cipherflag/internal/certparse"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/scanner/truststore"
	"github.com/net4n6-dev/cipherflag/internal/store"
	"github.com/net4n6-dev/cipherflag/internal/testdb"
)

func integrationStore(t *testing.T) *store.PostgresStore {
	t.Helper()
	ctx := context.Background()
	st, err := store.NewPostgresStore(ctx, testdb.Require(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.Migrate(ctx))
	return st
}

func seedHost(t *testing.T, st *store.PostgresStore, name string) string {
	t.Helper()
	h := &model.Host{CanonicalHostname: name, HostType: "server", FirstSeen: time.Now(), LastSeen: time.Now()}
	require.NoError(t, st.UpsertHost(context.Background(), h))
	require.NotEmpty(t, h.ID)
	return h.ID
}

func scannedCert(t *testing.T, cn string, isCA bool) (pemText, fingerprint string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: isCA, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	p := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	c, err := certparse.ParsePEM([]byte(p))
	require.NoError(t, err)
	return p, c.FingerprintSHA256
}

// host_trust_store and cert_private_key_holding reference certificates by
// fingerprint, and scan-truststore only wrote the rows, so every row for a
// certificate CipherFlag had not already seen failed its foreign key and was
// dropped with a warning while the command reported success: a scan of a
// macOS host found 414 trust-store entries and stored none. The scanned
// certificates are now stored first.
func TestPersistTrustStoreScan_StoresUnknownCertificatesFirst(t *testing.T) {
	st := integrationStore(t)
	ctx := context.Background()
	hostID := seedHost(t, st, "truststore-scan.test")

	caPEM, caFP := scannedCert(t, "Scanned Root CA", true)
	leafPEM, leafFP := scannedCert(t, "held-key.truststore.test", false)
	result := truststore.ScanResult{
		TrustStore: []model.TrustStoreObservation{
			{HostID: hostID, CAFingerprint: caFP, Source: "os_bundle", SourceDetail: "/etc/ssl/certs/ca-certificates.crt", CAPEM: caPEM},
			// The same CA in a second store: one certificate, two rows.
			{HostID: hostID, CAFingerprint: caFP, Source: "jvm_cacerts", SourceDetail: "/usr/lib/jvm/cacerts", CAPEM: caPEM},
		},
		PrivateKey: []model.PrivateKeyObservation{
			{HostID: hostID, CertFingerprint: leafFP, Evidence: "jks_private_key_entry", Source: "truststore", SourceDetail: "/opt/app/keystore.jks", CertPEM: leafPEM},
		},
	}

	require.NoError(t, persistTrustStoreScan(ctx, st, ingest.NewUnifiedIngester(st), hostID, result, reconcileScope{}))

	ca, err := st.GetCertificate(ctx, caFP)
	require.NoError(t, err)
	require.NotNil(t, ca, "the scanned CA certificate must be stored")
	require.Equal(t, "Scanned Root CA", ca.Subject.CommonName)
	require.True(t, ca.IsCA)

	leaf, err := st.GetCertificate(ctx, leafFP)
	require.NoError(t, err)
	require.NotNil(t, leaf, "the certificate whose key is held must be stored")

	trust, err := st.ListTrustStoreHoldingsForHost(ctx, hostID)
	require.NoError(t, err)
	require.Len(t, trust, 2, "both trust-store rows must land")

	holders, err := st.HostsHoldingCAKey(ctx, leafFP, true)
	require.NoError(t, err)
	require.Equal(t, []store.CAHolderRow{{HostID: hostID, Evidence: "jks_private_key_entry"}}, holders,
		"the private-key row must land")
}

// A trust-store CA or held key removed from a host used to stay in the
// inventory for ever: nothing pruned the rows a scan no longer saw. Each
// scan now removes, per source it fully covered, the rows it did not
// refresh; a source whose discoverer failed, or that had a row it could not
// write, is left alone.
func TestPersistTrustStoreScan_ReconcilesCoveredSources(t *testing.T) {
	st := integrationStore(t)
	ctx := context.Background()
	ing := ingest.NewUnifiedIngester(st)
	hostID := seedHost(t, st, "truststore-reconcile.test")

	type ca struct{ pem, fp string }
	mk := func(cn string, isCA bool) ca { p, fp := scannedCert(t, cn, isCA); return ca{p, fp} }
	osGone, osStays, osNew := mk("OS Removed CA", true), mk("OS Kept CA", true), mk("OS New CA", true)
	jvmGone, runtimeKept, appGone := mk("JVM CA", true), mk("Runtime CA", true), mk("App Config CA", true)
	heldKey := mk("held-key.reconcile.test", false)

	trust := func(c ca, source, detail string) model.TrustStoreObservation {
		return model.TrustStoreObservation{HostID: hostID, CAFingerprint: c.fp, Source: source, SourceDetail: detail, CAPEM: c.pem}
	}
	key := model.PrivateKeyObservation{HostID: hostID, CertFingerprint: heldKey.fp, Evidence: "jks_private_key_entry",
		Source: "truststore", SourceDetail: "/opt/app/keystore.jks", CertPEM: heldKey.pem}
	all := reconcileScope{TrustSources: []string{"app_config", "jvm_cacerts", "lang_runtime", "os_bundle"}, PrivateKeys: true}

	sources := func() map[string][]string {
		rows, err := st.ListTrustStoreHoldingsForHost(ctx, hostID)
		require.NoError(t, err)
		out := map[string][]string{}
		for _, r := range rows {
			out[r.Source] = append(out[r.Source], r.CAFingerprint)
		}
		return out
	}
	keyHeld := func() bool {
		holders, err := st.HostsHoldingCAKey(ctx, heldKey.fp, true)
		require.NoError(t, err)
		return len(holders) == 1
	}

	// Scan 1: everything present and every discoverer succeeded.
	require.NoError(t, persistTrustStoreScan(ctx, st, ing, hostID, truststore.ScanResult{
		TrustStore: []model.TrustStoreObservation{
			trust(osGone, "os_bundle", "/etc/ssl/certs/a.pem"),
			trust(osStays, "os_bundle", "/etc/ssl/certs/b.pem"),
			trust(jvmGone, "jvm_cacerts", "/usr/lib/jvm/cacerts"),
			trust(runtimeKept, "lang_runtime", "/usr/lib/python3/certifi/cacert.pem"),
			trust(appGone, "app_config", "nginx:/etc/nginx/nginx.conf:ssl_trusted_certificate"),
		},
		PrivateKey: []model.PrivateKeyObservation{key},
	}, all))
	require.True(t, keyHeld())

	// Scan 2: one OS CA removed and one added, the JVM CA and the held key
	// gone but the JVM discoverer failed (so neither the JVM store nor
	// private keys were covered), the app-config bundle emptied.
	require.NoError(t, persistTrustStoreScan(ctx, st, ing, hostID, truststore.ScanResult{
		TrustStore: []model.TrustStoreObservation{
			trust(osStays, "os_bundle", "/etc/ssl/certs/b.pem"),
			trust(osNew, "os_bundle", "/etc/ssl/certs/c.pem"),
			trust(runtimeKept, "lang_runtime", "/usr/lib/python3/certifi/cacert.pem"),
		},
	}, reconcileScope{TrustSources: []string{"app_config", "lang_runtime", "os_bundle"}, PrivateKeys: false}))

	got := sources()
	require.ElementsMatch(t, []string{osStays.fp, osNew.fp}, got["os_bundle"], "the removed OS CA is pruned; the others stay")
	require.Equal(t, []string{jvmGone.fp}, got["jvm_cacerts"], "a source whose discoverer failed is not pruned")
	require.Equal(t, []string{runtimeKept.fp}, got["lang_runtime"])
	require.Empty(t, got["app_config"], "the emptied app-config bundle is pruned")
	require.True(t, keyHeld(), "private keys were not covered, so the held key stays")

	// Scan 3: the OS store has a row that cannot be written (a CA with no
	// PEM that CipherFlag does not know). The source is not fully written,
	// so it is not pruned, even though its other CAs were not seen.
	require.NoError(t, persistTrustStoreScan(ctx, st, ing, hostID, truststore.ScanResult{
		TrustStore: []model.TrustStoreObservation{
			{HostID: hostID, CAFingerprint: "not-a-known-fingerprint", Source: "os_bundle", SourceDetail: "/etc/ssl/certs/x.pem"},
		},
	}, reconcileScope{TrustSources: []string{"os_bundle"}}))
	require.ElementsMatch(t, []string{osStays.fp, osNew.fp}, sources()["os_bundle"], "a source with a failed row is not pruned")

	// Scan 4: private keys covered and the key gone: it is pruned.
	require.NoError(t, persistTrustStoreScan(ctx, st, ing, hostID, truststore.ScanResult{}, reconcileScope{PrivateKeys: true}))
	require.False(t, keyHeld(), "a held key no longer found is pruned when private keys were covered")
}
