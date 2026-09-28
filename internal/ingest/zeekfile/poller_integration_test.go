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

package zeekfile

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
	"github.com/net4n6-dev/cipherflag/internal/testdb"
)

// The fixture's server and CA certificates (internal/ingest/zeek/testdata/zeek9).
const (
	fixtureServerFP = "b5341cf253692da10c93f8197a443817861e06f58bd6c691ab25a9709f25043c"
	fixtureCAFP     = "a343cadac5724c91ba6893f38386151f997918309d0fcd308eba63c80292ae40"
)

// Real Zeek 9 logs, through the real ingest pipeline, into Postgres: the
// certificates are stored with everything in them (the PEM from
// log-certs-base64) and the TLS sessions as observations.
func TestPoller_StoresZeekCertificatesAndSessions(t *testing.T) {
	ctx := context.Background()
	dsn := testdb.Require(t)
	st, err := store.NewPostgresStore(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.Migrate(ctx))

	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "x509.log"), fixture(t, "x509.log")...)
	writeLines(t, filepath.Join(dir, "ssl.log"), fixture(t, "ssl.log")...)
	p := New(Config{LogDir: dir, Interval: time.Hour}, st, ingest.NewUnifiedIngester(st))

	cleanup := func() {
		conn, err := pgx.Connect(ctx, dsn)
		require.NoError(t, err)
		defer conn.Close(ctx)
		// observations go with their certificates (ON DELETE CASCADE).
		_, err = conn.Exec(ctx, `DELETE FROM certificates WHERE fingerprint_sha256 = ANY($1)`,
			[]string{fixtureServerFP, fixtureCAFP})
		require.NoError(t, err)
		_, err = conn.Exec(ctx, `DELETE FROM ingestion_state WHERE source_name = $1`, p.sourceName())
		require.NoError(t, err)
	}
	cleanup()
	t.Cleanup(cleanup)

	require.NoError(t, p.PollOnce(ctx))

	server, err := st.GetCertificate(ctx, fixtureServerFP)
	require.NoError(t, err)
	require.NotNil(t, server, "the server certificate is stored")
	require.Equal(t, "tls.zeek-fixture.test", server.Subject.CommonName)
	require.Equal(t, "CipherFlag Fixtures", server.Subject.Organization)
	require.Equal(t, "Zeek Fixture Root CA", server.Issuer.CommonName)
	require.Equal(t, model.KeyECDSA, server.KeyAlgorithm)
	require.ElementsMatch(t, []string{"tls.zeek-fixture.test", "alt.zeek-fixture.test"}, server.SubjectAltNames)
	require.Equal(t, []string{"http://ocsp.zeek-fixture.test"}, server.OCSPResponderURLs,
		"only the certificate itself has these: it came from the PEM")
	require.Equal(t, []string{"http://crl.zeek-fixture.test/ca.crl"}, server.CRLDistributionPoints)
	require.Equal(t, model.SourceZeekPassive, server.SourceDiscovery)

	ca, err := st.GetCertificate(ctx, fixtureCAFP)
	require.NoError(t, err)
	require.NotNil(t, ca)
	require.True(t, ca.IsCA)

	obs, err := st.GetObservations(ctx, fixtureServerFP, 10)
	require.NoError(t, err)
	require.Len(t, obs, 2, "two TLS 1.2 sessions served the server certificate")
	names := []string{obs[0].ServerName, obs[1].ServerName}
	require.ElementsMatch(t, []string{"tls.zeek-fixture.test", "alt.zeek-fixture.test"}, names)
	for _, o := range obs {
		require.Equal(t, "127.0.0.1", o.ServerIP)
		require.Equal(t, 4443, o.ServerPort)
		require.Equal(t, model.TLSVersion12, o.NegotiatedVersion, "Zeek's TLSv12 is mapped")
	}

	// A second poll finds nothing new.
	require.NoError(t, p.PollOnce(ctx))
	obs, err = st.GetObservations(ctx, fixtureServerFP, 10)
	require.NoError(t, err)
	require.Len(t, obs, 2)
}
