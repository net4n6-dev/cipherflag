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

package zeek

import (
	"bufio"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/net4n6-dev/cipherflag/internal/certparse"
)

func fixtureLines(t *testing.T, path string) [][]byte {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	var out [][]byte
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		out = append(out, append([]byte(nil), sc.Bytes()...))
	}
	require.NoError(t, sc.Err())
	return out
}

// Zeek removed the extract-certs-pem policy the sensor relied on; its
// successor, log-certs-base64, puts each certificate's DER in x509.log's
// "cert" field. The record carries it as PEM, so ingest can store the full
// certificate rather than the handful of fields x509.log has.
func TestParseX509Record_Zeek9CarriesTheCertificate(t *testing.T) {
	lines := fixtureLines(t, "testdata/zeek9/x509.log")
	require.Len(t, lines, 2, "the fixture has the server and CA certificates")
	for _, line := range lines {
		rec, err := ParseX509Record(line)
		require.NoError(t, err)
		require.NotEmpty(t, rec.CertPEM, "certificate %s", rec.Fingerprint)
		parsed, err := certparse.ParsePEM([]byte(rec.CertPEM))
		require.NoError(t, err)
		require.Equal(t, rec.Fingerprint, parsed.FingerprintSHA256,
			"x509.log's fingerprint is the SHA-256 of the certificate it carries")
	}
}

func TestParseX509Record_CertAbsentOrUnreadable(t *testing.T) {
	rec, err := ParseX509Record([]byte(`{"fingerprint":"aa"}`))
	require.NoError(t, err)
	require.Empty(t, rec.CertPEM, "a sensor without log-certs-base64 sends no certificate")

	rec, err = ParseX509Record([]byte(`{"fingerprint":"aa","cert":"not base64!"}`))
	require.NoError(t, err, "an unreadable cert field does not lose the rest of the record")
	require.Empty(t, rec.CertPEM)
	require.Equal(t, "aa", rec.Fingerprint)
}
