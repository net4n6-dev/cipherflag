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

package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// On conflict, UpsertCertificate used to update only last_seen,
// source_discovery, raw_pem and the key IDs, so a certificate stored blank
// (earlier versions kept only the fingerprint of a PEM-only discovery) stayed
// blank however often it was seen again with its metadata. Each metadata
// column is now filled when it is empty and never overwritten when it is set.

type certRow struct {
	subjectCN, issuerCN, serial, keyAlg, sigAlg, source, sans string
	notBefore, notAfter, firstSeen, lastSeen                  time.Time
	keySize                                                   int
	isCA                                                      bool
}

func readCertRow(t *testing.T, st *PostgresStore, fp string) certRow {
	t.Helper()
	var r certRow
	err := st.pool.QueryRow(context.Background(), `
		SELECT subject_cn, issuer_cn, serial_number, key_algorithm, signature_algorithm,
		       source_discovery, subject_alt_names::text, not_before, not_after,
		       first_seen, last_seen, key_size_bits, is_ca
		FROM certificates WHERE fingerprint_sha256 = $1`, fp).Scan(
		&r.subjectCN, &r.issuerCN, &r.serial, &r.keyAlg, &r.sigAlg,
		&r.source, &r.sans, &r.notBefore, &r.notAfter,
		&r.firstSeen, &r.lastSeen, &r.keySize, &r.isCA)
	require.NoError(t, err)
	return r
}

func TestUpsertCertificate_FillsOnlyEmptyColumnsOnConflict(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	fp := "refill-0001"
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM certificates WHERE fingerprint_sha256 = $1`, fp)
	})
	firstSeen := time.Now().Add(-48 * time.Hour).Truncate(time.Microsecond)

	// 1. The blank row earlier versions stored: fingerprint and PEM only.
	require.NoError(t, st.UpsertCertificate(ctx, &model.Certificate{
		FingerprintSHA256: fp,
		RawPEM:            "pem",
		SourceDiscovery:   "api",
		FirstSeen:         firstSeen,
		LastSeen:          firstSeen,
	}))
	blank := readCertRow(t, st, fp)
	require.Equal(t, "", blank.subjectCN)

	// 2. Seen again with its metadata: every empty column is filled.
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	notAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	seen := time.Now().Truncate(time.Microsecond)
	full := &model.Certificate{
		FingerprintSHA256:  fp,
		Subject:            model.DistinguishedName{CommonName: "Refill Issuing CA"},
		Issuer:             model.DistinguishedName{CommonName: "Refill Root CA"},
		SerialNumber:       "1f2e",
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		KeyAlgorithm:       model.KeyECDSA,
		KeySizeBits:        256,
		SignatureAlgorithm: model.SigECDSAWithSHA256,
		SubjectAltNames:    []string{"ca.refill.test"},
		IsCA:               true,
		RawPEM:             "pem",
		SourceDiscovery:    "sprint-later-source",
		FirstSeen:          seen,
		LastSeen:           seen,
	}
	require.NoError(t, st.UpsertCertificate(ctx, full))
	got := readCertRow(t, st, fp)
	require.Equal(t, "Refill Issuing CA", got.subjectCN)
	require.Equal(t, "Refill Root CA", got.issuerCN)
	require.Equal(t, "1f2e", got.serial)
	require.True(t, got.notBefore.Equal(notBefore), "not_before %v", got.notBefore)
	require.True(t, got.notAfter.Equal(notAfter), "not_after %v", got.notAfter)
	require.Equal(t, string(model.KeyECDSA), got.keyAlg)
	require.Equal(t, 256, got.keySize)
	require.Equal(t, string(model.SigECDSAWithSHA256), got.sigAlg)
	require.JSONEq(t, `["ca.refill.test"]`, got.sans)
	require.True(t, got.isCA)
	require.True(t, got.lastSeen.Equal(seen), "last_seen %v, want %v", got.lastSeen, seen)
	require.True(t, got.firstSeen.Equal(firstSeen), "first_seen must keep the first observation")
	require.Equal(t, "api", got.source, "source_discovery keeps the first discovering source")

	// 3. Seen again with different values: nothing that is set is
	// overwritten, and a CA is never downgraded.
	require.NoError(t, st.UpsertCertificate(ctx, &model.Certificate{
		FingerprintSHA256:  fp,
		Subject:            model.DistinguishedName{CommonName: "Other Name"},
		Issuer:             model.DistinguishedName{CommonName: "Other Issuer"},
		SerialNumber:       "ffff",
		NotBefore:          notBefore.Add(time.Hour),
		NotAfter:           notAfter.Add(time.Hour),
		KeyAlgorithm:       model.KeyRSA,
		KeySizeBits:        4096,
		SignatureAlgorithm: model.SigSHA256WithRSA,
		SubjectAltNames:    []string{"other.test"},
		IsCA:               false,
		SourceDiscovery:    "third-source",
		FirstSeen:          time.Now(),
		LastSeen:           time.Now(),
	}))
	again := readCertRow(t, st, fp)
	again.lastSeen, got.lastSeen = time.Time{}, time.Time{}
	require.Equal(t, got, again, "a set column must never be overwritten")
}
