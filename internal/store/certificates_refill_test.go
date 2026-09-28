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

// The startup repair runs alongside live ingest and writes a row back with
// the last_seen it read. last_seen was overwritten unconditionally, so a
// re-observation landing between the repair's read and its write was
// rewound to the older time, and the Venafi push (last_seen >
// venafi_pushed_at) could miss it. last_seen now only moves forward.
func TestUpsertCertificate_NeverMovesLastSeenBack(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	fp := "refill-lastseen-0001"
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM certificates WHERE fingerprint_sha256 = $1`, fp)
	})
	older := time.Now().Add(-time.Hour).Truncate(time.Microsecond)
	newer := time.Now().Truncate(time.Microsecond)

	require.NoError(t, st.UpsertCertificate(ctx, &model.Certificate{FingerprintSHA256: fp, FirstSeen: older, LastSeen: older}))
	require.NoError(t, st.UpsertCertificate(ctx, &model.Certificate{FingerprintSHA256: fp, FirstSeen: older, LastSeen: newer}))
	require.True(t, readCertRow(t, st, fp).lastSeen.Equal(newer), "a later sighting moves last_seen forward")

	// The repair's write, carrying the last_seen it read before the sighting.
	require.NoError(t, st.UpsertCertificate(ctx, &model.Certificate{FingerprintSHA256: fp, FirstSeen: older, LastSeen: older}))
	got := readCertRow(t, st, fp).lastSeen
	require.True(t, got.Equal(newer), "last_seen %v was moved back from %v", got, newer)
}

type extraRow struct {
	org, spki, ocsp, crl, scts, keyAlg, sigAlg string
	aki, ski                                   []byte
	pathLen                                    *int
}

func readExtraRow(t *testing.T, st *PostgresStore, fp string) extraRow {
	t.Helper()
	var r extraRow
	var spki *string
	err := st.pool.QueryRow(context.Background(), `
		SELECT subject_org, spki_fingerprint_sha256, ocsp_responder_urls::text,
		       crl_distribution_points::text, scts::text, key_algorithm, signature_algorithm,
		       authority_key_id, subject_key_id, basic_constraints_path_len
		FROM certificates WHERE fingerprint_sha256 = $1`, fp).Scan(
		&r.org, &spki, &r.ocsp, &r.crl, &r.scts, &r.keyAlg, &r.sigAlg, &r.aki, &r.ski, &r.pathLen)
	require.NoError(t, err)
	if spki != nil {
		r.spki = *spki
	}
	return r
}

// The rest of a certificate's metadata follows the same fill-only rule, and
// the SPKI fingerprint is written at all (UpsertCertificate never wrote it).
// An observation that lacks a value (one without a PEM, say) must not blank
// out one the row already has, key IDs included, and 'Unknown' algorithms
// (what the Zeek mapper records) count as empty.
func TestUpsertCertificate_FillsRemainingMetadataColumns(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	fp := "refill-extra-0001"
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM certificates WHERE fingerprint_sha256 = $1`, fp)
	})
	now := time.Now()

	// Seen first by a source that knows little: unknown algorithms, no PEM.
	require.NoError(t, st.UpsertCertificate(ctx, &model.Certificate{
		FingerprintSHA256: fp, KeyAlgorithm: model.KeyUnknown, SignatureAlgorithm: model.SigUnknown,
		FirstSeen: now, LastSeen: now,
	}))

	// Then with the full certificate.
	pathLen := 0
	full := &model.Certificate{
		FingerprintSHA256:       fp,
		Subject:                 model.DistinguishedName{CommonName: "Extra CA", Organization: "Extra Org"},
		NotAfter:                now.Add(time.Hour),
		KeyAlgorithm:            model.KeyECDSA,
		SignatureAlgorithm:      model.SigECDSAWithSHA256,
		SPKIFingerprintSHA256:   "spki-hex",
		OCSPResponderURLs:       []string{"http://ocsp.extra.test"},
		CRLDistributionPoints:   []string{"http://crl.extra.test/ca.crl"},
		SCTs:                    []string{"sct-1"},
		AuthorityKeyID:          []byte{1, 2, 3},
		SubjectKeyID:            []byte{4, 5, 6},
		BasicConstraintsPathLen: &pathLen,
		FirstSeen:               now, LastSeen: now,
	}
	require.NoError(t, st.UpsertCertificate(ctx, full))
	got := readExtraRow(t, st, fp)
	require.Equal(t, "Extra Org", got.org)
	require.Equal(t, "spki-hex", got.spki)
	require.JSONEq(t, `["http://ocsp.extra.test"]`, got.ocsp)
	require.JSONEq(t, `["http://crl.extra.test/ca.crl"]`, got.crl)
	require.JSONEq(t, `["sct-1"]`, got.scts)
	require.Equal(t, string(model.KeyECDSA), got.keyAlg, "'Unknown' is filled")
	require.Equal(t, string(model.SigECDSAWithSHA256), got.sigAlg, "'Unknown' is filled")
	require.Equal(t, []byte{1, 2, 3}, got.aki)
	require.Equal(t, []byte{4, 5, 6}, got.ski)
	require.NotNil(t, got.pathLen)
	require.Equal(t, 0, *got.pathLen)

	// Seen again without any of it (no PEM): nothing is blanked.
	require.NoError(t, st.UpsertCertificate(ctx, &model.Certificate{FingerprintSHA256: fp, FirstSeen: now, LastSeen: now}))
	require.Equal(t, got, readExtraRow(t, st, fp), "an observation lacking values must not blank the row")
}
