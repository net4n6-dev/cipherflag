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
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// TestUpsertCertificate_BindsAKIAndSKI asserts that authority_key_id and
// subject_key_id are persisted when present on the model.Certificate passed
// to UpsertCertificate.
func TestUpsertCertificate_BindsAKIAndSKI(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	aki := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	ski := []byte{0xca, 0xfe, 0xba, 0xbe, 0x05, 0x06, 0x07, 0x08}

	cert := &model.Certificate{
		FingerprintSHA256:  "sha256:akiski-binds-0001",
		Subject:            model.DistinguishedName{CommonName: "aki-ski-test.example"},
		Issuer:             model.DistinguishedName{CommonName: "TestCA"},
		SerialNumber:       "serial-akiski-001",
		NotBefore:          time.Now().Add(-365 * 24 * time.Hour),
		NotAfter:           time.Now().Add(30 * 24 * time.Hour),
		KeyAlgorithm:       model.KeyRSA,
		KeySizeBits:        2048,
		SignatureAlgorithm: model.SigSHA256WithRSA,
		SourceDiscovery:    model.SourceZeekPassive,
		FirstSeen:          time.Now(),
		LastSeen:           time.Now(),
		AuthorityKeyID:     aki,
		SubjectKeyID:       ski,
	}

	if err := st.UpsertCertificate(ctx, cert); err != nil {
		t.Fatalf("UpsertCertificate: %v", err)
	}
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM certificates WHERE fingerprint_sha256 = $1`, cert.FingerprintSHA256)
	})

	var gotAKI, gotSKI []byte
	err := st.pool.QueryRow(ctx,
		`SELECT authority_key_id, subject_key_id FROM certificates WHERE fingerprint_sha256 = $1`,
		cert.FingerprintSHA256,
	).Scan(&gotAKI, &gotSKI)
	if err != nil {
		t.Fatalf("query AKI/SKI: %v", err)
	}

	if !bytes.Equal(gotAKI, aki) {
		t.Errorf("authority_key_id: got %x, want %x", gotAKI, aki)
	}
	if !bytes.Equal(gotSKI, ski) {
		t.Errorf("subject_key_id: got %x, want %x", gotSKI, ski)
	}
}

// TestUpsertCertificate_NullableAKIAndSKI asserts that when AuthorityKeyID
// and SubjectKeyID are nil on the model.Certificate, the columns are stored
// as NULL (pgx encodes a nil []byte as SQL NULL for BYTEA columns).
func TestUpsertCertificate_NullableAKIAndSKI(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	cert := &model.Certificate{
		FingerprintSHA256:  "sha256:akiski-null-0001",
		Subject:            model.DistinguishedName{CommonName: "aki-ski-null.example"},
		Issuer:             model.DistinguishedName{CommonName: "TestCA"},
		SerialNumber:       "serial-akiski-null-001",
		NotBefore:          time.Now().Add(-365 * 24 * time.Hour),
		NotAfter:           time.Now().Add(30 * 24 * time.Hour),
		KeyAlgorithm:       model.KeyRSA,
		KeySizeBits:        2048,
		SignatureAlgorithm: model.SigSHA256WithRSA,
		SourceDiscovery:    model.SourceZeekPassive,
		FirstSeen:          time.Now(),
		LastSeen:           time.Now(),
		AuthorityKeyID:     nil,
		SubjectKeyID:       nil,
	}

	if err := st.UpsertCertificate(ctx, cert); err != nil {
		t.Fatalf("UpsertCertificate: %v", err)
	}
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM certificates WHERE fingerprint_sha256 = $1`, cert.FingerprintSHA256)
	})

	// Use *[]byte pointers so pgx can scan NULL as nil.
	var gotAKI, gotSKI *[]byte
	err := st.pool.QueryRow(ctx,
		`SELECT authority_key_id, subject_key_id FROM certificates WHERE fingerprint_sha256 = $1`,
		cert.FingerprintSHA256,
	).Scan(&gotAKI, &gotSKI)
	if err != nil {
		t.Fatalf("query AKI/SKI (null case): %v", err)
	}

	if gotAKI != nil {
		t.Errorf("authority_key_id: expected NULL, got %x", *gotAKI)
	}
	if gotSKI != nil {
		t.Errorf("subject_key_id: expected NULL, got %x", *gotSKI)
	}
}
