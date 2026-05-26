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

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// TestSearchCertificates_GradesMap covers the v1.4.5 /assets contract:
// SearchCertificates now returns a fingerprint → grade map alongside the
// certificate rows so list views can render a Grade column without N+1
// /health fetches. Certs with no health_reports row must be absent from
// the map (not "" / "?" — the frontend distinguishes missing from graded).
func TestSearchCertificates_GradesMap(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	now := time.Now()
	certs := []*model.Certificate{
		{
			FingerprintSHA256: "sha256:grades-graded-a",
			Subject:           model.DistinguishedName{CommonName: "graded-a.example"},
			Issuer:            model.DistinguishedName{CommonName: "TestCA"},
			SerialNumber:      "serial-graded-a",
			NotBefore:         now.Add(-24 * time.Hour),
			NotAfter:          now.Add(30 * 24 * time.Hour),
			KeyAlgorithm:      model.KeyRSA,
			SourceDiscovery:   model.SourceActiveScan,
			FirstSeen:         now,
			LastSeen:          now,
		},
		{
			FingerprintSHA256: "sha256:grades-graded-c",
			Subject:           model.DistinguishedName{CommonName: "graded-c.example"},
			Issuer:            model.DistinguishedName{CommonName: "TestCA"},
			SerialNumber:      "serial-graded-c",
			NotBefore:         now.Add(-24 * time.Hour),
			NotAfter:          now.Add(30 * 24 * time.Hour),
			KeyAlgorithm:      model.KeyRSA,
			SourceDiscovery:   model.SourceActiveScan,
			FirstSeen:         now,
			LastSeen:          now,
		},
		{
			FingerprintSHA256: "sha256:grades-ungraded",
			Subject:           model.DistinguishedName{CommonName: "ungraded.example"},
			Issuer:            model.DistinguishedName{CommonName: "TestCA"},
			SerialNumber:      "serial-ungraded",
			NotBefore:         now.Add(-24 * time.Hour),
			NotAfter:          now.Add(30 * 24 * time.Hour),
			KeyAlgorithm:      model.KeyRSA,
			SourceDiscovery:   model.SourceActiveScan,
			FirstSeen:         now,
			LastSeen:          now,
		},
	}
	for _, c := range certs {
		if err := st.UpsertCertificate(ctx, c); err != nil {
			t.Fatalf("UpsertCertificate %s: %v", c.FingerprintSHA256, err)
		}
	}

	// Seed grades for 2 of 3.
	grades := []*model.HealthReport{
		{CertFingerprint: "sha256:grades-graded-a", Grade: "A", Score: 95, ScoredAt: now},
		{CertFingerprint: "sha256:grades-graded-c", Grade: "C", Score: 65, ScoredAt: now},
	}
	for _, g := range grades {
		if err := st.SaveHealthReport(ctx, g); err != nil {
			t.Fatalf("SaveHealthReport %s: %v", g.CertFingerprint, err)
		}
	}

	result, err := st.SearchCertificates(ctx, CertSearchQuery{
		Search:   "grades-",
		Page:     1,
		PageSize: 10,
	})
	if err != nil {
		t.Fatalf("SearchCertificates: %v", err)
	}
	if result.Total != 3 {
		t.Errorf("total = %d, want 3 (Certificates: %+v)", result.Total, result.Certificates)
	}
	if result.Grades == nil {
		t.Fatal("grades map is nil — must be non-nil even with zero graded rows")
	}
	if len(result.Grades) != 2 {
		t.Errorf("grades map size = %d, want 2", len(result.Grades))
	}
	if got := result.Grades["sha256:grades-graded-a"]; got != "A" {
		t.Errorf("grades[graded-a] = %q, want A", got)
	}
	if got := result.Grades["sha256:grades-graded-c"]; got != "C" {
		t.Errorf("grades[graded-c] = %q, want C", got)
	}
	if _, present := result.Grades["sha256:grades-ungraded"]; present {
		t.Error("grades map must not include ungraded fingerprints")
	}
}

// TestSearchCertificates_GradesMap_EmptyResult verifies that a zero-match
// search returns a non-nil empty grades map rather than leaving it nil.
// (The frontend expects `grades ?? {}` at worst, but we want consistency
// with how Certificates is initialized as [].)
func TestSearchCertificates_GradesMap_EmptyResult(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	result, err := st.SearchCertificates(ctx, CertSearchQuery{
		Search:   "no-such-cert-will-ever-match-" + time.Now().Format("20060102150405"),
		Page:     1,
		PageSize: 10,
	})
	if err != nil {
		t.Fatalf("SearchCertificates: %v", err)
	}
	if result.Total != 0 {
		t.Errorf("total = %d, want 0", result.Total)
	}
	if result.Grades == nil {
		t.Fatal("grades map is nil on empty result — must be initialized")
	}
	if len(result.Grades) != 0 {
		t.Errorf("grades map size = %d, want 0", len(result.Grades))
	}
}
