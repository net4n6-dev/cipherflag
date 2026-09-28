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

package ingest

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// CE before 2.3.0 stored a certificate posted to /api/v1/ingest with only
// RawPEM as a blank row (fingerprint and PEM, nothing else). Clients do not
// re-send certificates they have already posted, so serve repairs those rows
// from their stored PEM at startup.
func TestRepairBlankCertificates(t *testing.T) {
	st := newIntegrationStore(t)
	ctx := context.Background()
	lastSeen := time.Now().Add(-72 * time.Hour).Truncate(time.Microsecond)

	caPEM, ca := testCAPEM(t)
	otherPEM, _ := testCAPEM(t)
	blank := func(fp, pem string) {
		t.Helper()
		require.NoError(t, st.UpsertCertificate(ctx, &model.Certificate{
			FingerprintSHA256: fp, RawPEM: pem, SourceDiscovery: "api",
			FirstSeen: lastSeen, LastSeen: lastSeen,
		}))
	}
	blank(ca.FingerprintSHA256, caPEM) // repairable
	blank("0000-unparseable", "not a pem")
	blank("0001-no-pem", "")
	blank("ffff-wrong-fingerprint", otherPEM) // PEM of a different certificate

	// Page one row at a time so the unrepairable rows are paged past, not
	// re-read forever.
	defer func(n int) { repairBatchSize = n }(repairBatchSize)
	repairBatchSize = 1

	var scored []string
	score := func(_ context.Context, fp string) error { scored = append(scored, fp); return nil }

	res, err := RepairBlankCertificates(ctx, st, score)
	require.NoError(t, err)
	require.Equal(t, RepairResult{Repaired: 1, Skipped: 2}, res)
	require.Equal(t, []string{ca.FingerprintSHA256}, scored, "a repaired certificate is scored straight away")

	got, err := st.GetCertificate(ctx, ca.FingerprintSHA256)
	require.NoError(t, err)
	require.Equal(t, "PEM Only Issuing CA", got.Subject.CommonName)
	require.Equal(t, "PEM Only Issuing CA", got.Issuer.CommonName)
	require.True(t, got.IsCA)
	require.True(t, ca.NotAfter.Equal(got.NotAfter), "not_after %v", got.NotAfter)
	require.Equal(t, 256, got.KeySizeBits)
	require.True(t, got.LastSeen.Equal(lastSeen), "a repair is not a sighting: last_seen %v, want %v", got.LastSeen, lastSeen)

	for _, fp := range []string{"0000-unparseable", "0001-no-pem", "ffff-wrong-fingerprint"} {
		c, err := st.GetCertificate(ctx, fp)
		require.NoError(t, err)
		require.Equal(t, "", c.Subject.CommonName, "%s must be left as it was", fp)
	}

	// Idempotent: nothing left to repair.
	scored = nil
	res, err = RepairBlankCertificates(ctx, st, score)
	require.NoError(t, err)
	require.Equal(t, RepairResult{Repaired: 0, Skipped: 2}, res)
	require.Empty(t, scored)
}
