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

func batchFixture(t *testing.T, st *PostgresStore, fp string) func(client string) *model.CertificateObservation {
	t.Helper()
	ctx := context.Background()
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM certificates WHERE fingerprint_sha256 = $1`, fp)
	})
	require.NoError(t, st.UpsertCertificate(ctx, &model.Certificate{
		FingerprintSHA256: fp, RawPEM: "pem", SourceDiscovery: "api",
		FirstSeen: time.Now(), LastSeen: time.Now(),
	}))
	at := time.Now().Add(-time.Hour).Truncate(time.Microsecond)
	return func(client string) *model.CertificateObservation {
		return &model.CertificateObservation{
			CertFingerprint: fp, ServerIP: "10.0.0.5", ServerPort: 443, ClientIP: client,
			ServerName: "a.test", Source: model.SourceZeekPassive, ObservedAt: at,
		}
	}
}

func TestBatchRecordObservations_StoresEachOnceAndIsIdempotent(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	fp := "obs-batch-0001"
	obs := batchFixture(t, st, fp)

	batch := []*model.CertificateObservation{obs("10.0.0.9"), obs("10.0.0.10"), obs("10.0.0.9")}
	require.NoError(t, st.BatchRecordObservations(ctx, batch))
	require.Equal(t, 2, obsCount(t, st, fp), "the repeated session inside the batch is stored once")
	require.NoError(t, st.BatchRecordObservations(ctx, batch), "a replayed batch is a no-op, not an error")
	require.Equal(t, 2, obsCount(t, st, fp))
}

// A batch is atomic. One row that violates the foreign key
// stores none of them, so a poller retry cannot leave half a batch behind.
func TestBatchRecordObservations_IsAtomic(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	fp := "obs-batch-0002"
	obs := batchFixture(t, st, fp)

	bad := obs("10.0.0.11")
	bad.CertFingerprint = "obs-batch-no-such-certificate"
	err := st.BatchRecordObservations(ctx, []*model.CertificateObservation{obs("10.0.0.9"), bad})
	require.Error(t, err)
	require.Equal(t, 0, obsCount(t, st, fp), "the good row before the bad one was rolled back")
}

func TestBatchRecordObservations_EmptyIsANoOp(t *testing.T) {
	st := testStore(t)
	require.NoError(t, st.BatchRecordObservations(context.Background(), nil))
}
