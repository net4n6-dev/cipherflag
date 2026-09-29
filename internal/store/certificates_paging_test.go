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
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// Certificates issued together share a not_after. OFFSET paging over a sort
// with ties must still visit every row exactly once, in the same order each
// time, or an export that walks the pages repeats and skips certificates.
func TestSearchCertificates_PagingIsStableAcrossTies(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	const n = 7
	want := map[string]bool{}
	var sorted []string
	for i := 1; i <= n; i++ {
		sorted = append(sorted, fmt.Sprintf("page-tie-%04d", i))
	}
	notAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	// Insert in reverse fingerprint order so physical order is the opposite
	// of the order the tie-break must produce.
	for i := n; i >= 1; i-- {
		fp := fmt.Sprintf("page-tie-%04d", i)
		want[fp] = true
		t.Cleanup(func() {
			_, _ = st.pool.Exec(ctx, `DELETE FROM certificates WHERE fingerprint_sha256 = $1`, fp)
		})
		require.NoError(t, st.UpsertCertificate(ctx, &model.Certificate{
			FingerprintSHA256: fp, RawPEM: "pem", SourceDiscovery: "api",
			NotBefore: notAfter.Add(-24 * time.Hour), NotAfter: notAfter,
			FirstSeen: time.Now(), LastSeen: time.Now(),
		}))
	}

	pass := func(sortDir string) []string {
		var order []string
		for page := 1; page <= 3; page++ {
			res, err := st.SearchCertificates(ctx, CertSearchQuery{
				Search: "page-tie-", SortDir: sortDir, Page: page, PageSize: 3,
			})
			require.NoError(t, err)
			for _, c := range res.Certificates {
				order = append(order, c.FingerprintSHA256)
			}
		}
		return order
	}

	for _, dir := range []string{"", "desc"} {
		first := pass(dir)
		require.Len(t, first, n, "sort_dir=%q", dir)
		seen := map[string]bool{}
		for _, fp := range first {
			require.False(t, seen[fp], "sort_dir=%q: %s repeated", dir, fp)
			seen[fp] = true
		}
		require.Equal(t, want, seen, "sort_dir=%q", dir)
		// The tie-break is ascending in both directions.
		require.Equal(t, sorted, first, "sort_dir=%q", dir)
		require.Equal(t, first, pass(dir), "sort_dir=%q: a second pass changed the order", dir)
	}
}
