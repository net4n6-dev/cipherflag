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
)

// GetCipherStats must return non-nil slice fields even when the
// observations table is empty. A nil slice marshals as JSON `null`, and
// CryptoPostureTab.svelte reads tls_cipher_matrix via .find / .map
// unguarded — an empty-DB deployment would otherwise crash the heatmap.
func TestGetCipherStats_EmptyObservations_SlicesNonNil(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)

	cs, err := st.GetCipherStats(ctx)
	if err != nil {
		t.Fatalf("GetCipherStats: %v", err)
	}
	if cs.SuiteDistribution == nil {
		t.Error("SuiteDistribution is nil — must be a non-nil empty slice ([] in JSON)")
	}
	if cs.TLSCipherMatrix == nil {
		t.Error("TLSCipherMatrix is nil — must be a non-nil empty slice ([] in JSON)")
	}
}
