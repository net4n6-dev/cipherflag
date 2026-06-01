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

func TestIsDeclared_TrueWhenInOperatorTable(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	userID := seedUser(t, st)
	if err := st.UpsertCertificate(ctx, minCert("declared-fp")); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool().Exec(ctx,
		`INSERT INTO operator_declared_cas (fingerprint_sha256, added_by) VALUES ($1, $2)`,
		"declared-fp", userID,
	); err != nil {
		t.Fatal(err)
	}
	got, err := st.IsDeclared(ctx, "declared-fp")
	if err != nil {
		t.Fatalf("IsDeclared(declared-fp): %v", err)
	}
	if !got {
		t.Error("IsDeclared(declared-fp) = false, want true")
	}
	got, err = st.IsDeclared(ctx, "other-fp")
	if err != nil {
		t.Fatalf("IsDeclared(other-fp): %v", err)
	}
	if got {
		t.Error("IsDeclared(other-fp) = true, want false")
	}
}
