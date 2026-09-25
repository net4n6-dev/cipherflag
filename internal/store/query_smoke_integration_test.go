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
	"strings"
	"testing"
	"time"
)

// noSchemaDrift fails the test if err is a "does not exist" SQL error: the query
// references a table or column the CE migrations do not create.
func noSchemaDrift(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), "does not exist") {
		t.Errorf("%s: schema drift: %v", what, err)
	}
}

// Runs the CE queries that touch the objects this release reconciles, against an
// empty migrated schema. Only the absence of drift errors is asserted.
func TestQuerySmoke_NoSchemaDrift(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	_, err := st.ListApplications(ctx, nil)
	noSchemaDrift(t, "ListApplications", err)

	_, err = st.tagsWithDeadlineBefore(ctx, time.Now())
	noSchemaDrift(t, "tagsWithDeadlineBefore", err)

	_, err = st.GetApplication(ctx, "no-such-app")
	noSchemaDrift(t, "GetApplication", err)

	_, err = st.ListApplicationScopeAssets(ctx, "no-such-app")
	noSchemaDrift(t, "ListApplicationScopeAssets", err)

	_, err = st.ListAllAssetHealthReports(ctx)
	noSchemaDrift(t, "ListAllAssetHealthReports", err)

	_, err = st.ListScopeAssets(ctx, ScopeAssetQuery{HostIDs: []string{"00000000-0000-0000-0000-000000000001"}})
	noSchemaDrift(t, "ListScopeAssets", err)

	_, err = st.ListWeakAlgorithmOccurrences(ctx, WeakAlgoFilter{})
	noSchemaDrift(t, "ListWeakAlgorithmOccurrences", err)

	// The removed EE-only asset type must be harmless as a filter, not a SQL error.
	_, err = st.ListWeakAlgorithmOccurrences(ctx, WeakAlgoFilter{AssetTypes: []string{"protocol_endpoint"}})
	noSchemaDrift(t, "ListWeakAlgorithmOccurrences(protocol_endpoint filter)", err)
}
