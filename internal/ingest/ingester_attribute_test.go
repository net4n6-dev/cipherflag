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
	"errors"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/store"
)

// attributeAssetsFakeStore records every UpsertOwnershipSighting call.
// failOnCall=N (1-indexed) causes the Nth call to return an error.
type attributeAssetsFakeStore struct {
	calls      []*store.OwnershipSighting
	failOnCall int
}

func (f *attributeAssetsFakeStore) UpsertOwnershipSighting(_ context.Context, s *store.OwnershipSighting) error {
	f.calls = append(f.calls, s)
	if f.failOnCall > 0 && len(f.calls) == f.failOnCall {
		return errors.New("mock upsert error")
	}
	return nil
}

// attributeAssetsFullStore wraps the narrow fake in a type that satisfies
// store.CryptoStore for the one method AttributeAssets actually calls.
// Embedding a nil store.CryptoStore is the Go idiom for "panic on any
// method I don't override" — desired behaviour for a test that must not
// exercise Ingest-side store methods.
type attributeAssetsFullStore struct {
	writer *attributeAssetsFakeStore
	store.CryptoStore // embedded nil interface; any unimplemented method panics
}

func (s *attributeAssetsFullStore) UpsertOwnershipSighting(ctx context.Context, sighting *store.OwnershipSighting) error {
	return s.writer.UpsertOwnershipSighting(ctx, sighting)
}

func newTestIngesterWithStore(w *attributeAssetsFakeStore) *UnifiedIngester {
	// Minimal UnifiedIngester for exercising AttributeAssets in isolation.
	return &UnifiedIngester{store: &attributeAssetsFullStore{writer: w}}
}

func TestAttributeAssets_FanOut(t *testing.T) {
	writer := &attributeAssetsFakeStore{}
	u := newTestIngesterWithStore(writer)
	claims := []OwnershipClaim{
		{AssetType: "certificate", AssetID: "cert-abc", Team: "Payments Team", Source: "sighting_agent", Confidence: "inferred", Evidence: map[string]any{"tag_key": "Team"}},
		{AssetType: "ssh_key", AssetID: "ssh-123", Team: "Payments Team", Source: "sighting_agent", Confidence: "inferred", Evidence: map[string]any{"tag_key": "Team"}},
		{AssetType: "crypto_library", AssetID: "lib-xyz", Team: "Payments Team", Source: "sighting_agent", Confidence: "inferred", Evidence: map[string]any{"tag_key": "Team"}},
	}

	emitted, skipped, err := u.AttributeAssets(context.Background(), claims)

	if err != nil {
		t.Fatalf("AttributeAssets err = %v, want nil", err)
	}
	if emitted != 3 {
		t.Errorf("emitted = %d, want 3", emitted)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0", skipped)
	}
	if len(writer.calls) != 3 {
		t.Fatalf("writer.calls = %d, want 3", len(writer.calls))
	}
	for i, s := range writer.calls {
		if s.Team != "payments-team" {
			t.Errorf("call[%d].Team = %q, want %q", i, s.Team, "payments-team")
		}
		if s.Source != "sighting_agent" {
			t.Errorf("call[%d].Source = %q", i, s.Source)
		}
		if s.Confidence != "inferred" {
			t.Errorf("call[%d].Confidence = %q", i, s.Confidence)
		}
		if s.AssetType != claims[i].AssetType {
			t.Errorf("call[%d].AssetType = %q, want %q", i, s.AssetType, claims[i].AssetType)
		}
		if s.AssetID != claims[i].AssetID {
			t.Errorf("call[%d].AssetID = %q, want %q", i, s.AssetID, claims[i].AssetID)
		}
	}
}

func TestAttributeAssets_EmptyTeam(t *testing.T) {
	writer := &attributeAssetsFakeStore{}
	u := newTestIngesterWithStore(writer)
	claims := []OwnershipClaim{
		{AssetType: "certificate", AssetID: "cert-abc", Team: "   ", Source: "sighting_agent", Confidence: "inferred"},
	}

	emitted, skipped, err := u.AttributeAssets(context.Background(), claims)

	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if emitted != 0 {
		t.Errorf("emitted = %d, want 0", emitted)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}
	if len(writer.calls) != 0 {
		t.Errorf("writer.calls = %d, want 0", len(writer.calls))
	}
}

func TestAttributeAssets_SlugTooShort(t *testing.T) {
	writer := &attributeAssetsFakeStore{}
	u := newTestIngesterWithStore(writer)
	claims := []OwnershipClaim{
		{AssetType: "certificate", AssetID: "cert-abc", Team: "x.", Source: "sighting_agent", Confidence: "inferred"},
	}

	emitted, skipped, _ := u.AttributeAssets(context.Background(), claims)

	if emitted != 0 || skipped != 1 {
		t.Errorf("emitted=%d skipped=%d, want 0/1", emitted, skipped)
	}
	if len(writer.calls) != 0 {
		t.Errorf("writer.calls = %d, want 0", len(writer.calls))
	}
}

func TestAttributeAssets_NoClaims(t *testing.T) {
	writer := &attributeAssetsFakeStore{}
	u := newTestIngesterWithStore(writer)

	emitted, skipped, err := u.AttributeAssets(context.Background(), nil)

	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if emitted != 0 || skipped != 0 {
		t.Errorf("emitted=%d skipped=%d, want 0/0 for empty claim set", emitted, skipped)
	}
}

func TestAttributeAssets_EmitError_Swallowed(t *testing.T) {
	writer := &attributeAssetsFakeStore{failOnCall: 2}
	u := newTestIngesterWithStore(writer)
	claims := []OwnershipClaim{
		{AssetType: "certificate", AssetID: "cert-abc", Team: "Payments", Source: "sighting_agent", Confidence: "inferred"},
		{AssetType: "ssh_key", AssetID: "ssh-123", Team: "Payments", Source: "sighting_agent", Confidence: "inferred"},
		{AssetType: "crypto_library", AssetID: "lib-xyz", Team: "Payments", Source: "sighting_agent", Confidence: "inferred"},
	}

	emitted, skipped, err := u.AttributeAssets(context.Background(), claims)

	// Second claim errored; function logs WARN, continues to third.
	// First + third succeed.
	if err != nil {
		t.Fatalf("err = %v, want nil (individual upsert failures are swallowed)", err)
	}
	if emitted != 2 {
		t.Errorf("emitted = %d, want 2", emitted)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0 (per-upsert errors don't count as skips)", skipped)
	}
	if len(writer.calls) != 3 {
		t.Errorf("writer.calls = %d, want 3 (all three attempted)", len(writer.calls))
	}
}

func TestAttributeAssets_CtxCancelled(t *testing.T) {
	writer := &attributeAssetsFakeStore{}
	u := newTestIngesterWithStore(writer)
	claims := []OwnershipClaim{
		{AssetType: "certificate", AssetID: "cert-abc", Team: "Payments", Source: "sighting_agent", Confidence: "inferred"},
		{AssetType: "ssh_key", AssetID: "ssh-123", Team: "Payments", Source: "sighting_agent", Confidence: "inferred"},
		{AssetType: "crypto_library", AssetID: "lib-xyz", Team: "Payments", Source: "sighting_agent", Confidence: "inferred"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before any claim is processed

	emitted, skipped, err := u.AttributeAssets(ctx, claims)

	// AttributeAssets must return ctx.Err() at the first iteration — no
	// claims attempted. Partial batch handling becomes an AWS concern
	// when claim batches grow beyond trivial size; this test locks in
	// the "check ctx.Err() at loop top" contract.
	if err == nil {
		t.Fatal("err = nil, want non-nil (ctx.Err())")
	}
	if err != context.Canceled {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if emitted != 0 {
		t.Errorf("emitted = %d, want 0 (ctx cancelled before any upsert)", emitted)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0 (ctx cancelled before any skip check)", skipped)
	}
	if len(writer.calls) != 0 {
		t.Errorf("writer.calls = %d, want 0 (no upserts attempted)", len(writer.calls))
	}
}
