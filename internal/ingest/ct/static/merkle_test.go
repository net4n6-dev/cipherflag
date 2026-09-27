// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package static

import (
	"fmt"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

// Builds a 4-leaf tree via tlog, then asserts our wrapper verifies a
// valid inclusion proof and rejects a tampered one. Uses tlog's own
// helpers to construct the canonical tree state — if the wrapper
// drifts from tlog's semantics this test breaks loudly.
func TestVerifyInclusion_HappyPathAndTamperRejection(t *testing.T) {
	leaves := [][]byte{
		[]byte("leaf-0"),
		[]byte("leaf-1"),
		[]byte("leaf-2"),
		[]byte("leaf-3"),
	}
	hashes := make([]tlog.Hash, len(leaves))
	for i, l := range leaves {
		hashes[i] = tlog.RecordHash(l)
	}

	// Build the flat hash store: precompute all stored hashes for all
	// records so ReadHashes can serve arbitrary level/index without
	// recursion.
	hr, err := newTestHashReader(hashes)
	if err != nil {
		t.Fatalf("newTestHashReader: %v", err)
	}

	root, err := tlog.TreeHash(int64(len(leaves)), hr)
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}

	// Inclusion proof for leaf 2 (zero-indexed).
	proof, err := tlog.ProveRecord(int64(len(leaves)), 2, hr)
	if err != nil {
		t.Fatalf("ProveRecord: %v", err)
	}

	if err := VerifyInclusion(leaves[2], 2, int64(len(leaves)), root[:], proof); err != nil {
		t.Errorf("VerifyInclusion happy-path: %v", err)
	}

	// Tamper the leaf — verification must fail.
	if err := VerifyInclusion([]byte("tampered"), 2, int64(len(leaves)), root[:], proof); err == nil {
		t.Error("VerifyInclusion: tampered leaf accepted, want rejection")
	}

	// Tamper the root — verification must fail.
	badRoot := make([]byte, 32)
	if err := VerifyInclusion(leaves[2], 2, int64(len(leaves)), badRoot, proof); err == nil {
		t.Error("VerifyInclusion: bad root accepted, want rejection")
	}
}

// testHashReader is a tlog.HashReader backed by a precomputed flat
// hash store (map from StoredHashIndex → Hash). Avoids the mutual
// recursion that results from calling tlog.TreeHash inside ReadHashes.
type testHashReader map[int64]tlog.Hash

// newTestHashReader builds the complete stored-hash store for a tree
// whose leaf hashes are provided. Uses tlog.StoredHashesForRecordHash
// to add each record's contribution (leaf + any completed subtrees).
func newTestHashReader(leafHashes []tlog.Hash) (testHashReader, error) {
	store := make(testHashReader)

	// We need a HashReader to compute StoredHashes for records > 0.
	// We supply ourselves; by the time record n is processed, all
	// hashes needed for n's completed subtrees (indices < n) are
	// already in the store.
	for n, lh := range leafHashes {
		stored, err := tlog.StoredHashesForRecordHash(int64(n), lh, store)
		if err != nil {
			return nil, fmt.Errorf("record %d: %w", n, err)
		}
		base := tlog.StoredHashIndex(0, int64(n))
		for i, h := range stored {
			store[base+int64(i)] = h
		}
	}
	return store, nil
}

func (h testHashReader) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, idx := range indexes {
		v, ok := h[idx]
		if !ok {
			return nil, fmt.Errorf("hash index %d not found in store", idx)
		}
		out[i] = v
	}
	return out, nil
}

// Wrong index — a proof generated for index 2 must not verify when the
// caller claims the leaf was at index 1. Catches bugs where the index
// parameter is silently ignored.
func TestVerifyInclusion_RejectsWrongIndex(t *testing.T) {
	rawLeaves := [][]byte{
		[]byte("leaf-0"),
		[]byte("leaf-1"),
		[]byte("leaf-2"),
		[]byte("leaf-3"),
	}
	hashes := make([]tlog.Hash, len(rawLeaves))
	for i, l := range rawLeaves {
		hashes[i] = tlog.RecordHash(l)
	}
	hr, err := newTestHashReader(hashes)
	if err != nil {
		t.Fatalf("newTestHashReader: %v", err)
	}
	root, err := tlog.TreeHash(int64(len(rawLeaves)), hr)
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}
	proof, err := tlog.ProveRecord(int64(len(rawLeaves)), 2, hr)
	if err != nil {
		t.Fatalf("ProveRecord: %v", err)
	}
	if err := VerifyInclusion(rawLeaves[2], 1, int64(len(rawLeaves)), root[:], proof); err == nil {
		t.Error("VerifyInclusion accepted wrong index, want rejection")
	}
}

// Wrong treeSize — a proof for a 4-leaf tree must not verify when the
// caller claims an 8-leaf tree.
func TestVerifyInclusion_RejectsWrongTreeSize(t *testing.T) {
	rawLeaves := [][]byte{
		[]byte("leaf-0"),
		[]byte("leaf-1"),
		[]byte("leaf-2"),
		[]byte("leaf-3"),
	}
	hashes := make([]tlog.Hash, len(rawLeaves))
	for i, l := range rawLeaves {
		hashes[i] = tlog.RecordHash(l)
	}
	hr, err := newTestHashReader(hashes)
	if err != nil {
		t.Fatalf("newTestHashReader: %v", err)
	}
	root, err := tlog.TreeHash(int64(len(rawLeaves)), hr)
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}
	proof, err := tlog.ProveRecord(int64(len(rawLeaves)), 2, hr)
	if err != nil {
		t.Fatalf("ProveRecord: %v", err)
	}
	if err := VerifyInclusion(rawLeaves[2], 2, 8, root[:], proof); err == nil {
		t.Error("VerifyInclusion accepted wrong treeSize, want rejection")
	}
}
