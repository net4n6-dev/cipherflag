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

	"golang.org/x/mod/sumdb/tlog"
)

// VerifyInclusion checks that `leaf` is at position `index` in a tree
// of `treeSize` whose root is `root`, using the supplied
// inclusion-proof hashes. Thin wrapper over tlog.CheckRecord: hashes
// the leaf via tlog.RecordHash (RFC 6962 §2.1 leaf hash, SHA-256 with
// 0x00 prefix), copies the root into tlog.Hash, and delegates.
//
// Returns nil on a valid proof, non-nil on any mismatch (leaf, root,
// index, treeSize, or proof structure).
//
// Callers must pass the bytes the log signed over. For Static CT this
// is the RFC 6962 MerkleTreeLeaf record produced by EncodeTileLeaf —
// see Sunlight's reference implementation at filippo.io/sunlight/tile.go
// (MerkleTreeLeaf). Raw certificate DER is NOT the correct input.
//
// Spec: RFC 6962 §2.1.3 (Merkle audit paths); c2sp.org/static-ct-api
// inherits this definition unchanged.
func VerifyInclusion(leaf []byte, index, treeSize int64, root []byte, proof []tlog.Hash) error {
	if len(root) != tlog.HashSize {
		return fmt.Errorf("static: VerifyInclusion: root len = %d, want %d", len(root), tlog.HashSize)
	}
	var rootHash tlog.Hash
	copy(rootHash[:], root)
	leafHash := tlog.RecordHash(leaf)
	if err := tlog.CheckRecord(proof, treeSize, rootHash, index, leafHash); err != nil {
		return fmt.Errorf("static: VerifyInclusion: %w", err)
	}
	return nil
}
