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

package b3

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"

	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

// GoDetector parses .go files via the stdlib AST and matches against the
// Go-language rules in the catalog. Imports are tracked locally per-file
// (including aliases) so a call like md5alias.New() still resolves to
// crypto/md5.
type GoDetector struct {
	rules map[string][]CryptoAPIRule // import path -> rules
}

// NewGoDetector pre-indexes catalog rules by import path for O(1) lookup
// during AST traversal.
func NewGoDetector() *GoDetector {
	idx := map[string][]CryptoAPIRule{}
	for _, r := range RulesByLanguage(LangGo) {
		idx[r.Import] = append(idx[r.Import], r)
	}
	return &GoDetector{rules: idx}
}

func (d *GoDetector) Name() string { return "b3.go" }

func (d *GoDetector) Detect(ctx context.Context, b enumerate.Blob, data []byte) ([]finding.FindingRecord, error) {
	if filepath.Ext(b.Path) != ".go" {
		return nil, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, b.Path, data, parser.SkipObjectResolution)
	if err != nil {
		// Tolerate parse failures silently — repos commit incomplete code.
		return nil, nil
	}

	// Map: alias used in source -> import path.
	// e.g. `import md5alias "crypto/md5"` => "md5alias" -> "crypto/md5"
	// Default alias = last segment of path.
	aliases := map[string]string{}
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		var alias string
		if imp.Name != nil {
			alias = imp.Name.Name
		} else {
			alias = filepath.Base(path)
		}
		// Skip "_" (blank) and "." imports — not call-site selectors.
		if alias == "_" || alias == "." {
			continue
		}
		aliases[alias] = path
	}

	var out []finding.FindingRecord
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		path, ok := aliases[ident.Name]
		if !ok {
			return true
		}
		rules, ok := d.rules[path]
		if !ok {
			return true
		}
		for _, r := range rules {
			if r.Selector != sel.Sel.Name {
				continue
			}
			pos := fset.Position(call.Pos())
			out = append(out, buildB3Finding(b.Path, r, pos.Line, pos.Line))
		}
		return true
	})
	return out, nil
}

// buildB3Finding constructs the standard FindingRecord shape for a B3 hit.
// Shared with python.go and java.go so the emitted shape is consistent.
func buildB3Finding(path string, r CryptoAPIRule, startLine, endLine int) finding.FindingRecord {
	return finding.FindingRecord{
		RuleID:           r.RuleID,
		Severity:         r.Severity,
		Bucket:           finding.BucketB3,
		Path:             path,
		LineRange:        [2]int{startLine, endLine},
		DetectedBy:       []string{"det:" + r.RuleID},
		ModelAttribution: "deterministic",
		Confidence:       0.92,
		CBOM: &finding.CBOMInfo{
			Algorithm:   r.Algorithm,
			Mode:        r.Mode,
			Padding:     r.Padding,
			KeySizeBits: r.KeySizeBits,
			OID:         r.OID,
			EvidenceOccurrence: []finding.Occurrence{
				{Path: path, Line: startLine},
			},
		},
		Evidence: map[string]any{"language": "go"},
	}
}
