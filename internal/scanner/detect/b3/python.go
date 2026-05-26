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
	"path/filepath"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/python"

	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

// PythonDetector parses .py files via Tree-sitter. The detector tracks
// imports (both `import X` and `from X import Y [as Z]`) and resolves
// call sites to (module, function) pairs that are looked up in the catalog.
type PythonDetector struct {
	parser      *sitter.Parser
	rules       []CryptoAPIRule
	importQuery *sitter.Query
	callQuery   *sitter.Query
}

// NewPythonDetector lazily allocates a parser configured for Python.
func NewPythonDetector() *PythonDetector {
	p := sitter.NewParser()
	p.SetLanguage(python.GetLanguage())
	d := &PythonDetector{
		parser: p,
		rules:  RulesByLanguage(LangPython),
	}
	// Capture all import-related shapes with explicit field captures so we
	// don't have to walk children types ourselves. Five shapes covered:
	//   1. `import X`                          → @plain_imp_name
	//   2. `import X as Y`                     → @plain_imp_alias_orig + @plain_imp_alias_name
	//   3. `from M import X`                   → @from_mod + @from_name
	//   4. `from M import X as Y`              → @from_mod + @from_alias_orig + @from_alias_name
	//   5. `from M import X, Y` (multi-name)   → multiple @from_name captures share one @from_mod (sitter emits per-match)
	// Tree-sitter Python grammar: import_from_statement has a module_name
	// field but the imported names are unnamed children (just dotted_name
	// or aliased_import nodes after the `import` keyword). Match positionally.
	importQ, _ := sitter.NewQuery([]byte(`
		(import_statement
			(dotted_name) @plain_imp_name)

		(import_statement
			(aliased_import
				name: (dotted_name) @plain_imp_alias_orig
				alias: (identifier) @plain_imp_alias_name))

		(import_from_statement
			module_name: (dotted_name) @from_mod
			(dotted_name) @from_name)

		(import_from_statement
			module_name: (dotted_name) @from_mod
			(aliased_import
				name: (dotted_name) @from_alias_orig
				alias: (identifier) @from_alias_name))
	`), python.GetLanguage())
	d.importQuery = importQ
	callQ, _ := sitter.NewQuery([]byte(`(call function: (_) @fn) @call`), python.GetLanguage())
	d.callQuery = callQ
	return d
}

func (d *PythonDetector) Name() string { return "b3.python" }

func (d *PythonDetector) Detect(ctx context.Context, b enumerate.Blob, data []byte) ([]finding.FindingRecord, error) {
	if filepath.Ext(b.Path) != ".py" {
		return nil, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	tree, err := d.parser.ParseCtx(ctx, nil, data)
	if err != nil || tree == nil {
		return nil, nil
	}
	defer tree.Close()
	root := tree.RootNode()
	if root == nil {
		return nil, nil
	}

	// Step 1: collect imports (alias -> fully-qualified module/name).
	aliases := d.collectImports(root, data)

	// Step 2: walk call sites; resolve to (module, selector).
	var out []finding.FindingRecord
	cursor := sitter.NewQueryCursor()
	defer cursor.Close()
	cursor.Exec(d.callQuery, root)
	for {
		match, ok := cursor.NextMatch()
		if !ok {
			break
		}
		var fnNode, callNode *sitter.Node
		for _, c := range match.Captures {
			name := d.callQuery.CaptureNameForId(c.Index)
			switch name {
			case "fn":
				fnNode = c.Node
			case "call":
				callNode = c.Node
			}
		}
		if fnNode == nil || callNode == nil {
			continue
		}
		mod, sel := resolvePythonCall(fnNode, data, aliases)
		if mod == "" || sel == "" {
			continue
		}
		for _, r := range d.rules {
			if r.Import == mod && r.Selector == sel {
				line := int(callNode.StartPoint().Row) + 1
				out = append(out, buildB3FindingPy(b.Path, r, line))
			}
		}
	}
	return out, nil
}

// collectImports walks `import` and `from … import …` statements via the
// pre-compiled importQuery, returning alias -> fully-qualified target.
//   - `import X`               → out[X] = X
//   - `import X as Y`          → out[Y] = X
//   - `from M import X`        → out[X] = M
//   - `from M import X as Y`   → out[Y] = M
//
// For `from M import X, Y` Tree-sitter emits one match per (mod, name) pair.
func (d *PythonDetector) collectImports(root *sitter.Node, src []byte) map[string]string {
	out := map[string]string{}
	cursor := sitter.NewQueryCursor()
	defer cursor.Close()
	cursor.Exec(d.importQuery, root)
	for {
		match, ok := cursor.NextMatch()
		if !ok {
			break
		}
		// Bucket captures by name.
		var (
			plainImp       *sitter.Node
			plainImpAliasA *sitter.Node // original
			plainImpAliasN *sitter.Node // alias name
			fromMod        *sitter.Node
			fromName       *sitter.Node
			fromAliasOrig  *sitter.Node
			fromAliasName  *sitter.Node
		)
		for _, c := range match.Captures {
			switch d.importQuery.CaptureNameForId(c.Index) {
			case "plain_imp_name":
				plainImp = c.Node
			case "plain_imp_alias_orig":
				plainImpAliasA = c.Node
			case "plain_imp_alias_name":
				plainImpAliasN = c.Node
			case "from_mod":
				fromMod = c.Node
			case "from_name":
				fromName = c.Node
			case "from_alias_orig":
				fromAliasOrig = c.Node
			case "from_alias_name":
				fromAliasName = c.Node
			}
		}
		switch {
		case plainImp != nil:
			n := plainImp.Content(src)
			out[n] = n
		case plainImpAliasA != nil && plainImpAliasN != nil:
			out[plainImpAliasN.Content(src)] = plainImpAliasA.Content(src)
		case fromMod != nil && fromAliasOrig != nil && fromAliasName != nil:
			_ = fromAliasOrig
			out[fromAliasName.Content(src)] = fromMod.Content(src)
		case fromMod != nil && fromName != nil:
			out[fromName.Content(src)] = fromMod.Content(src)
		}
	}
	return out
}

// resolvePythonCall handles attribute (object.attr(...)) and identifier
// (bare ARC4(...)) call shapes. Returns (module, selector) or ("","").
//
// Resolution rules:
//   - `import M`               + `M.f(...)`  → module=M, sel=f
//   - `import M as A`          + `A.f(...)`  → module=M, sel=f
//   - `from M import N`        + `N.f(...)`  → module=M.N, sel=f
//     (the alias N stands in for the M.N submodule at the call site)
//   - `from M import N as A`   + `A.f(...)`  → module=M.N, sel=f
//     (we lost the original name; resolver tracks aliases[A]=M only,
//     so this case currently resolves as module=M, sel=f. v1 deferral.)
//   - `from M import f`        + `f(...)`    → module=M, sel=f (bare call)
func resolvePythonCall(fnNode *sitter.Node, src []byte, aliases map[string]string) (string, string) {
	switch fnNode.Type() {
	case "attribute":
		obj := fnNode.ChildByFieldName("object")
		attr := fnNode.ChildByFieldName("attribute")
		if obj == nil || attr == nil {
			return "", ""
		}
		objName := obj.Content(src)
		mod, ok := aliases[objName]
		if !ok {
			return "", ""
		}
		// Distinguish `import M` (alias key == module value) from
		// `from M import N` (alias key != module value).
		if mod == objName {
			return mod, attr.Content(src)
		}
		return mod + "." + objName, attr.Content(src)
	case "identifier":
		// from X import Y; then Y(...) means module=X, sel=Y
		name := fnNode.Content(src)
		if mod, ok := aliases[name]; ok {
			return mod, name
		}
	}
	return "", ""
}

func buildB3FindingPy(path string, r CryptoAPIRule, line int) finding.FindingRecord {
	f := buildB3Finding(path, r, line, line)
	if f.Evidence == nil {
		f.Evidence = map[string]any{}
	}
	f.Evidence["language"] = "python"
	return f
}
