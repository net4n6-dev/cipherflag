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
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/java"

	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

// JavaDetector parses .java files via Tree-sitter and matches calls of the
// shape `ClassName.method(stringLiteral)` against the Java rules in the
// catalog. JCA algorithm-string triples (`algorithm/mode/padding`) are
// parsed; the mode component additionally drives the ECB rule independent
// of the underlying cipher.
type JavaDetector struct {
	parser *sitter.Parser
	rules  []CryptoAPIRule
	query  *sitter.Query
}

func NewJavaDetector() *JavaDetector {
	p := sitter.NewParser()
	p.SetLanguage(java.GetLanguage())
	q, _ := sitter.NewQuery([]byte(`
		(method_invocation
			object: (identifier) @class
			name: (identifier) @method
			arguments: (argument_list) @args
		) @call
	`), java.GetLanguage())
	return &JavaDetector{
		parser: p,
		rules:  RulesByLanguage(LangJava),
		query:  q,
	}
}

func (d *JavaDetector) Name() string { return "b3.java" }

func (d *JavaDetector) Detect(ctx context.Context, b enumerate.Blob, data []byte) ([]finding.FindingRecord, error) {
	if filepath.Ext(b.Path) != ".java" {
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

	var out []finding.FindingRecord
	cursor := sitter.NewQueryCursor()
	defer cursor.Close()
	cursor.Exec(d.query, root)
	for {
		match, ok := cursor.NextMatch()
		if !ok {
			break
		}
		var classNode, methodNode, argsNode, callNode *sitter.Node
		for _, c := range match.Captures {
			switch d.query.CaptureNameForId(c.Index) {
			case "class":
				classNode = c.Node
			case "method":
				methodNode = c.Node
			case "args":
				argsNode = c.Node
			case "call":
				callNode = c.Node
			}
		}
		if classNode == nil || methodNode == nil || argsNode == nil || callNode == nil {
			continue
		}
		className := classNode.Content(data)
		methodName := methodNode.Content(data)

		// Extract first argument if it is a literal string. Tree-sitter's
		// java grammar represents string literals as 'string_literal' with
		// the leading/trailing double-quote chars in Content().
		var algStr string
		if argsNode.NamedChildCount() >= 1 {
			first := argsNode.NamedChild(0)
			if first != nil && first.Type() == "string_literal" {
				raw := first.Content(data)
				algStr = strings.Trim(raw, `"`)
			}
		}
		if algStr == "" {
			// No literal arg — cannot resolve. Skip per v1 plan-time decision.
			continue
		}

		algorithm, mode, padding := parseJCATriple(algStr)
		line := int(callNode.StartPoint().Row) + 1

		for _, r := range d.rules {
			if r.ClassName != className || r.Selector != methodName {
				continue
			}
			matched := false
			switch {
			case r.AlgorithmString != "" && r.AlgorithmString == algorithm:
				matched = true
			case r.Mode == "ECB" && mode == "ECB":
				matched = true
			}
			if !matched {
				continue
			}
			f := buildB3Finding(b.Path, r, line, line)
			if f.CBOM == nil {
				f.CBOM = &finding.CBOMInfo{}
			}
			// Override mode/padding from the parsed JCA triple if present
			// (the catalog entry only carries the rule-defining fields).
			if mode != "" {
				f.CBOM.Mode = mode
			}
			if padding != "" {
				f.CBOM.Padding = padding
			}
			if r.Algorithm == "" && algorithm != "" {
				f.CBOM.Algorithm = algorithm
			}
			f.Evidence = map[string]any{
				"language":         "java",
				"algorithm_string": algStr,
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// parseJCATriple splits a JCA algorithm string into its (algorithm, mode, padding)
// components. Examples:
//
//	"MD5"                         -> "MD5", "", ""
//	"DES/CBC/PKCS5Padding"        -> "DES", "CBC", "PKCS5Padding"
//	"AES/ECB/NoPadding"           -> "AES", "ECB", "NoPadding"
//	"AES"                         -> "AES", "", ""
func parseJCATriple(s string) (algorithm, mode, padding string) {
	parts := strings.Split(s, "/")
	if len(parts) >= 1 {
		algorithm = parts[0]
	}
	if len(parts) >= 2 {
		mode = parts[1]
	}
	if len(parts) >= 3 {
		padding = parts[2]
	}
	return
}
