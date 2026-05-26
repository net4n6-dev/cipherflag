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

package syslog

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/net4n6-dev/cipherflag/internal/export/cbom/sinks/types"
)

// cefFormatter produces ArcSight Common Event Format lines:
//   CEF:0|Vendor|Product|Version|RuleID|Title|Severity|Extensions\n
//
// For finding events, RuleID/Title/Severity come directly from the event.
// For asset events, each finding in the asset expands to one CEF line
// (asset events with no findings are skipped — Format returns nil).
type cefFormatter struct{}

// Format returns newline-terminated CEF line(s). May return nil for asset
// events that have no findings, indicating the caller should skip.
func (c *cefFormatter) Format(e types.SinkEvent, _ int) ([]byte, error) {
	if e.EventType == "asset" {
		return c.formatAssetAsFindings(e)
	}
	return c.formatFinding(e)
}

func (c *cefFormatter) formatFinding(e types.SinkEvent) ([]byte, error) {
	ruleID := stringOr(e.Payload, "rule_id", "unknown")
	title := stringOr(e.Payload, "title", "")
	severity := cefSeverity(e.Severity)

	ext := map[string]string{
		"assetType": e.AssetType,
		"assetId":   e.AssetID,
		"grade":     stringOr(e.Payload, "asset_grade", ""),
		"riskScore": intOr(e.Payload, "asset_risk_score", "0"),
		"detail":    stringOr(e.Payload, "detail", ""),
	}

	return []byte(buildCEFLine(ruleID, title, severity, ext) + "\n"), nil
}

func (c *cefFormatter) formatAssetAsFindings(e types.SinkEvent) ([]byte, error) {
	rawFindings, _ := e.Payload["findings"].([]map[string]interface{})
	if len(rawFindings) == 0 {
		return nil, nil
	}
	var buf bytes.Buffer
	for _, f := range rawFindings {
		ruleID := stringOr(f, "rule_id", "unknown")
		title := stringOr(f, "title", "")
		severity := cefSeverity(stringOr(f, "severity", "Info"))
		ext := map[string]string{
			"assetType": e.AssetType,
			"assetId":   e.AssetID,
			"grade":     stringOr(e.Payload, "grade", ""),
			"riskScore": intOr(e.Payload, "risk_score", "0"),
			"detail":    stringOr(f, "detail", ""),
		}
		buf.WriteString(buildCEFLine(ruleID, title, severity, ext))
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

// cefSeverity maps CipherFlag severity to CEF 0-10 scale.
func cefSeverity(s string) int {
	switch s {
	case "Critical":
		return 10
	case "High":
		return 7
	case "Medium":
		return 5
	case "Low":
		return 3
	case "Info":
		return 1
	}
	return 1
}

// buildCEFLine assembles the CEF prefix + extensions.
func buildCEFLine(ruleID, title string, severity int, ext map[string]string) string {
	return fmt.Sprintf("CEF:0|CipherFlag|CipherFlag-EE|%s|%s|%s|%d|%s",
		"1.0", // schema version
		escapeCEFHeader(ruleID),
		escapeCEFHeader(title),
		severity,
		buildExtensions(ext),
	)
}

// escapeCEFHeader escapes characters that terminate CEF header fields.
func escapeCEFHeader(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	return s
}

// escapeCEFExtension escapes characters that terminate CEF extension values.
func escapeCEFExtension(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `=`, `\=`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

func buildExtensions(ext map[string]string) string {
	keys := []string{"assetType", "assetId", "grade", "riskScore", "detail"}
	var parts []string
	for _, k := range keys {
		v, ok := ext[k]
		if !ok || v == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s", k, escapeCEFExtension(v)))
	}
	return strings.Join(parts, " ")
}

func stringOr(m map[string]interface{}, key, fallback string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return fallback
}

func intOr(m map[string]interface{}, key, fallback string) string {
	switch v := m[key].(type) {
	case int:
		return fmt.Sprintf("%d", v)
	case float64:
		return fmt.Sprintf("%d", int(v))
	case string:
		return v
	}
	return fallback
}
