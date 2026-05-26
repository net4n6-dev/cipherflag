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
	"strings"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/export/cbom/sinks/types"
)

func TestRFC5424_Format_Basic(t *testing.T) {
	r := &rfc5424Formatter{}
	e := types.SinkEvent{
		Timestamp: time.Unix(1700000000, 0).UTC(),
		Scope:     "prod",
		AssetType: "crypto_library",
		AssetID:   "lib-uuid",
		EventType: "asset",
		Severity:  "Critical",
		Payload:   map[string]interface{}{"library_name": "openssl"},
	}
	out, err := r.Format(e, 16)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.HasPrefix(s, "<130>1 ") { // 16*8 + 2 = 130
		t.Errorf("PRI prefix wrong: %q", s)
	}
	if !strings.Contains(s, "cipherflag") {
		t.Errorf("missing APPNAME: %q", s)
	}
	if !strings.Contains(s, "lib-uuid") {
		t.Errorf("missing MSGID (AssetID): %q", s)
	}
	if !strings.Contains(s, `"library_name":"openssl"`) {
		t.Errorf("missing payload: %q", s)
	}
	if !strings.HasSuffix(s, "\n") {
		t.Errorf("no trailing newline")
	}
}

func TestSeverityToSyslog(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"Critical", 2}, {"High", 3}, {"Medium", 4}, {"Low", 6}, {"Info", 6},
		{"", 6}, {"unrecognised", 6},
	}
	for _, tt := range tests {
		if got := severityToSyslog(tt.in); got != tt.want {
			t.Errorf("severityToSyslog(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestCEF_Format_Finding(t *testing.T) {
	c := &cefFormatter{}
	e := types.SinkEvent{
		EventType: "finding",
		AssetType: "crypto_library",
		AssetID:   "lib1",
		Severity:  "Critical",
		Payload: map[string]interface{}{
			"rule_id":          "LIB-001",
			"title":            "Critical CVE",
			"detail":           "Heartbleed",
			"asset_grade":      "F",
			"asset_risk_score": 95,
		},
	}
	out, err := c.Format(e, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.TrimSuffix(string(out), "\n")
	if !strings.HasPrefix(s, "CEF:0|CipherFlag|CipherFlag-EE|") {
		t.Errorf("missing CEF prefix: %q", s)
	}
	if !strings.Contains(s, "|LIB-001|Critical CVE|10|") {
		t.Errorf("missing rule/title/severity: %q", s)
	}
	if !strings.Contains(s, "assetId=lib1") {
		t.Errorf("missing extension assetId: %q", s)
	}
	if !strings.Contains(s, "riskScore=95") {
		t.Errorf("missing extension riskScore: %q", s)
	}
}

func TestCEF_Format_AssetExpandsToFindings(t *testing.T) {
	c := &cefFormatter{}
	findings := []map[string]interface{}{
		{"rule_id": "LIB-001", "title": "T1", "severity": "Critical", "detail": "d1"},
		{"rule_id": "LIB-002", "title": "T2", "severity": "High", "detail": "d2"},
	}
	e := types.SinkEvent{
		EventType: "asset",
		AssetType: "crypto_library",
		AssetID:   "lib1",
		Payload: map[string]interface{}{
			"findings":   findings,
			"grade":      "D",
			"risk_score": 75,
		},
	}
	out, err := c.Format(e, 0)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) != 2 {
		t.Errorf("line count = %d, want 2 (one per finding)", len(lines))
	}
	if !strings.Contains(lines[0], "LIB-001") || !strings.Contains(lines[1], "LIB-002") {
		t.Errorf("finding rule IDs not present in order: %v", lines)
	}
}

func TestCEF_Format_AssetWithNoFindings_EmitsNothing(t *testing.T) {
	c := &cefFormatter{}
	e := types.SinkEvent{
		EventType: "asset",
		Payload:   map[string]interface{}{"findings": []map[string]interface{}{}},
	}
	out, err := c.Format(e, 0)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Errorf("expected nil for asset with no findings, got %q", string(out))
	}
}

func TestCEF_EscapeHeader(t *testing.T) {
	if got := escapeCEFHeader(`foo|bar`); got != `foo\|bar` {
		t.Errorf("pipe escape: %q", got)
	}
	if got := escapeCEFHeader(`foo\bar`); got != `foo\\bar` {
		t.Errorf("backslash escape: %q", got)
	}
}

func TestCEF_EscapeExtension(t *testing.T) {
	if got := escapeCEFExtension(`a=b`); got != `a\=b` {
		t.Errorf("equals escape: %q", got)
	}
	if got := escapeCEFExtension("line1\nline2"); got != `line1\nline2` {
		t.Errorf("newline escape: %q", got)
	}
}

func TestCEFSeverity(t *testing.T) {
	tests := map[string]int{
		"Critical": 10, "High": 7, "Medium": 5, "Low": 3, "Info": 1, "": 1, "bogus": 1,
	}
	for in, want := range tests {
		if got := cefSeverity(in); got != want {
			t.Errorf("cefSeverity(%q) = %d, want %d", in, got, want)
		}
	}
}
