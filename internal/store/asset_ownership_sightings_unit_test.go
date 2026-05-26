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

import "testing"

// TestInferTeamFromSSHComment pins the v1.8.1 ssh_comment producer's
// parser contract: accept only `<local>@<domain>` comments, skip
// personal-email providers, slug-normalise the surviving domain
// minus its TLD. Everything else (free text, ssh-keygen's literal
// `no comment` placeholder, empty string, too-short post-slug)
// returns "" and the caller skips the sighting emit silently.
//
// Spec: research/ownership-plan-v1.8.1.md §3.2.
func TestInferTeamFromSSHComment(t *testing.T) {
	cases := []struct {
		name     string
		comment  string
		expected string
	}{
		{"email corporate", "alice@ops-01.acme.com", "acme"},
		{"email multi-label", "bob@fintech.example.com", "fintech-example"},
		{"email uppercase domain", "alice@ACME.COM", "acme"},
		{"email with whitespace", "  alice@acme.com  ", "acme"},
		{"personal gmail skipped", "charlie@gmail.com", ""},
		{"personal outlook skipped", "ex@outlook.com", ""},
		{"personal hotmail skipped", "ex@hotmail.com", ""},
		{"personal yahoo skipped", "ex@yahoo.com", ""},
		{"personal protonmail skipped", "ex@protonmail.com", ""},
		{"personal icloud skipped", "ex@icloud.com", ""},
		{"no at sign", "payments-bastion", ""},
		{"ssh-keygen placeholder", "no comment", ""},
		{"empty domain", "root@", ""},
		{"empty local", "@acme.com", ""},
		{"too short post-slug", "x@a.co", ""},
		{"empty string", "", ""},
		{"multi-word free-text", "deploy bot for payments", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := InferTeamFromSSHComment(tc.comment)
			if got != tc.expected {
				t.Errorf("InferTeamFromSSHComment(%q) = %q, want %q", tc.comment, got, tc.expected)
			}
		})
	}
}
