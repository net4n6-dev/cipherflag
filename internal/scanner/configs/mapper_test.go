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

package configs

import (
	"testing"
	"time"
)

func TestMapFindings(t *testing.T) {
	findings := []ConfigFinding{
		{
			ConfigType: "sshd_config",
			FilePath:   "/etc/ssh/sshd_config",
			Settings: map[string]string{
				"Ciphers":                "aes256-gcm@openssh.com",
				"MACs":                   "hmac-sha2-256-etm@openssh.com",
				"PasswordAuthentication": "no",
			},
			RawContent: "# full file content here...",
			ModifiedAt: time.Now(),
			FileMode:   0644,
		},
	}

	discoveries := MapFindings(findings)

	if len(discoveries) != 1 {
		t.Fatalf("got %d, want 1", len(discoveries))
	}

	d := discoveries[0]
	if d.ConfigType != "sshd_config" {
		t.Errorf("ConfigType = %q", d.ConfigType)
	}
	if d.FilePath != "/etc/ssh/sshd_config" {
		t.Errorf("FilePath = %q", d.FilePath)
	}
	if d.Settings["Ciphers"] != "aes256-gcm@openssh.com" {
		t.Errorf("Settings[Ciphers] = %q", d.Settings["Ciphers"])
	}
	if d.Findings != nil {
		t.Error("Findings should be nil — scoring is Layer 4")
	}
}

func TestMapFindings_Empty(t *testing.T) {
	discoveries := MapFindings(nil)
	if len(discoveries) != 0 {
		t.Errorf("got %d, want 0", len(discoveries))
	}
}
