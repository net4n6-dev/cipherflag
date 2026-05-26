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

package config

import (
	"strings"
	"testing"
)

func TestHTTPSinkConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     HTTPSinkConfig
		wantErr string
	}{
		{"valid bearer", HTTPSinkConfig{URL: "https://x", Auth: "bearer", AuthRef: "T"}, ""},
		{"valid none", HTTPSinkConfig{URL: "https://x"}, ""},
		{"missing url", HTTPSinkConfig{Auth: "bearer"}, "url is required"},
		{"bad auth", HTTPSinkConfig{URL: "https://x", Auth: "weird"}, "must be"},
		{"header without name", HTTPSinkConfig{URL: "https://x", Auth: "header"}, "auth_header_name is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate("sink[0]")
			if tt.wantErr == "" && err != nil {
				t.Errorf("want ok, got %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Errorf("want err containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestFileSinkConfig_Validate(t *testing.T) {
	if err := (&FileSinkConfig{PathTemplate: "/tmp/x"}).Validate("s"); err != nil {
		t.Errorf("valid config: %v", err)
	}
	if err := (&FileSinkConfig{}).Validate("s"); err == nil {
		t.Error("expected error for missing path_template")
	}
}

func TestS3SinkConfig_Validate(t *testing.T) {
	ok := S3SinkConfig{Bucket: "b", Region: "us-east-1"}
	if err := ok.Validate("s"); err != nil {
		t.Errorf("valid: %v", err)
	}
	if err := (&S3SinkConfig{Region: "us-east-1"}).Validate("s"); err == nil {
		t.Error("expected error for missing bucket")
	}
	if err := (&S3SinkConfig{Bucket: "b"}).Validate("s"); err == nil {
		t.Error("expected error for missing region")
	}
	if err := (&S3SinkConfig{Bucket: "b", Region: "r", ContentEncoding: "zstd"}).Validate("s"); err == nil {
		t.Error("expected error for bad content_encoding")
	}
}

func TestSplunkSinkConfig_Validate(t *testing.T) {
	ok := SplunkSinkConfig{URL: "https://x:8088", TokenRef: "T"}
	if err := ok.Validate("s"); err != nil {
		t.Errorf("valid: %v", err)
	}
	if err := (&SplunkSinkConfig{TokenRef: "T"}).Validate("s"); err == nil {
		t.Error("expected error for missing url")
	}
	if err := (&SplunkSinkConfig{URL: "x"}).Validate("s"); err == nil {
		t.Error("expected error for missing token_ref")
	}
	if err := (&SplunkSinkConfig{URL: "x", TokenRef: "T", BatchSize: -1}).Validate("s"); err == nil {
		t.Error("expected error for negative batch_size")
	}
}

func TestSyslogSinkConfig_Validate(t *testing.T) {
	ok := SyslogSinkConfig{Protocol: "udp", Address: "h:514", Format: "rfc5424"}
	if err := ok.Validate("s"); err != nil {
		t.Errorf("valid: %v", err)
	}
	if err := (&SyslogSinkConfig{Protocol: "carrier-pigeon", Address: "x", Format: "rfc5424"}).Validate("s"); err == nil {
		t.Error("expected error for bad protocol")
	}
	if err := (&SyslogSinkConfig{Protocol: "tls", Address: "x", Format: "cef"}).Validate("s"); err == nil {
		t.Error("expected error for missing TLS cert/key")
	}
	if err := (&SyslogSinkConfig{Protocol: "udp", Address: "x", Format: "smoke-signal"}).Validate("s"); err == nil {
		t.Error("expected error for bad format")
	}
	if err := (&SyslogSinkConfig{Protocol: "udp", Address: "x", Format: "rfc5424", Facility: 99}).Validate("s"); err == nil {
		t.Error("expected error for facility out of range")
	}
}
