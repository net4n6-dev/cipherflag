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

package s3

// This file exists only to give the external test package (s3_test) access to
// this package's test-only construction path (newWithClient, stubPutAPI).
// Kept separate from s3_test.go so the internal-package tests are unaffected.

import "github.com/net4n6-dev/cipherflag/internal/config"

// NewWithClient exposes newWithClient to external tests.
func NewWithClient(cfg config.S3SinkConfig, common config.SinkConfig, scopeName string, client s3PutAPI) *Sink {
	return newWithClient(cfg, common, scopeName, client)
}

// NewStubPutAPI returns a fresh recording PutObject stub for external tests.
// Its concrete type is unexported; use it only through the s3PutAPI interface
// (pass it to NewWithClient) and its exported Body method.
func NewStubPutAPI() *stubPutAPI {
	return &stubPutAPI{}
}

// Body returns the raw bytes of the last object uploaded via this stub.
func (s *stubPutAPI) Body() []byte { return s.bodyBytes }
