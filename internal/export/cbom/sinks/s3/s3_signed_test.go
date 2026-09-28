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

// External test package: cbomtest depends on internal/export/cbom, which
// itself depends on this sink package (via the push scheduler), so a
// cryptographic signature check can only be wired up from outside package s3.
// See export_test.go for the test-only exported hooks this file needs.
package s3_test

import (
	"context"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom/cbomtest"
	s3sink "github.com/net4n6-dev/cipherflag/internal/export/cbom/sinks/s3"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom/sinks/types"
)

// A signed BOM must reach the bucket with a signature that actually verifies.
// The stock cyclonedx encoder emits "signature":{} because cdx.JSFSignature
// embeds *JSFSigner with json:"-"; a string check on the uploaded bytes cannot
// tell a syntactically-plausible-but-wrong signature from a correct one, so
// this runs the real ed25519.Verify over the RFC 8785 canonical form.
func TestS3Sink_SignedCBOMKeepsSignature(t *testing.T) {
	stub := s3sink.NewStubPutAPI()
	sink := s3sink.NewWithClient(
		config.S3SinkConfig{Bucket: "cbom-test", Region: "us-east-1", Prefix: "cf/{scope}/"},
		config.SinkConfig{},
		"prod",
		stub,
	)
	if err := sink.Send(context.Background(), &types.SinkPayload{BOM: cbomtest.SignedBOM(t)}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	cbomtest.AssertValidSignature(t, stub.Body())
}
