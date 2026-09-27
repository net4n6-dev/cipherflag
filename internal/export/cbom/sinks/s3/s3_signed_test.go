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

import (
	"context"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom/sinks/types"
)

// A signed BOM must reach the bucket with its signature. The stock cyclonedx
// encoder emits "signature":{} because cdx.JSFSignature embeds *JSFSigner with
// json:"-".
func TestS3Sink_SignedCBOMKeepsSignature(t *testing.T) {
	stub := &stubPutAPI{}
	sink := newWithClient(
		config.S3SinkConfig{Bucket: "cbom-test", Region: "us-east-1", Prefix: "cf/{scope}/"},
		config.SinkConfig{},
		"prod",
		stub,
	)
	bom := &cdx.BOM{
		SpecVersion:  cdx.SpecVersion1_6,
		SerialNumber: "urn:uuid:x",
		Signature: &cdx.JSFSignature{JSFSigner: &cdx.JSFSigner{
			Algorithm: "Ed25519",
			Value:     "c2ln",
			PublicKey: cdx.JSFPublicKey{KTY: "OKP", CRV: "Ed25519", X: "a2V5"},
		}},
	}
	if err := sink.Send(context.Background(), &types.SinkPayload{BOM: bom}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	body := string(stub.bodyBytes)
	if strings.Contains(body, `"signature":{}`) {
		t.Fatalf("uploaded object carries an empty signature block: %s", body)
	}
	for _, want := range []string{`"algorithm":"Ed25519"`, `"value":"c2ln"`, `"x":"a2V5"`} {
		if !strings.Contains(body, want) {
			t.Errorf("uploaded object missing %s: %s", want, body)
		}
	}
}
