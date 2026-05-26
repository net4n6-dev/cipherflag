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
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom/sinks/types"
)

type stubPutAPI struct {
	lastInput *s3.PutObjectInput
	bodyBytes []byte
	err       error
}

func (s *stubPutAPI) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	s.lastInput = in
	if in.Body != nil {
		b, _ := io.ReadAll(in.Body)
		s.bodyBytes = b
	}
	if s.err != nil {
		return nil, s.err
	}
	return &s3.PutObjectOutput{}, nil
}

func TestS3Sink_SendCBOM(t *testing.T) {
	stub := &stubPutAPI{}
	sink := newWithClient(
		config.S3SinkConfig{Bucket: "cbom-test", Region: "us-east-1", Prefix: "cf/{scope}/"},
		config.SinkConfig{},
		"prod",
		stub,
	)
	err := sink.Send(context.Background(), &types.SinkPayload{BOM: &cdx.BOM{SpecVersion: cdx.SpecVersion1_6, SerialNumber: "urn:uuid:x"}})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if aws.ToString(stub.lastInput.Bucket) != "cbom-test" {
		t.Errorf("Bucket = %q", aws.ToString(stub.lastInput.Bucket))
	}
	key := aws.ToString(stub.lastInput.Key)
	if !strings.HasPrefix(key, "cf/prod/") {
		t.Errorf("Key = %q; want prefix cf/prod/", key)
	}
	if !strings.HasSuffix(key, ".json") {
		t.Errorf("Key = %q; want .json suffix", key)
	}
	if aws.ToString(stub.lastInput.ContentType) != "application/vnd.cyclonedx+json; version=1.6" {
		t.Errorf("ContentType = %q", aws.ToString(stub.lastInput.ContentType))
	}
}

func TestS3Sink_SendEventsNDJSON(t *testing.T) {
	stub := &stubPutAPI{}
	sink := newWithClient(
		config.S3SinkConfig{Bucket: "b", Region: "r", Prefix: "cf/"},
		config.SinkConfig{},
		"prod",
		stub,
	)
	events := []types.SinkEvent{
		{Payload: map[string]interface{}{"asset_id": "a1"}},
		{Payload: map[string]interface{}{"asset_id": "a2"}},
	}
	err := sink.Send(context.Background(), &types.SinkPayload{Events: events})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if aws.ToString(stub.lastInput.ContentType) != "application/x-ndjson" {
		t.Errorf("ContentType = %q", aws.ToString(stub.lastInput.ContentType))
	}
	key := aws.ToString(stub.lastInput.Key)
	if !strings.HasSuffix(key, ".ndjson") {
		t.Errorf("Key = %q; want .ndjson suffix", key)
	}
}

func TestS3Sink_Gzip(t *testing.T) {
	stub := &stubPutAPI{}
	sink := newWithClient(
		config.S3SinkConfig{Bucket: "b", Region: "r", ContentEncoding: "gzip"},
		config.SinkConfig{},
		"prod",
		stub,
	)
	err := sink.Send(context.Background(), &types.SinkPayload{BOM: &cdx.BOM{SpecVersion: cdx.SpecVersion1_6, SerialNumber: "x"}})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if aws.ToString(stub.lastInput.ContentEncoding) != "gzip" {
		t.Errorf("ContentEncoding = %q, want gzip", aws.ToString(stub.lastInput.ContentEncoding))
	}
	key := aws.ToString(stub.lastInput.Key)
	if !strings.HasSuffix(key, ".json.gz") {
		t.Errorf("Key = %q; want .json.gz suffix", key)
	}
}

func TestS3Sink_PutError(t *testing.T) {
	stub := &stubPutAPI{err: fmt.Errorf("bucket does not exist")}
	sink := newWithClient(
		config.S3SinkConfig{Bucket: "b", Region: "r"},
		config.SinkConfig{},
		"prod",
		stub,
	)
	err := sink.Send(context.Background(), &types.SinkPayload{BOM: &cdx.BOM{SpecVersion: cdx.SpecVersion1_6}})
	if err == nil {
		t.Fatal("expected error from PutObject")
	}
}
