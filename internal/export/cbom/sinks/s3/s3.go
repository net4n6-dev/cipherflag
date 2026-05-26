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

// Package s3 implements the Layer 5.3 S3-compatible object storage sink.
// Credentials are resolved via the AWS SDK default credential chain
// (environment variables, shared config file, IAM instance role).
package s3

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom/sinks/types"
)

// Sink posts a CBOM or NDJSON payload to an S3-compatible bucket.
type Sink struct {
	cfg       config.S3SinkConfig
	common    config.SinkConfig
	scopeName string
	client    s3PutAPI
}

// s3PutAPI is the minimal interface the sink needs — allows test injection.
type s3PutAPI interface {
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// New builds an S3 sink using the SDK's default credential chain. Returns an
// error if credentials / region resolution fails.
func New(ctx context.Context, cfg config.S3SinkConfig, common config.SinkConfig, scopeName string) (*Sink, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Region))
	if err != nil {
		return nil, fmt.Errorf("cbom s3sink: load aws config: %w", err)
	}
	opts := []func(*s3.Options){}
	if cfg.EndpointURL != "" {
		opts = append(opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.EndpointURL)
			o.UsePathStyle = true // required for MinIO/LocalStack
		})
	}
	client := s3.NewFromConfig(awsCfg, opts...)
	return &Sink{cfg: cfg, common: common, scopeName: scopeName, client: client}, nil
}

// newWithClient is used by tests to inject a stub s3PutAPI.
func newWithClient(cfg config.S3SinkConfig, common config.SinkConfig, scopeName string, client s3PutAPI) *Sink {
	return &Sink{cfg: cfg, common: common, scopeName: scopeName, client: client}
}

// Send encodes the payload and puts it at the resolved object key.
// CBOM payloads serialize as CycloneDX JSON; event payloads serialize as NDJSON.
func (s *Sink) Send(ctx context.Context, payload *types.SinkPayload) error {
	body, contentType, err := s.encode(payload)
	if err != nil {
		return fmt.Errorf("cbom s3sink: encode: %w", err)
	}

	if s.cfg.ContentEncoding == "gzip" {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		if _, err := gw.Write(body); err != nil {
			return fmt.Errorf("cbom s3sink: gzip: %w", err)
		}
		if err := gw.Close(); err != nil {
			return fmt.Errorf("cbom s3sink: gzip close: %w", err)
		}
		body = buf.Bytes()
	}

	key := s.resolveKey(payload)

	putIn := &s3.PutObjectInput{
		Bucket:      aws.String(s.cfg.Bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(body),
		ContentType: aws.String(contentType),
	}
	if s.cfg.ContentEncoding == "gzip" {
		putIn.ContentEncoding = aws.String("gzip")
	}

	_, err = s.client.PutObject(ctx, putIn)
	if err != nil {
		return fmt.Errorf("cbom s3sink: put %s/%s: %w", s.cfg.Bucket, key, err)
	}
	return nil
}

func (s *Sink) encode(payload *types.SinkPayload) ([]byte, string, error) {
	if payload == nil {
		return nil, "", fmt.Errorf("nil payload")
	}
	if payload.BOM != nil {
		var buf bytes.Buffer
		enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
		enc.SetPretty(false)
		if err := enc.Encode(payload.BOM); err != nil {
			return nil, "", err
		}
		return buf.Bytes(), "application/vnd.cyclonedx+json; version=1.6", nil
	}
	// Events -> NDJSON
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for i := range payload.Events {
		if err := enc.Encode(payload.Events[i].Payload); err != nil {
			return nil, "", err
		}
	}
	return buf.Bytes(), "application/x-ndjson", nil
}

// resolveKey fills in the Prefix template with {scope}, {date}, {timestamp}.
func (s *Sink) resolveKey(payload *types.SinkPayload) string {
	ts := time.Now().UTC()
	prefix := s.cfg.Prefix
	if prefix == "" {
		prefix = "cipherflag/{scope}/{date}/"
	}
	suffix := "cbom"
	extension := ".json"
	if payload.Events != nil {
		suffix = "events"
		extension = ".ndjson"
	}
	if s.cfg.ContentEncoding == "gzip" {
		extension += ".gz"
	}
	filename := fmt.Sprintf("%s-%s%s", suffix, ts.Format("20060102T150405Z"), extension)

	key := strings.NewReplacer(
		"{scope}", sanitizeScope(s.scopeName),
		"{date}", ts.Format("2006-01-02"),
		"{timestamp}", ts.Format("20060102T150405Z"),
	).Replace(prefix)

	if !strings.HasSuffix(key, "/") {
		key += "/"
	}
	return key + filename
}

func sanitizeScope(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == '-' {
			b.WriteRune(c)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}
