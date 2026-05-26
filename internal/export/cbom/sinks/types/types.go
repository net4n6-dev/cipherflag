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

// Package types provides shared types for all CBOM sink implementations.
// By isolating types in a separate package, sink implementations can import
// these types without creating circular dependencies with the cbom package.
package types

import (
	"context"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// SinkEvent is one per-asset or per-finding record emitted to SIEM-style sinks.
type SinkEvent struct {
	Timestamp time.Time              // emission time
	Scope     string                 // originating scope name
	AssetType string                 // "certificate" | "ssh_key" | ...
	AssetID   string                 // fingerprint / UUID
	EventType string                 // "asset" | "finding"
	Severity  string                 // finding severity or asset worst-finding severity
	Payload   map[string]interface{} // flat JSON body
}

// SinkPayload carries either a full CBOM or a stream of per-asset/per-finding
// events. Exactly one of BOM or Events is populated per call. Used by
// Sink.Send so each sink can handle whichever payload format it supports.
type SinkPayload struct {
	BOM    *cdx.BOM
	Events []SinkEvent
}

// Sink is the push destination interface. Both HTTPSink and FileSink implement it.
type Sink interface {
	Send(ctx context.Context, payload *SinkPayload) error
}

// RetryableError marks an HTTP error as retryable (5xx or network).
type RetryableError struct{ Err error }

func (e *RetryableError) Error() string { return e.Err.Error() }
func (e *RetryableError) Unwrap() error { return e.Err }
