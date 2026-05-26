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

// Package detect defines the Detector interface and shared helpers used by
// every bucket-specific detector package (b1, b3 in 6.1c, b4).
package detect

import (
	"context"

	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

// Detector examines a single blob and returns zero or more FindingRecords.
// Input is a Blob (path + SHA + size) plus the raw bytes of the file.
// Implementations MUST NOT mutate bytes. They SHOULD be concurrency-safe
// (the pipeline runs N goroutines against the same Detector instance).
type Detector interface {
	Name() string
	// Detect runs against one blob; ctx honoured for cancellation on long scans.
	Detect(ctx context.Context, b enumerate.Blob, bytes []byte) ([]finding.FindingRecord, error)
}

// Dispatcher selects the right per-format Detector(s) for a blob. Used by
// b1.Dispatcher and b4.Dispatcher to keep the pipeline one-call-per-bucket.
type Dispatcher interface {
	Name() string
	Detect(ctx context.Context, b enumerate.Blob, bytes []byte) ([]finding.FindingRecord, error)
}
