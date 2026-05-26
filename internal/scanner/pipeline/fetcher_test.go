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

package pipeline

import (
	"errors"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

func TestClassifyError_RetryableRateLimit(t *testing.T) {
	err := &RetryableError{Class: model.FailureClassRateLimit, RetryAfter: 60 * time.Second, Cause: errors.New("429")}
	class, retryable, after := ClassifyError(err)
	if class != model.FailureClassRateLimit || !retryable || after != 60*time.Second {
		t.Errorf("got class=%q retryable=%v after=%v", class, retryable, after)
	}
}

func TestClassifyError_PermanentAuth(t *testing.T) {
	err := &PermanentError{Class: model.FailureClassAuth, Cause: errors.New("401")}
	class, retryable, _ := ClassifyError(err)
	if class != model.FailureClassAuth || retryable {
		t.Errorf("got class=%q retryable=%v", class, retryable)
	}
}

func TestClassifyError_BareErrorDefaultsToInternalPermanent(t *testing.T) {
	class, retryable, _ := ClassifyError(errors.New("mystery"))
	if class != model.FailureClassInternal || retryable {
		t.Errorf("got class=%q retryable=%v", class, retryable)
	}
}

func TestComputeBackoff_GrowsExponentially(t *testing.T) {
	// With uniform ±25% jitter, the worst-case overlap between buckets is
	// 2.5s (b0 max) vs 3s (b1 min) — they don't overlap. A few samples
	// per bucket is plenty.
	const samples = 3
	var b0, b1, b2 time.Duration
	for i := 0; i < samples; i++ {
		b0 += ComputeBackoff(0)
		b1 += ComputeBackoff(1)
		b2 += ComputeBackoff(2)
	}
	if b0 >= b1 || b1 >= b2 {
		t.Errorf("non-monotonic averages: b0=%v b1=%v b2=%v", b0/samples, b1/samples, b2/samples)
	}
}

func TestComputeBackoff_CapsAt5Min(t *testing.T) {
	// ComputeBackoff caps base at 5min for retry ≥ 8, then applies
	// ±25% jitter. Documented range: [5min - 75s, 5min + 75s) =
	// [3m45s, 6m15s).
	//
	// The prior assertion `got > 6*time.Minute` was tighter than the
	// implementation's documented ±25% jitter (6min = 5min + 20%), so
	// this test flaked ~10% of the time whenever the random offset
	// landed in (135s, 150s). Rebound to the true range.
	const (
		cap5Min        = 5 * time.Minute
		jitterQuarter  = cap5Min / 4 // 75s — the ±25% documented range
	)
	lower := cap5Min - jitterQuarter
	upper := cap5Min + jitterQuarter // upper bound is < this (rand.Int64N is exclusive)

	got := ComputeBackoff(100)
	if got < lower {
		t.Errorf("below documented jitter range: got %v, want ≥ %v", got, lower)
	}
	if got >= upper {
		t.Errorf("exceeded documented jitter range: got %v, want < %v", got, upper)
	}
}

func TestDetectProviderKindFromErr(t *testing.T) {
	cases := []struct{ in, want string }{
		{"401 Unauthorized", model.FailureClassAuth},
		{"403 Forbidden", model.FailureClassAuth},
		{"404 Not Found", model.FailureClassNotFound},
		{"429 Too Many Requests", model.FailureClassRateLimit},
		{"generic failure", ""},
	}
	for _, c := range cases {
		got := DetectProviderKindFromErr(errors.New(c.in))
		if got != c.want {
			t.Errorf("%q: got %q want %q", c.in, got, c.want)
		}
	}
}

func TestBuildImageRef_URLAlreadyTaggedIgnoresBranchRef(t *testing.T) {
	got := buildImageRef("docker.io/library/alpine:3.19", "3.19")
	if got != "docker.io/library/alpine:3.19" {
		t.Errorf("got %q, want no-duplicate-tag", got)
	}
}

func TestBuildImageRef_URLWithDigestIgnoresBranchRef(t *testing.T) {
	url := "docker.io/library/alpine@sha256:abc123"
	got := buildImageRef(url, "latest")
	if got != url {
		t.Errorf("got %q, want digest-form preserved", got)
	}
}

func TestBuildImageRef_URLNoTagAppendsBranchRef(t *testing.T) {
	got := buildImageRef("docker.io/library/alpine", "3.19")
	if got != "docker.io/library/alpine:3.19" {
		t.Errorf("got %q, want :3.19 appended", got)
	}
}

func TestBuildImageRef_URLNoTagEmptyBranchRefDefaultsLatest(t *testing.T) {
	got := buildImageRef("docker.io/library/alpine", "")
	if got != "docker.io/library/alpine:latest" {
		t.Errorf("got %q, want :latest", got)
	}
}

func TestBuildImageRef_LocalhostPort(t *testing.T) {
	// Regression for T9 bug: localhost:5000/library/alpine:3.19 has ":" in
	// the registry hostname portion. Must not confuse the tag detector.
	got := buildImageRef("localhost:5000/library/alpine:3.19", "3.19")
	if got != "localhost:5000/library/alpine:3.19" {
		t.Errorf("got %q, want no-duplicate-tag", got)
	}
}

func TestBuildImageRef_LocalhostPortNoTag(t *testing.T) {
	got := buildImageRef("localhost:5000/library/alpine", "3.19")
	if got != "localhost:5000/library/alpine:3.19" {
		t.Errorf("got %q, want tag appended", got)
	}
}
