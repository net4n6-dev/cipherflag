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

// Fetcher unifies Stage 1 of the scanner pipeline. The git cloner (6.1)
// and the container puller (6.2) both satisfy the same interface so the
// pipeline orchestrator can dispatch on provider kind without knowing
// which concrete fetch backend is in use.
//
// CE OVERLAY NOTES
// ----------------
// This file is the CE-flavor of internal/scanner/pipeline/fetcher.go,
// vendored by scripts/ce-port/extract.sh during Phase B (post-copy patch
// step). Differences vs the EE-original at ce-port-phase1-source:
//
//   1. The "github.com/net4n6-dev/cipherflag/internal/scanner/image" import
//      is dropped — internal/scanner/image is Layer 6.2 EE-moat and is
//      not in the CE manifest.
//   2. FetchResult.Referrers's element type is changed from
//      []image.Referrer to a CE-local []Referrer (defined in pipeline.go's
//      CE overlay as an opaque marker; CE never populates it). The field
//      stays in the struct so callers don't compile-fail referencing it.
//   3. DispatchingFetcher.ImagePuller is typed as the CE-local Puller
//      interface (defined in pipeline.go's CE overlay).
//   4. fetchContainer always returns PermanentError(NotImplemented) — the
//      original called df.ImagePuller.Pull + image.PullError translation,
//      both of which require internal/scanner/image. CE has no container
//      scan path, so the dispatcher short-circuits at the kind check.
//   5. translatePullError is removed (only called from the dropped
//      container path).
//   6. DetectProviderKindFromErr is retained in CE (no image.* deps; exercised by fetcher_test.go).
//
// All other behavior (RetryableError, PermanentError, ClassifyError,
// ComputeBackoff, fetchGit, buildImageRef, fetcherFromCloner) is byte-
// identical to the EE-original.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/scanner/clone"
)

// Referrer is a CE-local stand-in for image.Referrer (EE-only). Always
// empty in CE because the container fetcher path is not exercised.
type Referrer struct{}

// Fetcher is the unified Stage-1 interface satisfied by both the git
// cloner (6.1) and the container puller (6.2). Stage 1 asks the Fetcher
// for a WorkDir + AssetID; everything downstream is source-agnostic.
type Fetcher interface {
	Fetch(ctx context.Context, job *model.ScanJob, src *model.Repository, providerKind string) (*FetchResult, error)
}

// FetchResult is the asset-agnostic output of Stage 1.
type FetchResult struct {
	// WorkDir is the ephemeral filesystem root for detection.
	WorkDir string
	// AssetID is what gets written to asset_health_reports.asset_id.
	//   - git: the repository UUID (unchanged from 6.1)
	//   - container: "sha256:<digest>@<platform>" (EE only)
	AssetID string
	// AssetType discriminates downstream asset-type-aware code.
	//   - "repository" for git
	//   - "container_image" for OCI (EE only)
	AssetType string
	// HeadSHA carries the git commit SHA for repos; empty for containers.
	HeadSHA string
	// Referrers are OCI referrers (SBOMs/CBOMs/attestations) fetched with
	// the image in Stage 1 (6.2b). Always empty in CE.
	Referrers []Referrer
	// SummaryExtras are fields to merge into scan_jobs.summary_json.
	// Containers populate scanned_tag/scanned_digest/scanned_platform here;
	// CE git path leaves this nil.
	SummaryExtras map[string]any
}

// FailureClassifier is exported so StereoscopePuller can share taxonomy.
// (CE retains the type alias only for source-shape parity; CE has no
// StereoscopePuller.)
type FailureClassifier interface {
	Classify(err error) (class string, retryable bool, retryAfter time.Duration)
}

// ClassifyError maps an arbitrary error into the scan_jobs.failure_class
// taxonomy. Returns (class, retryable, optional Retry-After delay).
func ClassifyError(err error) (string, bool, time.Duration) {
	if err == nil {
		return "", false, 0
	}
	// Prefer typed errors.
	var re *RetryableError
	if errors.As(err, &re) {
		return re.Class, true, re.RetryAfter
	}
	var pe *PermanentError
	if errors.As(err, &pe) {
		return pe.Class, false, 0
	}
	// Heuristics for bare errors — network/timeout → transient.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return model.FailureClassTransient, true, 2 * time.Second
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "401"), strings.Contains(s, "403"):
		return model.FailureClassAuth, false, 0
	case strings.Contains(s, "404"):
		return model.FailureClassNotFound, false, 0
	case strings.Contains(s, "429"):
		return model.FailureClassRateLimit, true, 5 * time.Second
	case strings.Contains(s, "timeout"), strings.Contains(s, "temporarily"):
		return model.FailureClassTransient, true, 2 * time.Second
	}
	return model.FailureClassInternal, false, 0
}

// RetryableError wraps a transient registry error.
type RetryableError struct {
	Class      string // rate_limit | transient
	RetryAfter time.Duration
	Cause      error
}

func (e *RetryableError) Error() string {
	if e == nil {
		return "<nil RetryableError>"
	}
	if e.Cause == nil {
		return "retryable: " + e.Class
	}
	return "retryable: " + e.Class + ": " + e.Cause.Error()
}

func (e *RetryableError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// PermanentError wraps a non-retryable error.
type PermanentError struct {
	Class string // auth | not_found | malformed | security | internal
	Cause error
}

func (e *PermanentError) Error() string {
	if e == nil {
		return "<nil PermanentError>"
	}
	if e.Cause == nil {
		return "permanent: " + e.Class
	}
	return "permanent: " + e.Class + ": " + e.Cause.Error()
}

func (e *PermanentError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// ComputeBackoff returns the delay before the next retry, capped at 5 min.
// Exponential: 2s * 2^retry_count, ±25% jitter sampled from a goroutine-
// safe uniform RNG (math/rand/v2).
func ComputeBackoff(retryCount int) time.Duration {
	base := 2 * time.Second
	for i := 0; i < retryCount && base < 5*time.Minute; i++ {
		base *= 2
	}
	if base > 5*time.Minute {
		base = 5 * time.Minute
	}
	jitter := int64(base) / 4
	if jitter <= 0 {
		return base
	}
	offset := rand.Int64N(jitter * 2)
	base += time.Duration(offset - jitter)
	return base
}

// DetectProviderKindFromErr inspects common registry error strings to
// classify 401/403/404/429. Best-effort — typed errors from the puller
// are preferred. This is the fallback for bare errors bubbling up from
// go-containerregistry. Kept in CE because fetcher_test.go exercises it
// and the helper is just string-matching with no image deps.
func DetectProviderKindFromErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "401"):
		return model.FailureClassAuth
	case strings.Contains(s, "403"):
		return model.FailureClassAuth
	case strings.Contains(s, "404"):
		return model.FailureClassNotFound
	case strings.Contains(s, "429"):
		return model.FailureClassRateLimit
	}
	return ""
}

// DispatchingFetcher selects the concrete fetch backend based on the
// owning provider's kind. providerKind == "container_registry" routes to
// ImagePuller; everything else (git providers) routes to GitCloner.
//
// In CE, ImagePuller is always nil — container scanning is Layer 6.2 EE
// moat. A "container_registry" provider therefore always returns a
// PermanentError(NotImplemented).
type DispatchingFetcher struct {
	GitCloner   clone.Cloner
	ImagePuller Puller // CE: Puller is a marker interface defined in pipeline.go
}

var _ Fetcher = (*DispatchingFetcher)(nil)

// Fetch dispatches the request to GitCloner or (in EE) ImagePuller.
// CE always falls through to fetchGit unless providerKind is the literal
// "container_registry" — in which case it returns NotImplemented.
func (df *DispatchingFetcher) Fetch(ctx context.Context, job *model.ScanJob, src *model.Repository, providerKind string) (*FetchResult, error) {
	if providerKind == "container_registry" {
		return nil, &PermanentError{
			Class: model.FailureClassNotImplemented,
			Cause: errors.New("container scanning is an EE-only feature; CE does not include the OCI puller"),
		}
	}
	return df.fetchGit(ctx, job, src)
}

func (df *DispatchingFetcher) fetchGit(ctx context.Context, job *model.ScanJob, src *model.Repository) (*FetchResult, error) {
	if df.GitCloner == nil {
		return nil, &PermanentError{Class: model.FailureClassInternal, Cause: errors.New("git cloner not wired")}
	}
	spec := clone.CloneSpec{
		URL:       src.URL,
		Ref:       job.BranchRef,
		TargetDir: gitTargetDir(ctx),
	}
	cr, err := df.GitCloner.Clone(ctx, spec)
	if err != nil {
		return nil, err
	}
	return &FetchResult{
		WorkDir:   cr.WorkDir,
		AssetID:   src.ID,
		AssetType: model.AssetTypeRepository,
		HeadSHA:   cr.HeadSHA,
	}, nil
}

// buildImageRef composes a canonical OCI reference from the separate
// Repository.URL + ScanJob.BranchRef fields. Retained in CE for the
// fetcher_test.go tests; unused by the CE git path.
func buildImageRef(url, branchRef string) string {
	if strings.Contains(url, "@sha256:") {
		return url
	}
	lastSlash := strings.LastIndex(url, "/")
	tail := url
	if lastSlash >= 0 {
		tail = url[lastSlash+1:]
	}
	if strings.Contains(tail, ":") {
		return url
	}
	if branchRef == "" {
		branchRef = "latest"
	}
	return url + ":" + branchRef
}

// gitTargetDirKey is a context key for passing the resolved per-job clone
// target dir into DispatchingFetcher.fetchGit. The pipeline orchestrator
// computes the path (it owns ephemeral dir layout) and stashes it via
// withGitTargetDir so the dispatcher needn't know that policy.
type gitTargetDirKey struct{}

func withGitTargetDir(ctx context.Context, dir string) context.Context {
	return context.WithValue(ctx, gitTargetDirKey{}, dir)
}

func gitTargetDir(ctx context.Context) string {
	if v, ok := ctx.Value(gitTargetDirKey{}).(string); ok {
		return v
	}
	return ""
}

// fetcherFromCloner adapts a bare clone.Cloner into a Fetcher so legacy
// pipelines that still set Pipeline.Cloner (no Fetcher) keep working.
// Used by Pipeline.Run when Config.Fetcher is nil.
type fetcherFromCloner struct{ c clone.Cloner }

func (f *fetcherFromCloner) Fetch(ctx context.Context, job *model.ScanJob, src *model.Repository, providerKind string) (*FetchResult, error) {
	if f.c == nil {
		return nil, &PermanentError{Class: model.FailureClassInternal, Cause: errors.New("no cloner configured")}
	}
	cr, err := f.c.Clone(ctx, clone.CloneSpec{
		URL:       src.URL,
		Ref:       job.BranchRef,
		TargetDir: gitTargetDir(ctx),
	})
	if err != nil {
		return nil, fmt.Errorf("clone: %w", err)
	}
	return &FetchResult{
		WorkDir:   cr.WorkDir,
		AssetID:   src.ID,
		AssetType: model.AssetTypeRepository,
		HeadSHA:   cr.HeadSHA,
	}, nil
}
