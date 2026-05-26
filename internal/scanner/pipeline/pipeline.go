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

// Package pipeline orchestrates a single scan job: clone, enumerate blobs,
// check cache, run detectors (B1+B4 from 6.1b-3; B3 lands in 6.1c), emit
// findings as JSONB on asset_health_reports, write cache, finalise lineage.
//
// CE OVERLAY NOTES
// ----------------
// This file is the CE-flavor of internal/scanner/pipeline/pipeline.go,
// vendored by scripts/ce-port/extract.sh during Phase B (post-copy patch
// step). Differences vs the EE-original at ce-port-phase1-source:
//
//   1. The "github.com/net4n6-dev/cipherflag/internal/scanner/image" import
//      is dropped — internal/scanner/image is Layer 6.2 EE-moat and is not
//      in the CE manifest.
//   2. Config.ImagePuller's type changes from image.Puller to a locally-
//      declared Puller interface (same shape — Pull(ctx, ImageSpec)
//      (*PullResult, error)). Marker types ImageSpec + PullResult are
//      declared as opaque structs so the field's signature continues to
//      compile; CE binaries never instantiate them (CE has no container
//      scan path).
//   3. The diff-from-base post-filter block in Run() is gated by a
//      conditional that's always false in CE because Config.DiffFromBase
//      defaults to false AND DiffFromBase (the helper from
//      diff_from_base.go, manifest-excluded) doesn't exist in CE. The
//      block is therefore removed wholesale.
//   4. resolveBaseFingerprints is removed (only called from the dropped
//      block above).
//
// All other behavior is byte-identical to the EE-original.
package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/scanner/clone"
	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
	"github.com/net4n6-dev/cipherflag/internal/scanner/fpreduce"
	"github.com/net4n6-dev/cipherflag/internal/scanner/lineage"
)

// Store is the narrow interface the pipeline needs (subset of store.CryptoStore).
type Store interface {
	GetRepository(ctx context.Context, id string) (*model.Repository, error)
	GetProvider(ctx context.Context, id string) (*model.Provider, error)
	UpdateScanJob(ctx context.Context, j *model.ScanJob) error
	GetCacheEntry(ctx context.Context, blobSHA []byte, ruleVersion, promptHash, scanMode, assetType string) (*model.RepoScanCacheEntry, error)
	PutCacheEntry(ctx context.Context, e *model.RepoScanCacheEntry) error
	SaveAssetHealthReport(ctx context.Context, r *model.AssetHealthReport) error
}

// BucketDetector is the interface the pipeline accepts for B1 / B4 (and
// future B3) dispatchers. Same shape as detect.Dispatcher; declared here
// so the pipeline doesn't import the dispatcher packages directly.
type BucketDetector interface {
	Name() string
	Detect(ctx context.Context, b enumerate.Blob, bytes []byte) ([]finding.FindingRecord, error)
}

// Puller is the CE-local stand-in for image.Puller (EE-only). CE never
// instantiates a container puller (Layer 6.2 is EE moat); the interface
// exists so Config.ImagePuller's field shape is stable for any CE code
// that still references it. The CE pipeline never invokes Pull because
// the diff-from-base post-filter block is removed from Run().
type Puller interface {
	Pull(ctx context.Context, spec ImageSpec) (*PullResult, error)
}

// ImageSpec is an opaque marker type matching the EE image.ImageSpec
// signature. Unused in CE.
type ImageSpec struct{}

// PullResult is an opaque marker type matching the EE image.PullResult
// signature. Unused in CE.
type PullResult struct{}

type Config struct {
	CloneDir         string // parent dir under which ephemeral clone dirs are created
	MaxBlobSizeBytes int64
	RuleVersion      string // for cache key
	// Stage-4 detectors. Each is nil-safe; if all are nil the pipeline
	// behaves like 6.1b-2 (empty findings).
	B1 BucketDetector
	B3 BucketDetector
	B4 BucketDetector
	B5 BucketDetector // 6.2b — binary-level crypto library detection (CE: nil)
	// Optional Stage-9 lineage finalizer. nil-safe.
	Finalizer *lineage.Finalizer
	// Optional Stage-6 LLM stage. nil → deterministic-only (Stages 6+7 skipped).
	//
	// In CE this field is always nil — the EE-only *LLMStage concrete is
	// in llm.go which the manifest excludes. The interface declaration
	// keeps the pipeline's Run() body identical to EE's.
	LLM LLMDispatcher
	// Fetcher abstracts Stage 1: git clone (CE) or OCI pull (EE only)
	// dispatched on provider kind. In CE only the git path is exercised;
	// fetcher.go's DispatchingFetcher returns FailureClassNotImplemented
	// for container_registry kinds.
	Fetcher Fetcher
	// MaxRetries caps the number of times a job re-queues with backoff
	// after a retryable RetryableError. Zero means use the default (3).
	MaxRetries int
	// Post-filter configuration (Layer 6.2c). DiffFromBase is always false
	// in CE; the diff-from-base block in Run() is removed (CE overlay).
	Allowlist    *fpreduce.Allowlist // nil → no allow-list applied
	DiffFromBase bool                // CE: must remain false
	ImagePuller  Puller              // CE: must remain nil
}

// LLMDispatcher is the contract the deterministic pipeline uses to invoke
// the Stage-6 AI tier. The deterministic pipeline knows only this interface;
// the concrete AI-tier types (LLMStage, LLMVerdict, prompts, guardrails,
// redactor, anthropic.Client) live behind it and are absent from CE builds.
type LLMDispatcher interface {
	RunAndMerge(ctx context.Context, scanID string, det []finding.FindingRecord, srcBytes []byte) (merged []finding.FindingRecord, summary LLMSummary, err error)
}

// LLMSummary is the per-blob LLM-stage telemetry rolled up into
// scan_jobs.summary_json. Always zero-valued in CE.
type LLMSummary struct {
	CallsAttempted   int     `json:"llm_calls_attempted"`
	CallsSucceeded   int     `json:"llm_calls_succeeded"`
	GuardrailDrops   int     `json:"llm_guardrail_drops"`
	TokensIn         int     `json:"llm_tokens_in"`
	TokensOut        int     `json:"llm_tokens_out"`
	CostUSD          float64 `json:"llm_cost_usd"`
	Truncated        bool    `json:"ai_truncated,omitempty"`
	TruncationReason string  `json:"ai_truncation_reason,omitempty"`
}

// defaultMaxRetries is applied when Config.MaxRetries is unset/zero.
const defaultMaxRetries = 3

type Pipeline struct {
	Store  Store
	Cloner clone.Cloner
	Config Config
}

// Result is returned by Run and reflects the final state written to scan_jobs.
type Result struct {
	Status        string
	FindingsCount int
	ErrorText     string
	Summary       map[string]any
}

// llmRunSummary aggregates per-blob Summary into per-scan summary_json.
type llmRunSummary struct {
	calls         int
	succeeded     int
	guardrailDrop int
	tokensIn      int
	tokensOut     int
	costUSD       float64
	truncated     bool
	truncReason   string
}

func (s *llmRunSummary) add(o LLMSummary) {
	s.calls += o.CallsAttempted
	s.succeeded += o.CallsSucceeded
	s.guardrailDrop += o.GuardrailDrops
	s.tokensIn += o.TokensIn
	s.tokensOut += o.TokensOut
	s.costUSD += o.CostUSD
	if o.Truncated && !s.truncated {
		s.truncated = true
		s.truncReason = o.TruncationReason
	}
}

// Run executes the full pipeline for one job. The job is assumed to be
// claimed (status=running) by the caller; Run writes the terminal status +
// summary back to the store.
//
// Cleanup (ephemeral clone directory) always runs even on error.
func (p *Pipeline) Run(ctx context.Context, job *model.ScanJob, repo *model.Repository) (*Result, error) {
	started := time.Now()
	cloneDir := fmt.Sprintf("%s/%s", p.Config.CloneDir, job.ID)
	if err := os.MkdirAll(p.Config.CloneDir, 0755); err != nil {
		return p.fail(ctx, job, fmt.Errorf("mkdir clone parent: %w", err))
	}
	defer func() {
		if err := os.RemoveAll(cloneDir); err != nil {
			log.Warn().Err(err).Str("scan_id", job.ID).Str("clone_dir", cloneDir).Msg("cleanup failed")
		}
	}()

	// Resolve the Stage-1 fetcher. Prefer Config.Fetcher (post-6.2a wiring)
	// and fall back to Pipeline.Cloner so 6.1-era call sites that still
	// set Cloner: continue to work without changes.
	fetcher := p.Config.Fetcher
	if fetcher == nil {
		fetcher = &fetcherFromCloner{c: p.Cloner}
	}

	// Look up the owning provider's kind so the Fetcher can dispatch
	// between git-clone and container-pull. A missing/orphaned provider
	// is a permanent failure — neither retrying nor falling back makes
	// sense if the provider row is gone.
	providerKind := ""
	if repo.ProviderID != "" {
		prov, err := p.Store.GetProvider(ctx, repo.ProviderID)
		if err != nil {
			return p.fail(ctx, job, fmt.Errorf("lookup provider %s: %w", repo.ProviderID, err))
		}
		if prov != nil {
			providerKind = prov.Kind
		}
	}

	// Stage 1: Fetch (git clone OR container pull). The dispatcher reads
	// the per-job target dir from context to keep the Fetcher interface
	// free of pipeline-internal directory policy.
	fetchCtx := withGitTargetDir(ctx, cloneDir)
	fr, err := fetcher.Fetch(fetchCtx, job, repo, providerKind)
	if err != nil {
		class, retryable, retryAfter := ClassifyError(err)
		maxRetries := p.Config.MaxRetries
		if maxRetries == 0 {
			maxRetries = defaultMaxRetries
		}
		if retryable && job.RetryCount < maxRetries {
			job.Status = model.ScanStatusQueued
			job.RetryCount++
			next := time.Now().Add(retryAfter)
			if retryAfter == 0 {
				next = time.Now().Add(ComputeBackoff(job.RetryCount))
			}
			job.NextRetryAt = &next
			job.FailureClass = class
			job.ErrorText = err.Error()
			if updErr := p.Store.UpdateScanJob(ctx, job); updErr != nil {
				return nil, fmt.Errorf("requeue: %w", updErr)
			}
			return &Result{Status: model.ScanStatusQueued, ErrorText: err.Error()}, nil
		}
		// Permanent failure — stamp failure_class before fail() persists.
		job.FailureClass = class
		return p.fail(ctx, job, fmt.Errorf("fetch: %w", err))
	}

	// Stage 2: Enumerate
	blobs, err := enumerate.Walk(fr.WorkDir, enumerate.Options{MaxBlobSizeBytes: p.Config.MaxBlobSizeBytes})
	if err != nil {
		return p.fail(ctx, job, fmt.Errorf("enumerate: %w", err))
	}

	hasDetectors := p.Config.B1 != nil || p.Config.B3 != nil || p.Config.B4 != nil || p.Config.B5 != nil

	// Stage 3 + Stage 4 + cache write
	var allFindings []finding.FindingRecord
	var scanned, cacheHits int
	// AssetType drives the cache key + asset_health_reports row. Default
	// to "repository" when the fetcher didn't specify (legacy git path).
	assetType := fr.AssetType
	if assetType == "" {
		assetType = model.AssetTypeRepository
	}
	for _, b := range blobs {
		hit, err := p.Store.GetCacheEntry(ctx, b.SHA256, p.Config.RuleVersion, "", job.ScanMode, assetType)
		if err != nil {
			return p.fail(ctx, job, fmt.Errorf("cache lookup %s: %w", b.Path, err))
		}
		if hit != nil {
			cacheHits++
			// Re-hydrate cached findings into the current scan output so the
			// asset_health_report reflects the full repo state, not just
			// newly-scanned blobs.
			if len(hit.FindingsJSON) > 0 && string(hit.FindingsJSON) != "[]" {
				var cached []finding.FindingRecord
				if err := json.Unmarshal(hit.FindingsJSON, &cached); err == nil {
					for i := range cached {
						cached[i].ScanID = job.ID
						if cached[i].CommitSHA == "" {
							cached[i].CommitSHA = fr.HeadSHA
						}
					}
					allFindings = append(allFindings, cached...)
				}
			}
			continue
		}

		var blobFindings []finding.FindingRecord
		if hasDetectors {
			data, err := os.ReadFile(filepath.Join(fr.WorkDir, b.Path))
			if err != nil {
				return p.fail(ctx, job, fmt.Errorf("read %s: %w", b.Path, err))
			}
			if p.Config.B1 != nil {
				fs, err := p.Config.B1.Detect(ctx, b, data)
				if err != nil {
					return p.fail(ctx, job, fmt.Errorf("b1 detect %s: %w", b.Path, err))
				}
				blobFindings = append(blobFindings, fs...)
			}
			if p.Config.B3 != nil {
				fs, err := p.Config.B3.Detect(ctx, b, data)
				if err != nil {
					return p.fail(ctx, job, fmt.Errorf("b3 detect %s: %w", b.Path, err))
				}
				blobFindings = append(blobFindings, fs...)
			}
			if p.Config.B4 != nil {
				fs, err := p.Config.B4.Detect(ctx, b, data)
				if err != nil {
					return p.fail(ctx, job, fmt.Errorf("b4 detect %s: %w", b.Path, err))
				}
				blobFindings = append(blobFindings, fs...)
			}
			if p.Config.B5 != nil {
				fs, err := p.Config.B5.Detect(ctx, b, data)
				if err != nil {
					return p.fail(ctx, job, fmt.Errorf("b5 detect %s: %w", b.Path, err))
				}
				blobFindings = append(blobFindings, fs...)
			}
			for i := range blobFindings {
				blobFindings[i].ScanID = job.ID
				if blobFindings[i].CommitSHA == "" {
					blobFindings[i].CommitSHA = fr.HeadSHA
				}
			}
		}

		// Cache the result (empty array if no findings).
		findingsJSON := []byte("[]")
		if len(blobFindings) > 0 {
			findingsJSON, _ = json.Marshal(blobFindings)
		}
		if err := p.Store.PutCacheEntry(ctx, &model.RepoScanCacheEntry{
			BlobSHA:           b.SHA256,
			RuleVersion:       p.Config.RuleVersion,
			PromptContentHash: "",
			ScanMode:          job.ScanMode,
			AssetType:         assetType,
			FindingsJSON:      findingsJSON,
		}); err != nil {
			return p.fail(ctx, job, fmt.Errorf("cache put %s: %w", b.Path, err))
		}
		allFindings = append(allFindings, blobFindings...)
		scanned++
	}

	// NOTE: the EE-original here merges referrer-attached SBOM/CBOM
	// components as B5 findings (ParseCycloneDXReferrers in
	// referrer_merge.go). In CE, fr.Referrers is always empty (no
	// container fetch path) AND referrer_merge.go is manifest-excluded,
	// so the block — and the helper call — is removed entirely.

	// Stage 6 + 7: LLM analysis and M2 merge (gated by Config.LLM presence).
	// CE: Config.LLM is always nil — this block is dead code in CE. Kept
	// for shape parity with the EE-original.
	var llmSummary llmRunSummary
	if p.Config.LLM != nil && len(allFindings) > 0 {
		byPath := map[string][]int{}
		for i, f := range allFindings {
			byPath[f.Path] = append(byPath[f.Path], i)
		}
		for path, idxs := range byPath {
			data, rerr := os.ReadFile(filepath.Join(fr.WorkDir, path))
			if rerr != nil {
				log.Warn().Err(rerr).Str("path", path).Msg("llm: read blob failed; skipping")
				continue
			}
			subset := make([]finding.FindingRecord, 0, len(idxs))
			for _, i := range idxs {
				subset = append(subset, allFindings[i])
			}
			merged, summary, err := p.Config.LLM.RunAndMerge(ctx, job.ID, subset, data)
			if err != nil {
				log.Warn().Err(err).Str("path", path).Msg("llm: run failed; continuing without verdicts")
				continue
			}
			for j, idx := range idxs {
				allFindings[idx] = merged[j]
			}
			llmSummary.add(summary)
		}
	}

	// Post-filter 1: allow-list (Layer 6.2c). Suppresses findings whose
	// (image_digest, path, fingerprint) matches a curated benign entry.
	if p.Config.Allowlist != nil {
		allFindings = p.Config.Allowlist.Apply(allFindings, fr.AssetID)
	}
	// NOTE: Post-filter 2 (diff-from-base) is intentionally removed in CE —
	// it relied on internal/scanner/image (Layer 6.2) and the
	// diff_from_base.go helper, both excluded by the CE manifest.

	// Stage 8: Emit. Use the asset_type + asset_id the Fetcher resolved so
	// container scans land in their own asset_health_reports rows. Default
	// to repo.ID when fr.AssetID is empty (legacy git path that didn't
	// thread it through).
	emitAssetID := fr.AssetID
	if emitAssetID == "" {
		emitAssetID = repo.ID
	}
	report := &model.AssetHealthReport{
		AssetType: assetType,
		AssetID:   emitAssetID,
		Grade:     "U", // Unscored — repo-specific scoring rules in a follow-on
		Score:     0,
		PQCStatus: "unknown",
	}
	if err := convertFindingsIntoReport(report, allFindings); err != nil {
		return p.fail(ctx, job, err)
	}
	if err := p.Store.SaveAssetHealthReport(ctx, report); err != nil {
		return p.fail(ctx, job, fmt.Errorf("save asset health report: %w", err))
	}

	// Stage 9: Lineage finalize (best-effort; partial failure logs warn).
	var lineageLinks int
	if p.Config.Finalizer != nil {
		n, err := p.Config.Finalizer.Finalize(ctx, repo.ID, job.ID, allFindings)
		lineageLinks = n
		if err != nil {
			log.Warn().Err(err).Str("scan_id", job.ID).Msg("lineage finalize partial failure")
		}
	}

	// Stage 10: finalize scan job
	summary := map[string]any{
		"head_sha":              fr.HeadSHA,
		"blobs_scanned":         scanned,
		"blobs_cache_hit":       cacheHits,
		"findings_total":        len(allFindings),
		"lineage_links_created": lineageLinks,
		"duration_seconds":      int(time.Since(started).Seconds()),
		"llm_calls_attempted":   llmSummary.calls,
		"llm_calls_succeeded":   llmSummary.succeeded,
		"llm_guardrail_drops":   llmSummary.guardrailDrop,
		"llm_tokens_in":         llmSummary.tokensIn,
		"llm_tokens_out":        llmSummary.tokensOut,
		"llm_cost_usd":          llmSummary.costUSD,
	}
	// Container fetchers stash scanned_tag/scanned_digest/scanned_platform
	// in SummaryExtras; merge them into summary_json.
	for k, v := range fr.SummaryExtras {
		summary[k] = v
	}
	if llmSummary.truncated {
		summary["ai_truncated"] = true
		summary["ai_truncation_reason"] = llmSummary.truncReason
	}
	job.Status = model.ScanStatusCompleted
	job.FindingsCount = len(allFindings)
	job.LLMTokensSpent = llmSummary.tokensIn + llmSummary.tokensOut
	job.LLMCostUSD = llmSummary.costUSD
	job.SummaryJSON = summary
	if err := p.Store.UpdateScanJob(ctx, job); err != nil {
		return nil, fmt.Errorf("finalise job: %w", err)
	}
	return &Result{Status: model.ScanStatusCompleted, FindingsCount: len(allFindings), Summary: summary}, nil
}

func (p *Pipeline) fail(ctx context.Context, job *model.ScanJob, err error) (*Result, error) {
	job.Status = model.ScanStatusFailed
	job.ErrorText = err.Error()
	if updErr := p.Store.UpdateScanJob(ctx, job); updErr != nil {
		log.Error().Err(updErr).Str("scan_id", job.ID).Msg("failed to record scan failure")
	}
	return &Result{Status: model.ScanStatusFailed, ErrorText: err.Error()}, nil
}

// convertFindingsIntoReport marshals FindingRecords twice:
//   - report.Findings: stripped HealthFinding form (rule_id/severity/etc.)
//     for downstream readers using the typed model (scoring, risk).
//   - report.RawFindings: full FindingRecord JSON preserved verbatim into
//     the findings JSONB column. Required because HealthFinding doesn't
//     carry bucket/cbom/fingerprint/scan_id — the CBOM generator (6.1c-2)
//     reads those raw fields, and so does the FindingsHandler list path.
//
// SaveAssetHealthReport writes RawFindings if non-nil, falling back to
// json.Marshal(Findings) otherwise.
func convertFindingsIntoReport(report *model.AssetHealthReport, records []finding.FindingRecord) error {
	if len(records) == 0 {
		report.Findings = nil
		report.RawFindings = nil
		return nil
	}
	b, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("marshal findings: %w", err)
	}
	report.RawFindings = b
	var hf []model.HealthFinding
	if err := json.Unmarshal(b, &hf); err != nil {
		return fmt.Errorf("convert findings: %w", err)
	}
	report.Findings = hf
	return nil
}
