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

package model

import "time"

// Scan modes (spec §5/§6).
const (
	ScanModeDeterministicOnly = "deterministic_only"
	ScanModeTriage            = "triage"
	ScanModeEnrichment        = "enrichment"
	ScanModeDeep              = "deep"
)

// Scan job triggers (spec §8).
const (
	TriggerManual    = "manual"
	TriggerScheduled = "scheduled"
)

// Scan job statuses (spec §5 Stage 10).
const (
	ScanStatusQueued    = "queued"
	ScanStatusRunning   = "running"
	ScanStatusCompleted = "completed"
	ScanStatusFailed    = "failed"
	ScanStatusCancelled = "cancelled"
)

// Failure classes (Layer 6.2a — scan_jobs.failure_class). Closed set used by
// the worker to decide whether a failed job should be re-queued with backoff
// (rate_limit, transient) or permanently failed (auth, not_found, malformed,
// security, internal). Empty string means "not classified" (e.g. successful
// runs or legacy rows pre-migration 016).
const (
	FailureClassRateLimit = "rate_limit"
	FailureClassTransient = "transient"
	FailureClassAuth      = "auth"
	FailureClassNotFound  = "not_found"
	FailureClassMalformed = "malformed"
	FailureClassSecurity  = "security"
	FailureClassInternal  = "internal"
	// FailureClassNotImplemented marks a job that hit a code path the
	// running scanner build does not yet support (e.g. container mode
	// before 6.2b wires ImagePuller). Distinct from FailureClassInternal
	// so operators can filter triage views without confusing "feature not
	// in this build" with genuine internal bugs.
	FailureClassNotImplemented = "not_implemented"
)

// ValidScanModes is the closed set used by API validators.
var ValidScanModes = map[string]struct{}{
	ScanModeDeterministicOnly: {},
	ScanModeTriage:            {},
	ScanModeEnrichment:        {},
	ScanModeDeep:              {},
}

func IsValidScanMode(s string) bool {
	_, ok := ValidScanModes[s]
	return ok
}

// IsTerminalScanStatus reports whether a status represents a finished job
// (no further transitions allowed).
func IsTerminalScanStatus(s string) bool {
	switch s {
	case ScanStatusCompleted, ScanStatusFailed, ScanStatusCancelled:
		return true
	default:
		return false
	}
}

// ScanJob is one unit of work in the scanner queue.
//
// BranchRef is dual-use: in git-mode scan jobs it carries the git branch
// (e.g. "main", "feat/x"); in container-mode scan jobs (Layer 6.2) it
// carries the image tag or digest reference (e.g. "v1.2.3", "latest",
// "sha256:abc…"). The underlying column is a free-form TEXT so callers
// can disambiguate by AssetType on the owning asset / the enclosing job.
type ScanJob struct {
	ID             string         `json:"id"`
	RepoID         string         `json:"repo_id"`
	ScanMode       string         `json:"scan_mode"`
	Trigger        string         `json:"trigger"`
	BranchRef      string         `json:"branch_ref,omitempty"`
	Status         string         `json:"status"`
	WorkerID       string         `json:"worker_id,omitempty"`
	StartedAt      *time.Time     `json:"started_at,omitempty"`
	CompletedAt    *time.Time     `json:"completed_at,omitempty"`
	SummaryJSON    map[string]any `json:"summary_json,omitempty"`
	LLMTokensSpent int            `json:"llm_tokens_spent"`
	LLMCostUSD     float64        `json:"llm_cost_usd"`
	FindingsCount  int            `json:"findings_count"`
	ErrorText      string         `json:"error_text,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	// Retry state (Layer 6.2a / migration 016). RetryCount is incremented
	// each time the worker re-queues a job; NextRetryAt gates claims —
	// ClaimScanJob skips rows whose NextRetryAt is still in the future.
	// FailureClass is one of the FailureClass* constants above.
	RetryCount   int        `json:"retry_count"`
	NextRetryAt  *time.Time `json:"next_retry_at,omitempty"`
	FailureClass string     `json:"failure_class,omitempty"`
}

// AIUsageRow mirrors one row in ai_usage_ledger (migration 013).
type AIUsageRow struct {
	ScanID            string    `json:"scan_id"`
	Provider          string    `json:"provider"`
	Model             string    `json:"model"`
	PromptID          string    `json:"prompt_id"`
	PromptVersion     string    `json:"prompt_version"`
	PromptContentHash string    `json:"prompt_content_hash"`
	TokensIn          int       `json:"tokens_in"`
	TokensOut         int       `json:"tokens_out"`
	CostUSD           float64   `json:"cost_usd"`
	At                time.Time `json:"at"`
}

// AIGuardrailViolation mirrors one row in ai_guardrail_violations.
type AIGuardrailViolation struct {
	ScanID             string    `json:"scan_id"`
	Guardrail          string    `json:"guardrail"`
	PromptID           string    `json:"prompt_id"`
	PromptVersion      string    `json:"prompt_version"`
	RawResponseExcerpt string    `json:"raw_response_excerpt"`
	At                 time.Time `json:"at"`
}
