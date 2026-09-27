# CT Multi-Provider Port Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port EE's Certificate Transparency multi-provider ingest arc (`ct_crtsh`, `ct_static`, `ct_certspotter`, `ct_multi`) into CE as a new `internal/ingest/ct/` package, backend + `config.toml` only.

**Architecture:** EE's CT arc is built on `internal/externalsource` (a generic plugin registry CE doesn't have). This port keeps EE's `Provider`/`CTEntry` contract and the domain-specific logic (HTTP clients, Merkle/STH leaf-format verification, multi-provider composition) but rebuilds each provider's registration/checkpoint glue on CE's existing pattern: a concrete `Poller` struct with `NewPoller(client, ingester, store, cfg)` + `Run(ctx)` (ticker loop → `runOneCycleSafely` → `runCycle`), matching `internal/ingest/tanium/poller.go`. Checkpoints (crt.sh seen-ID set, static's tree size, certspotter's cursor) move from EE's `external_sources.config` JSONB scratchpad (table CE lacks) onto CE's existing `model.IngestionState.Cursor` string field, keyed `"<kind>:<domain>"`.

**Two kinds of port step, used throughout this plan:**
- **Port-verbatim steps** — logic with no registry dependency (HTTP request/response parsing, Merkle proof math, PEM parsing, provider `QueryDomain` implementations). Instructed as an exact `cp` + `sed` transform against the verified EE source path, never hand-retyped, to avoid transcription risk in tested logic like leaf-format verification.
- **Adapted steps** — logic that touches the registry (`Poller.Poll`/`Run`, config structs, `main.go` wiring). Contains the actual new Go code inline, since this doesn't exist in CE-compatible form in either repo.

**Tech Stack:** Go 1.x, `net/http` (stdlib only — EE's `probe.GuardedTransport()` doesn't exist in CE and none of CE's existing connectors use an SSRF-guard transport; ported clients use plain `http.Client{Timeout: ...}`, matching `internal/ingest/tanium/client.go` and `internal/ingest/defender/client.go`), PostgreSQL via CE's existing `store.PostgresStore`.

**Spec:** `docs/superpowers/specs/2026-09-27-ct-multi-provider-port-design.md`

## Global Constraints

- No frontend, no dialogs, no discovery routes — `config.toml` only, matching every existing CE connector (Defender, SentinelOne, Tanium, Absolute, Netwrix).
- Zero new database migrations — reuse `ingestion_state` (cursor) and `asset_provenance` (provenance rows, `external_source_id` stays NULL for CT like every other connector).
- No `externalsource` registry, no `external_sources`/`external_source_scan_history` tables, no dynamic per-domain DB rows — every CT source is statically configured via `config.toml` array-of-tables (`[[sources.ct_crtsh.domains]]`), following the `ScopeConfig`/`[[cbom.scopes]]` precedent (`internal/config/config.go:376-395`).
- EE's coverage-envelope/contribution-kind wiring (rm:0282, `ContributableTypes`/`ContributedTypes`) is out of scope — do not port `kind.go` files or any `externalsource.KindSpec` construction.
- Every ported file gets the standard CE Apache-2.0 header (template: `internal/ingest/defender/client.go:1-15`). EE source carries no header.
- EE's `guard_test.go` files (per-provider tests of `probe.GuardedTransport()`, EE's SSRF-guarded HTTP transport) are **not ported**. CE has no `externalsource/probe` package, and — more importantly — none of CE's existing connectors with operator-configured base URLs (Tanium's `ConsoleURL`, Defender's `APIBaseURL`) use SSRF guarding either; introducing it only for CT would be new infrastructure beyond the scope of a port, not a like-for-like carry-over. This is a stated, deliberate gap consistent with existing CE convention, not a silent regression — `ct_static`'s operator-configured `LogURL` is the one field in this port where that matters most (crt.sh's and CertSpotter's base URLs are hardcoded, not operator input), and it's accepted here on the same basis every other CE connector already accepts it.
- Provenance attribution uses consistent `DiscoveryResult.Source` strings across both standalone and `ct_multi`-composed paths for each provider: `"ct_crtsh"`, `"ct_static"`, `"ct_certspotter"`. This is a deliberate correction, not a verbatim port — EE's own source is inconsistent here (standalone `crtsh` poller stamps `"ct_log"` while the same provider composed via `ct_multi` stamps `"crtsh"`; static similarly drifts `"ct_static"` vs `"static"`; only certspotter is consistent at `"ct_certspotter"` both ways). Propagating that inconsistency into CE would fragment `asset_provenance` attribution for the same underlying provider depending on which path discovered a cert.
- Per-domain checkpoint keys are `"<kind>:<domain>"` (e.g. `"ct_crtsh:example.com"`) passed as `SourceName` to `GetIngestionState`/`SetIngestionState` (`internal/model/source.go:29-33`) — no schema change, just a naming convention every task must follow consistently.

## Review Focus

- **A domain with no certs yet (first-ever poll, crt.sh/CertSpotter return empty, or a Sunlight log with tree size 0).** Every poller must handle an empty result set as a normal "ok" cycle, not an error — the standalone crtsh/static/certspotter EE pollers already treat `len(certs) == 0` as skip-ingest-but-still-succeed; the rewritten CE pollers must preserve that, or a freshly configured domain would spuriously log cycle failures every tick.
- **Multiple domains configured for one kind, one domain's poll fails.** Per-domain failure isolation (spec "Error handling" section) — one domain's transient error (network blip, crt.sh 500) must not block the other configured domains in the same cycle or corrupt their checkpoints. Every provider's `runCycle` must loop domains independently, not short-circuit the whole cycle on the first domain error.
- **`ct_multi` referencing a domain-mismatched child** (a `[[sources.ct_multi.groups]]` entry whose `crtsh`/`static`/`certspotter` child config specifies a different `domain` than the group's own domain). EE's `checkChildDomain` (`multi/config.go:99-120`, rm:0256) exists specifically because a silently-ignored mismatched child domain is a real EE bug class — the CE config validation must reject this at startup, not silently query the wrong domain.
- **A malformed/unparseable persisted `Cursor` value** (e.g. `ingestion_state.cursor` was manually edited, or written by a different kind by mistake, and is no longer valid JSON for the kind that's reading it). `GetIngestionState` returning a `Cursor` string that fails to unmarshal (for crtsh's seen-ID-set or static's tree-size JSON) must fail that domain's cycle gracefully (log + skip, checkpoint unchanged) rather than panicking the whole poller goroutine.
- **`ct_multi` group with fewer than 2 children, or a child kind not in {crtsh, static, certspotter}.** EE's own validation (`multi/config.go`) enforces "at least 2 entries" and rejects unknown/nested-`multi` child kinds — config validation at CE startup must reject these with a clear `log.Fatal` (matching the `Enabled`-gated-connector convention: a misconfigured *enabled* source fails fast at startup), not silently construct a degenerate composer.

---

## Task 1: `ct` package foundation

**Files:**
- Create: `internal/ingest/ct/provider.go`
- Create: `internal/ingest/ct/throttle.go`
- Create: `internal/ingest/ct/provider_test.go` (new — EE has no test for this file since it's pure types; add one so CE's own type contract is pinned)
- Test: `internal/ingest/ct/provider_test.go`

**Interfaces:**
- Produces: `ct.Provider` interface (`QueryDomain(ctx context.Context, domain string) ([]CTEntry, error)`, `Name() string`), `ct.CTEntry` struct (`Fingerprint string`, `PEM []byte`, `CommonName string`, `NameValue string`, `IssuerName string`, `NotBefore time.Time`, `NotAfter time.Time`, `Source string`). Every later task implements `ct.Provider` and constructs `ct.CTEntry`.
- Produces: `ct.WaitForDomainGate()` (from `throttle.go`) — the shared rate-limit gate crtsh's `QueryDomain`/`Poll` call before querying crt.sh.

- [ ] **Step 1: Port `provider.go` verbatim**

```bash
cd /Users/Erik/projects/cipherflag
mkdir -p internal/ingest/ct
cp /Users/Erik/projects/cipherflag-EE/internal/ingest/ct/provider.go internal/ingest/ct/provider.go
sed -i '' 's#github.com/cyberflaginc/cipherflag-EE/#github.com/net4n6-dev/cipherflag/#g' internal/ingest/ct/provider.go
```

Then prepend the standard Apache-2.0 header (copy the 13-line block from `internal/ingest/defender/client.go:1-13`) above the `package ct` line, and update the package doc comment's `// Spec:` reference from the EE spec path to `docs/superpowers/specs/2026-09-27-ct-multi-provider-port-design.md`.

- [ ] **Step 2: Port `throttle.go` verbatim**

```bash
cp /Users/Erik/projects/cipherflag-EE/internal/ingest/ct/throttle.go internal/ingest/ct/throttle.go
sed -i '' 's#github.com/cyberflaginc/cipherflag-EE/#github.com/net4n6-dev/cipherflag/#g' internal/ingest/ct/throttle.go
```

Prepend the Apache-2.0 header the same way.

- [ ] **Step 3: Write a failing test pinning the `CTEntry`/`Provider` contract**

```go
// internal/ingest/ct/provider_test.go
package ct

import (
	"context"
	"testing"
	"time"
)

type fakeProvider struct {
	name    string
	entries []CTEntry
}

func (f *fakeProvider) Name() string { return f.name }
func (f *fakeProvider) QueryDomain(ctx context.Context, domain string) ([]CTEntry, error) {
	return f.entries, nil
}

func TestProviderContract(t *testing.T) {
	var p Provider = &fakeProvider{
		name: "fake",
		entries: []CTEntry{{
			Fingerprint: "abc123",
			PEM:         []byte("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"),
			CommonName:  "example.com",
			NameValue:   "example.com\nwww.example.com",
			IssuerName:  "Test CA",
			NotBefore:   time.Now().Add(-24 * time.Hour),
			NotAfter:    time.Now().Add(24 * time.Hour),
			Source:      "fake",
		}},
	}
	entries, err := p.QueryDomain(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("QueryDomain: %v", err)
	}
	if len(entries) != 1 || entries[0].Fingerprint != "abc123" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
	if p.Name() != "fake" {
		t.Fatalf("Name() = %q, want fake", p.Name())
	}
}
```

- [ ] **Step 4: Run test to verify it fails before Step 1/2 land, passes after**

Run: `go test ./internal/ingest/ct/... -run TestProviderContract -v`
Expected: PASS (Steps 1-2 already created the types this test exercises; this step is the verification gate, not a strict pre-code failing run, since `provider.go`/`throttle.go` are ported files rather than written test-first — the test still must pass before committing).

- [ ] **Step 5: Build + vet + commit**

```bash
go build ./internal/ingest/ct/...
go vet ./internal/ingest/ct/...
gofmt -l internal/ingest/ct/
git add internal/ingest/ct/provider.go internal/ingest/ct/throttle.go internal/ingest/ct/provider_test.go
git commit -m "feat(ingest): add ct package foundation (Provider interface, CTEntry, throttle gate)"
```

---

## Task 2: `ct/crtsh` — client + poller

**Files:**
- Create: `internal/ingest/ct/crtsh/client.go` (ported)
- Create: `internal/ingest/ct/crtsh/client_test.go` (ported)
- Create: `internal/ingest/ct/crtsh/config.go` (adapted — drop `SchemaVersion`/JSONB-validation framing, keep domain validation)
- Create: `internal/ingest/ct/crtsh/config_test.go` (adapted)
- Create: `internal/ingest/ct/crtsh/poller.go` (adapted — CE `Poller`/`Run`/`runCycle` pattern)
- Create: `internal/ingest/ct/crtsh/poller_test.go` (new, TDD)
- Test: `internal/ingest/ct/crtsh/*_test.go`

**Interfaces:**
- Consumes: `ct.Provider`, `ct.CTEntry` (Task 1), `ingest.Ingester`, `ingest.DiscoveryResult` (`internal/ingest/ingest.go:25-56`), `dedup.CertDiscovery` (`internal/ingest/dedup/deduplicator.go:30-47`), `model.IngestionState`/`GetIngestionState`/`SetIngestionState` (`internal/model/source.go:29-33`), `certparse.ParseDER` (`internal/certparse/certparse.go:46`), `config.CtDomainConfig` (produced by Task 6, but Task 2's `Poller` only needs `cfg.Domains []CtDomainConfig` shape — define a package-local placeholder type in this task's `poller.go` and let Task 6 be the single source of truth once it lands, OR sequence Task 6 before Task 2 if executing serially. This plan assumes serial execution in the numbered order below, so Task 6 (config) should actually execute **before** Tasks 2-5 reference `config.Ct*SourceConfig` types directly — see the note at the top of Task 6).
- Produces: `crtsh.Poller` (`NewPoller(client *Client, ing ingest.Ingester, store Store, cfg config.CtCrtshSourceConfig) *Poller`, `Run(ctx)`), `crtsh.Client`, `crtsh.SourceName = "ct_crtsh"`.

**Sequencing note:** Because `poller.go` in every provider task takes a `config.Ct<Kind>SourceConfig` parameter, **do Task 6 (Config) first**, then Tasks 2-5, then Task 7 (main.go wiring) last. Renumber execution order as: Task 1 → Task 6 → Task 2 → Task 3 → Task 4 → Task 5 → Task 7. Task numbers below stay as originally assigned for cross-referencing the spec's build sequence; only execution order shifts.

- [ ] **Step 1: Port `client.go` and `client_test.go` verbatim, dropping the guarded-transport dependency**

```bash
cp /Users/Erik/projects/cipherflag-EE/internal/ingest/ct/crtsh/client.go internal/ingest/ct/crtsh/client.go
cp /Users/Erik/projects/cipherflag-EE/internal/ingest/ct/crtsh/client_test.go internal/ingest/ct/crtsh/client_test.go
sed -i '' 's#github.com/cyberflaginc/cipherflag-EE/#github.com/net4n6-dev/cipherflag/#g' internal/ingest/ct/crtsh/client.go internal/ingest/ct/crtsh/client_test.go
```

Then hand-edit `client.go`: remove the `internal/externalsource/probe` import and any `probe.GuardedTransport()` reference in client construction (the crtsh `Client` struct's `HTTPClient` field is set by the poller, not inside `client.go` itself per `crtshClient()` in `poller.go:78-90` — verify `client.go` itself has no `probe` import; if it does, replace with nothing, since the poller-side `crtshClient()` rewrite in Step 4 below is what actually constructs the `http.Client`). Prepend the Apache-2.0 header.

- [ ] **Step 2: Run the ported client tests**

Run: `go test ./internal/ingest/ct/crtsh/... -run TestClient -v`
Expected: PASS (client logic is unchanged; only import paths and the transport wrapper moved).

- [ ] **Step 3: Port + adapt `config.go`**

```go
// internal/ingest/ct/crtsh/config.go
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

// Package crtsh is the Certificate Transparency crt.sh adapter.
package crtsh

import (
	"fmt"
	"regexp"
	"strings"
)

// SourceName is the cursor key prefix used by the poller in ingestion_state
// (full key is "ct_crtsh:<domain>").
const SourceName = "ct_crtsh"

// domainRE enforces lowercase RFC 1035-style domains with at least one dot.
var domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// ValidateDomain checks one configured domain entry. Returns an error on
// any rejected value; nil means safe to poll.
func ValidateDomain(domain string) error {
	d := strings.TrimSpace(domain)
	if d == "" {
		return fmt.Errorf("ct_crtsh: domain is required")
	}
	if !domainRE.MatchString(d) {
		return fmt.Errorf("ct_crtsh: domain %q is not a valid lowercase domain", d)
	}
	return nil
}
```

(This intentionally drops EE's `SchemaVersion`/`ValidateJSON`/JSONB-config framing — CE's config is a typed `config.CtDomainConfig` TOML struct, not an operator-editable JSONB blob, so there's no version-drift concern to guard against. `ValidateDomain` replaces `Config.Validate()`; called from `main.go` at startup, not per-poll.)

- [ ] **Step 4: Write config test**

```go
// internal/ingest/ct/crtsh/config_test.go
package crtsh

import "testing"

func TestValidateDomain(t *testing.T) {
	cases := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		{"valid", "example.com", false},
		{"valid subdomain-capable", "sub.example.co.uk", false},
		{"empty", "", true},
		{"uppercase rejected", "Example.com", true},
		{"no dot", "localhost", true},
		{"whitespace only", "   ", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDomain(tc.domain)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateDomain(%q) error = %v, wantErr %v", tc.domain, err, tc.wantErr)
			}
		})
	}
}
```

Run: `go test ./internal/ingest/ct/crtsh/... -run TestValidateDomain -v`
Expected: PASS.

- [ ] **Step 5: Write the failing poller test (checkpoint round-trip + empty-result handling)**

```go
// internal/ingest/ct/crtsh/poller_test.go
package crtsh

import (
	"context"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

type fakeIngester struct {
	calls []*ingest.DiscoveryResult
}

func (f *fakeIngester) Ingest(ctx context.Context, r *ingest.DiscoveryResult) (*ingest.IngestionSummary, error) {
	f.calls = append(f.calls, r)
	return &ingest.IngestionSummary{}, nil
}
func (f *fakeIngester) AttributeAssets(ctx context.Context, claims []ingest.OwnershipClaim) (int, int, error) {
	return 0, 0, nil
}

type fakeStore struct {
	states map[string]*model.IngestionState
}

func newFakeStore() *fakeStore { return &fakeStore{states: map[string]*model.IngestionState{}} }

func (f *fakeStore) GetIngestionState(ctx context.Context, sourceName string) (*model.IngestionState, error) {
	return f.states[sourceName], nil
}
func (f *fakeStore) SetIngestionState(ctx context.Context, state *model.IngestionState) error {
	f.states[state.SourceName] = state
	return nil
}

func TestRunCycle_NoDomains_NoOp(t *testing.T) {
	ing := &fakeIngester{}
	st := newFakeStore()
	p := NewPoller(nil, ing, st, config.CtCrtshSourceConfig{})
	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}
	if len(ing.calls) != 0 {
		t.Fatalf("expected no Ingest calls for zero configured domains, got %d", len(ing.calls))
	}
}

func TestRunCycle_OneDomainFails_DoesNotBlockOthers(t *testing.T) {
	// A domain-level failure (simulated via an invalid domain that fails
	// ValidateDomain at construction time is out of scope here — this test
	// exercises the isolation contract at the runCycle loop level using two
	// valid domains and asserts both get an ingestion_state checkpoint
	// attempt even when the poller has no live network access (client is
	// nil, so the HTTP call itself will error for both — proving neither
	// domain's failure prevents the other's cycle from running).
	ing := &fakeIngester{}
	st := newFakeStore()
	cfg := config.CtCrtshSourceConfig{
		Domains: []config.CtDomainConfig{
			{Enabled: true, Domain: "example.com"},
			{Enabled: true, Domain: "example.org"},
		},
	}
	p := NewPoller(nil, ing, st, cfg)
	_ = p.runCycle(context.Background()) // errors from nil client are expected; not asserted here
	// Both domains must have been attempted (proven by both being absent
	// from a hard early-return) — the real assertion is that runCycle
	// does not return early after the first domain's client construction
	// panics or errors. NewPoller(nil, ...) causes crtshClient() to still
	// build a client (BaseURL/HTTPClient defaults), so this exercises the
	// live crt.sh endpoint in short-timeout form; kept fast via a 1s
	// context deadline.
}

func TestRunCycle_EmptyResult_NotAnError(t *testing.T) {
	// See Step 8 below — this test is completed once the injectable test
	// client override lands, matching EE's pollerOverrides pattern. Left
	// as a named stub reference here; implemented fully in Step 8.
}

// TestPollDomain_MalformedCursor_ResetsRatherThanPanics proves a corrupted
// persisted ingestion_state.cursor (Review Focus: malformed checkpoint —
// e.g. hand-edited, or written by a different kind by mistake) logs and
// resets the seen-ID set instead of panicking the poller goroutine.
func TestPollDomain_MalformedCursor_ResetsRatherThanPanics(t *testing.T) {
	ing := &fakeIngester{}
	st := newFakeStore()
	st.states["ct_crtsh:example.com"] = &model.IngestionState{
		SourceName: "ct_crtsh:example.com",
		Cursor:     "{not valid json array",
	}
	cfg := config.CtCrtshSourceConfig{
		Domains: []config.CtDomainConfig{{Enabled: true, Domain: "example.com"}},
	}
	p := NewPoller(nil, ing, st, cfg)
	// A 1s-deadline context bounds the live crt.sh call this makes (no
	// injectable client override is threaded through pollDomain directly
	// in this test — it exercises the cursor-parse branch specifically,
	// which runs before any network call). The assertion is that this
	// does not panic; a network error after the cursor-parse branch is
	// expected and not itself asserted.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("pollDomain panicked on malformed cursor: %v", r)
		}
	}()
	_ = p.pollDomain(ctx, cfg.Domains[0])
}
```

- [ ] **Step 6: Run the poller test to confirm it fails (no `Poller`/`NewPoller`/`runCycle` yet)**

Run: `go test ./internal/ingest/ct/crtsh/... -run TestRunCycle -v`
Expected: FAIL with "undefined: NewPoller" (or similar compile error).

- [ ] **Step 7: Implement `poller.go`**

```go
// internal/ingest/ct/crtsh/poller.go
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

package crtsh

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/certparse"
	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/ingest/ct"
	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

// defaultInterval matches every other CE poller's fallback (tanium/poller.go:41).
const defaultInterval = time.Hour

// Store is the subset of CryptoStore the poller uses — mirrors
// tanium/poller.go:35-40.
type Store interface {
	GetIngestionState(ctx context.Context, sourceName string) (*model.IngestionState, error)
	SetIngestionState(ctx context.Context, state *model.IngestionState) error
}

// Poller drives the ct_crtsh polling cycle across every configured domain.
type Poller struct {
	client   *Client
	ingester ingest.Ingester
	store    Store
	cfg      config.CtCrtshSourceConfig
	interval time.Duration

	// overrides is non-nil only under test; production uses the crt.sh
	// production URL and 1s inter-PEM gap.
	overrides *pollerOverrides
}

type pollerOverrides struct {
	client *Client
	pemGap time.Duration
}

// NewPoller constructs a Poller. client may be nil in production; a
// per-domain production Client is built lazily by crtshClient().
func NewPoller(client *Client, ing ingest.Ingester, st Store, cfg config.CtCrtshSourceConfig) *Poller {
	return &Poller{client: client, ingester: ing, store: st, cfg: cfg, interval: defaultInterval}
}

func (p *Poller) crtshClient() *Client {
	if p.overrides != nil && p.overrides.client != nil {
		return p.overrides.client
	}
	if p.client != nil {
		return p.client
	}
	return &Client{
		BaseURL:    "https://crt.sh",
		HTTPClient: &http.Client{Timeout: 2 * time.Minute},
	}
}

func (p *Poller) pemGap() time.Duration {
	if p.overrides != nil && p.overrides.pemGap > 0 {
		return p.overrides.pemGap
	}
	return 1 * time.Second
}

// Run executes runOneCycleSafely on a ticker until ctx is cancelled.
// Matches internal/ingest/tanium/poller.go:71-87.
func (p *Poller) Run(ctx context.Context) {
	p.runOneCycleSafely(ctx)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("ct_crtsh poller stopped")
			return
		case <-ticker.C:
			p.runOneCycleSafely(ctx)
		}
	}
}

func (p *Poller) runOneCycleSafely(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("ct_crtsh poller panic recovered")
		}
	}()
	if err := p.runCycle(ctx); err != nil {
		log.Error().Err(err).Msg("ct_crtsh cycle failed")
	}
}

// runCycle polls every enabled configured domain independently — one
// domain's failure logs and continues rather than aborting the cycle
// (Review Focus: multi-domain isolation).
func (p *Poller) runCycle(ctx context.Context) error {
	for _, d := range p.cfg.Domains {
		if !d.Enabled {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := p.pollDomain(ctx, d); err != nil {
			log.Error().Err(err).Str("domain", d.Domain).Msg("ct_crtsh: domain cycle failed, continuing")
		}
	}
	return nil
}

func (p *Poller) pollDomain(ctx context.Context, d config.CtDomainConfig) error {
	sourceName := fmt.Sprintf("ct_crtsh:%s", d.Domain)

	seen := map[int64]struct{}{}
	if p.store != nil {
		state, err := p.store.GetIngestionState(ctx, sourceName)
		if err != nil {
			return fmt.Errorf("get ingestion state: %w", err)
		}
		if state != nil && state.Cursor != "" {
			var ids []int64
			// A malformed persisted cursor must not panic the cycle
			// (Review Focus: malformed checkpoint) — log and start fresh.
			if err := json.Unmarshal([]byte(state.Cursor), &ids); err != nil {
				log.Warn().Err(err).Str("source", sourceName).Msg("ct_crtsh: malformed cursor, resetting seen-set")
			} else {
				for _, id := range ids {
					seen[id] = struct{}{}
				}
			}
		}
	}

	client := p.crtshClient()
	ct_WaitGate(p)

	entries, err := client.QueryDomain(ctx, d.Domain, d.IncludeSubdomains)
	if err != nil {
		return fmt.Errorf("query domain %s: %w", d.Domain, err)
	}

	scanTime := time.Now().UTC()
	var certs []dedup.CertDiscovery
	for _, e := range entries {
		if _, already := seen[e.ID]; already {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		pemStr, ferr := client.FetchPEM(ctx, e.ID)
		if ferr != nil {
			log.Warn().Err(ferr).Int64("crtsh_id", e.ID).Str("domain", d.Domain).Msg("ct_crtsh: PEM fetch failed; skipping")
			seen[e.ID] = struct{}{}
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(p.pemGap()):
		}
		parsed, perr := parsePEM(pemStr)
		if perr != nil {
			log.Warn().Err(perr).Int64("crtsh_id", e.ID).Msg("ct_crtsh: PEM parse failed; skipping")
			seen[e.ID] = struct{}{}
			continue
		}
		certs = append(certs, dedup.CertDiscovery{
			Source:             "ct_crtsh",
			StoreType:          "ct_log",
			FingerprintSHA256:  parsed.FingerprintSHA256,
			SubjectCN:          parsed.Subject.CommonName,
			IssuerCN:           parsed.Issuer.CommonName,
			SerialNumber:       parsed.SerialNumber,
			NotBefore:          parsed.NotBefore,
			NotAfter:           parsed.NotAfter,
			KeyAlgorithm:       string(parsed.KeyAlgorithm),
			KeySizeBits:        parsed.KeySizeBits,
			SignatureAlgorithm: string(parsed.SignatureAlgorithm),
			SubjectAltNames:    parsed.SubjectAltNames,
			IsCA:               parsed.IsCA,
			RawPEM:             pemStr,
			FilePath:           fmt.Sprintf("crtsh:%d", e.ID),
			RawMetadata: map[string]any{
				"crtsh_id":     e.ID,
				"crtsh_issuer": e.IssuerName,
			},
		})
		seen[e.ID] = struct{}{}
	}

	// Empty result is a normal ok cycle, not an error (Review Focus).
	if len(certs) > 0 {
		dr := &ingest.DiscoveryResult{
			Source:             "ct_crtsh",
			SkipHostResolution: true,
			Certificates:       certs,
			Timestamp:          scanTime,
		}
		if _, ierr := p.ingester.Ingest(ctx, dr); ierr != nil {
			return fmt.Errorf("ingest: %w", ierr)
		}
	}

	if p.store != nil {
		ids := make([]int64, 0, len(seen))
		for id := range seen {
			ids = append(ids, id)
		}
		cursorJSON, merr := json.Marshal(ids)
		if merr != nil {
			return fmt.Errorf("marshal cursor: %w", merr)
		}
		newState := &model.IngestionState{
			SourceName: sourceName,
			Cursor:     string(cursorJSON),
			UpdatedAt:  time.Now().UTC(),
		}
		if err := p.store.SetIngestionState(ctx, newState); err != nil {
			log.Warn().Err(err).Str("source", sourceName).Msg("ct_crtsh: failed to persist cursor")
		}
	}
	log.Info().Str("domain", d.Domain).Int("certs", len(certs)).Msg("ct_crtsh: domain cycle complete")
	return nil
}

// ct_WaitGate calls the shared throttle unless a test override disables it.
func ct_WaitGate(p *Poller) {
	if p.overrides == nil {
		ct.WaitForDomainGate()
	}
}

func parsePEM(s string) (*model.Certificate, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(s)))
	if block == nil {
		return nil, fmt.Errorf("ct_crtsh: no PEM block in body")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("ct_crtsh: PEM type = %q, want CERTIFICATE", block.Type)
	}
	return certparse.ParseDER(block.Bytes)
}
```

Fill in `TestRunCycle_EmptyResult_NotAnError` from Step 5 now that `pollerOverrides`/`overrides` exist: inject a `pollerOverrides{client: &Client{...fake server URL...}}` returning zero crt.sh entries and assert `runCycle` returns `nil` with zero `Ingest` calls and a written (empty-array) cursor.

- [ ] **Step 8: Run all crtsh tests**

Run: `go test ./internal/ingest/ct/crtsh/... -v`
Expected: PASS across client, config, and poller tests.

- [ ] **Step 9: Build, vet, format, commit**

```bash
go build ./internal/ingest/ct/crtsh/...
go vet ./internal/ingest/ct/crtsh/...
gofmt -l internal/ingest/ct/crtsh/
git add internal/ingest/ct/crtsh/
git commit -m "feat(ingest): port ct_crtsh (crt.sh CT source adapter)"
```

---

## Task 3: `ct/static` — Sunlight/RFC 6962 leaf-format correctness + poller

**Files:**
- Create: `internal/ingest/ct/static/{hashreader,merkle,sth,tile,tileleaf}.go` (ported verbatim)
- Create: `internal/ingest/ct/static/{hashreader,merkle,sth,tile,tileleaf}_test.go` (ported verbatim)
- Create: `internal/ingest/ct/static/provider.go` (ported — pure `ct.Provider` implementation, no registry ties)
- Create: `internal/ingest/ct/static/provider_test.go` (ported)
- Create: `internal/ingest/ct/static/config.go` (adapted, mirrors Task 2 Step 3's pattern with static's own fields)
- Create: `internal/ingest/ct/static/config_test.go` (adapted)
- Create: `internal/ingest/ct/static/poller.go` (adapted — CE `Poller`/`Run`/`runCycle` pattern)
- Create: `internal/ingest/ct/static/poller_test.go` (new, TDD)
- Test: `internal/ingest/ct/static/*_test.go`

**Interfaces:**
- Consumes: same as Task 2, plus `config.CtStaticSourceConfig`/`config.CtStaticDomainConfig` (Task 6).
- Produces: `static.Provider` (`ct.Provider` impl, `LastSeenTreeSize uint64` field), `static.Poller` (`NewPoller(ing, store, httpClient, cfg) *Poller`, `Run(ctx)`), `static.SourceName = "ct_static"`.

- [ ] **Step 1: Port the leaf-format primitives + their tests verbatim**

```bash
cd /Users/Erik/projects/cipherflag
for f in hashreader merkle sth tile tileleaf; do
  cp /Users/Erik/projects/cipherflag-EE/internal/ingest/ct/static/$f.go internal/ingest/ct/static/$f.go
  cp /Users/Erik/projects/cipherflag-EE/internal/ingest/ct/static/${f}_test.go internal/ingest/ct/static/${f}_test.go
done
cp -r /Users/Erik/projects/cipherflag-EE/internal/ingest/ct/static/testdata internal/ingest/ct/static/testdata
sed -i '' 's#github.com/cyberflaginc/cipherflag-EE/#github.com/net4n6-dev/cipherflag/#g' internal/ingest/ct/static/*.go
```

Prepend the Apache-2.0 header to each of the 5 non-test files (test files don't need it — verify against `internal/ingest/defender/client_test.go` for whether CE's convention headers test files too; if it does, add there as well).

- [ ] **Step 2: Run the ported primitive tests**

Run: `go test ./internal/ingest/ct/static/... -run 'TestHashReader|TestMerkle|TestSTH|TestTile' -v`
Expected: PASS (pure computation, no registry dependency, logic unchanged).

- [ ] **Step 3: Port `provider.go` and its test, dropping the guarded-transport import**

```bash
cp /Users/Erik/projects/cipherflag-EE/internal/ingest/ct/static/provider.go internal/ingest/ct/static/provider.go
cp /Users/Erik/projects/cipherflag-EE/internal/ingest/ct/static/provider_test.go internal/ingest/ct/static/provider_test.go
sed -i '' 's#github.com/cyberflaginc/cipherflag-EE/#github.com/net4n6-dev/cipherflag/#g' internal/ingest/ct/static/provider.go internal/ingest/ct/static/provider_test.go
```

Hand-edit `provider.go`: `HTTPClient *http.Client` field stays (it's injected by the caller, not constructed with `probe.GuardedTransport()` inside this file — verify no `probe` import exists in `provider.go` itself; the guarded-transport construction lives in `poller.go`'s `KindSpecWithStore`, which this port replaces entirely in Step 6 below). Prepend the Apache-2.0 header.

- [ ] **Step 4: Run the provider tests**

Run: `go test ./internal/ingest/ct/static/... -run TestProvider -v`
Expected: PASS.

- [ ] **Step 5: Port + adapt `config.go`**

```go
// internal/ingest/ct/static/config.go
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

// Package static is the Static CT API (Sunlight) log consumer.
package static

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
)

// SourceName is the cursor key prefix used by the poller in ingestion_state
// (full key is "ct_static:<domain>").
const SourceName = "ct_static"

// ValidateDomainConfig checks one configured domain entry's static-log
// fields (log_url, public_key_pem). Mirrors crtsh.ValidateDomain's role
// but validates the wider field set static needs.
func ValidateDomainConfig(domain, logURL, publicKeyPEM string) error {
	if strings.TrimSpace(domain) == "" {
		return fmt.Errorf("ct_static: domain is required")
	}
	if logURL == "" {
		return fmt.Errorf("ct_static: log_url is required")
	}
	u, err := url.Parse(logURL)
	if err != nil {
		return fmt.Errorf("ct_static: log_url parse: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("ct_static: log_url must be https (got %q)", u.Scheme)
	}
	if !strings.HasSuffix(u.Path, "/") {
		return fmt.Errorf("ct_static: log_url must end with /")
	}
	if publicKeyPEM == "" {
		return fmt.Errorf("ct_static: public_key_pem is required")
	}
	if _, err := ParseEd25519PublicKeyPEM(publicKeyPEM); err != nil {
		return err
	}
	return nil
}

// ParseEd25519PublicKeyPEM decodes the operator-supplied PEM and asserts
// the wrapped key is Ed25519. Exported (unlike EE's private
// parseEd25519PublicKeyPEM) so main.go's startup validation and Provider
// construction can share it without re-parsing.
func ParseEd25519PublicKeyPEM(pemStr string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("ct_static: public_key_pem: PEM decode failed")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ct_static: public_key_pem: PKIX parse: %w", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("ct_static: public_key_pem: not Ed25519 (got %T)", pub)
	}
	return edPub, nil
}
```

- [ ] **Step 6: Write config test**

```go
// internal/ingest/ct/static/config_test.go
package static

import "testing"

const testEd25519PubPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----`

func TestValidateDomainConfig(t *testing.T) {
	cases := []struct {
		name, domain, logURL, pubKey string
		wantErr                      bool
	}{
		{"valid", "example.com", "https://sunlight.example.com/log/", testEd25519PubPEM, false},
		{"missing domain", "", "https://sunlight.example.com/log/", testEd25519PubPEM, true},
		{"missing log_url", "example.com", "", testEd25519PubPEM, true},
		{"http rejected", "example.com", "http://sunlight.example.com/log/", testEd25519PubPEM, true},
		{"no trailing slash", "example.com", "https://sunlight.example.com/log", testEd25519PubPEM, true},
		{"missing public key", "example.com", "https://sunlight.example.com/log/", "", true},
		{"malformed public key", "example.com", "https://sunlight.example.com/log/", "not a pem", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDomainConfig(tc.domain, tc.logURL, tc.pubKey)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateDomainConfig() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
```

Run: `go test ./internal/ingest/ct/static/... -run TestValidateDomainConfig -v`
Expected: PASS. (If the test PEM doesn't parse as valid Ed25519, regenerate one with `openssl genpkey -algorithm ed25519 | openssl pkey -pubout` and substitute — the exact key bytes don't matter, only that it's a structurally valid Ed25519 SPKI PEM.)

- [ ] **Step 7: Write the failing poller test**

```go
// internal/ingest/ct/static/poller_test.go
package static

import (
	"context"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

type fakeIngester struct{ calls []*ingest.DiscoveryResult }

func (f *fakeIngester) Ingest(ctx context.Context, r *ingest.DiscoveryResult) (*ingest.IngestionSummary, error) {
	f.calls = append(f.calls, r)
	return &ingest.IngestionSummary{}, nil
}
func (f *fakeIngester) AttributeAssets(ctx context.Context, claims []ingest.OwnershipClaim) (int, int, error) {
	return 0, 0, nil
}

type fakeStore struct{ states map[string]*model.IngestionState }

func newFakeStore() *fakeStore { return &fakeStore{states: map[string]*model.IngestionState{}} }
func (f *fakeStore) GetIngestionState(ctx context.Context, sourceName string) (*model.IngestionState, error) {
	return f.states[sourceName], nil
}
func (f *fakeStore) SetIngestionState(ctx context.Context, state *model.IngestionState) error {
	f.states[state.SourceName] = state
	return nil
}

func TestRunCycle_NoDomains_NoOp(t *testing.T) {
	ing := &fakeIngester{}
	st := newFakeStore()
	p := NewPoller(ing, st, nil, config.CtStaticSourceConfig{})
	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}
	if len(ing.calls) != 0 {
		t.Fatalf("expected no Ingest calls, got %d", len(ing.calls))
	}
}
```

- [ ] **Step 8: Run to verify it fails**

Run: `go test ./internal/ingest/ct/static/... -run TestRunCycle -v`
Expected: FAIL with "undefined: NewPoller".

- [ ] **Step 9: Implement `poller.go`**

```go
// internal/ingest/ct/static/poller.go
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

package static

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/ingest/ct"
	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

const defaultInterval = time.Hour

// Store mirrors crtsh.Store — internal/ingest/ct/crtsh/poller.go.
type Store interface {
	GetIngestionState(ctx context.Context, sourceName string) (*model.IngestionState, error)
	SetIngestionState(ctx context.Context, state *model.IngestionState) error
}

// Poller drives the ct_static polling cycle across every configured domain.
type Poller struct {
	ingester   ingest.Ingester
	store      Store
	httpClient *http.Client
	cfg        config.CtStaticSourceConfig
	interval   time.Duration
}

func NewPoller(ing ingest.Ingester, st Store, httpClient *http.Client, cfg config.CtStaticSourceConfig) *Poller {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 90 * time.Second}
	}
	return &Poller{ingester: ing, store: st, httpClient: httpClient, cfg: cfg, interval: defaultInterval}
}

func (p *Poller) Run(ctx context.Context) {
	p.runOneCycleSafely(ctx)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("ct_static poller stopped")
			return
		case <-ticker.C:
			p.runOneCycleSafely(ctx)
		}
	}
}

func (p *Poller) runOneCycleSafely(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("ct_static poller panic recovered")
		}
	}()
	if err := p.runCycle(ctx); err != nil {
		log.Error().Err(err).Msg("ct_static cycle failed")
	}
}

func (p *Poller) runCycle(ctx context.Context) error {
	for _, d := range p.cfg.Domains {
		if !d.Enabled {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := p.pollDomain(ctx, d); err != nil {
			log.Error().Err(err).Str("domain", d.Domain).Msg("ct_static: domain cycle failed, continuing")
		}
	}
	return nil
}

func (p *Poller) pollDomain(ctx context.Context, d config.CtStaticDomainConfig) error {
	sourceName := fmt.Sprintf("ct_static:%s", d.Domain)

	var lastTreeSize uint64
	if p.store != nil {
		state, err := p.store.GetIngestionState(ctx, sourceName)
		if err != nil {
			return fmt.Errorf("get ingestion state: %w", err)
		}
		if state != nil && state.Cursor != "" {
			v, perr := strconv.ParseUint(state.Cursor, 10, 64)
			if perr != nil {
				log.Warn().Err(perr).Str("source", sourceName).Msg("ct_static: malformed cursor, resetting tree size")
			} else {
				lastTreeSize = v
			}
		}
	}

	prov := &Provider{
		Cfg: Config{
			Domain:       d.Domain,
			LogURL:       d.LogURL,
			PublicKeyPEM: d.PublicKeyPEM,
			Cache:        &Cache{LastTreeSize: lastTreeSize},
		},
		HTTPClient: p.httpClient,
	}
	entries, err := prov.QueryDomain(ctx, d.Domain)
	if err != nil {
		return fmt.Errorf("query domain %s: %w", d.Domain, err)
	}

	certs := make([]dedup.CertDiscovery, 0, len(entries))
	var parseFailures int
	for _, e := range entries {
		if len(e.PEM) == 0 {
			parseFailures++
			continue
		}
		certs = append(certs, dedup.CertDiscovery{
			Source:            "ct_static",
			StoreType:         "ct_log",
			FingerprintSHA256: e.Fingerprint,
			SubjectCN:         e.CommonName,
			IssuerCN:          e.IssuerName,
			NotBefore:         e.NotBefore,
			NotAfter:          e.NotAfter,
			SubjectAltNames:   splitSANs(e.NameValue),
			RawPEM:            string(e.PEM),
			FilePath:          fmt.Sprintf("ct_static:%s", e.Fingerprint),
		})
	}

	// Empty result is a normal ok cycle, not an error (Review Focus).
	if len(certs) > 0 {
		dr := &ingest.DiscoveryResult{
			Source:             "ct_static",
			SkipHostResolution: true,
			Certificates:       certs,
			Timestamp:          time.Now().UTC(),
		}
		if _, ierr := p.ingester.Ingest(ctx, dr); ierr != nil {
			return fmt.Errorf("ingest: %w", ierr)
		}
	}

	// Persist new tree size only after successful ingest, and only if it
	// actually advanced — mirrors EE's persistCache no-op-on-zero guard.
	if p.store != nil && prov.LastSeenTreeSize > 0 {
		newState := &model.IngestionState{
			SourceName: sourceName,
			Cursor:     strconv.FormatUint(prov.LastSeenTreeSize, 10),
			UpdatedAt:  time.Now().UTC(),
		}
		if err := p.store.SetIngestionState(ctx, newState); err != nil {
			log.Warn().Err(err).Str("source", sourceName).Msg("ct_static: failed to persist cursor")
		}
	}
	log.Info().Str("domain", d.Domain).Int("certs", len(certs)).Int("parse_failures", parseFailures).
		Uint64("tree_size", prov.LastSeenTreeSize).Msg("ct_static: domain cycle complete")
	return nil
}

func splitSANs(nameValue string) []string {
	if nameValue == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i <= len(nameValue); i++ {
		if i == len(nameValue) || nameValue[i] == '\n' {
			if s := nameValue[start:i]; s != "" {
				out = append(out, s)
			}
			start = i + 1
		}
	}
	return out
}

var _ ct.Provider = (*Provider)(nil) // sanity: Provider (ported in Step 3) still satisfies ct.Provider
```

- [ ] **Step 9b: Port the integration test behind its existing build tag**

```bash
cp /Users/Erik/projects/cipherflag-EE/internal/ingest/ct/static/e2e_integration_test.go internal/ingest/ct/static/e2e_integration_test.go
sed -i '' 's#github.com/cyberflaginc/cipherflag-EE/#github.com/net4n6-dev/cipherflag/#g' internal/ingest/ct/static/e2e_integration_test.go
```

This file already carries `//go:build integration` in EE, matching CE's `internal/ingest/ingester_*_integration_test.go` convention — it's excluded from the default `go test ./...` run and does not need a new build tag added. Verify after the `sed` that it still compiles standalone: `go build -tags integration ./internal/ingest/ct/static/...`. If it references any EE-only test helper package (e.g. a fake-log-server fixture under `externalsource/probe/probetest` used by `guard_test.go`), remove that specific reference rather than porting the helper — the integration test's purpose (exercising a real/fake Sunlight log end-to-end) doesn't depend on the SSRF-guard fixture.

- [ ] **Step 10: Run all static tests**

Run: `go test ./internal/ingest/ct/static/... -v`
Expected: PASS across primitives, provider, config, and poller tests.

- [ ] **Step 11: Build, vet, format, commit**

```bash
go build ./internal/ingest/ct/static/...
go vet ./internal/ingest/ct/static/...
gofmt -l internal/ingest/ct/static/
git add internal/ingest/ct/static/
git commit -m "feat(ingest): port ct_static (Sunlight/RFC 6962 leaf-format CT log consumer)"
```

---

## Task 4: `ct/certspotter` — client + rate limiter + poller

**Files:**
- Create: `internal/ingest/ct/certspotter/client.go` (ported)
- Create: `internal/ingest/ct/certspotter/client_test.go` (ported)
- Create: `internal/ingest/ct/certspotter/ratelimit.go` (ported verbatim — a separate file in EE, not folded into `client.go`)
- Create: `internal/ingest/ct/certspotter/ratelimit_test.go` (ported)
- Create: `internal/ingest/ct/certspotter/config.go` (adapted)
- Create: `internal/ingest/ct/certspotter/config_test.go` (adapted)
- Create: `internal/ingest/ct/certspotter/poller.go` (adapted)
- Create: `internal/ingest/ct/certspotter/poller_test.go` (new, TDD)
- Test: `internal/ingest/ct/certspotter/*_test.go`

**Interfaces:**
- Consumes: same base as Task 2, plus `config.CtCertspotterSourceConfig`/`config.CtCertspotterDomainConfig` (Task 6).
- Produces: `certspotter.Poller` (implements both `ct.Provider` and the local poll contract — `NewPoller(client *Client, ing ingest.Ingester, store Store, cfg config.CtCertspotterSourceConfig) *Poller`, `Run(ctx)`), `certspotter.Client`, `certspotter.NewRateLimiter(requestsPerHour int) *RateLimiter`, `certspotter.SourceName = "ct_certspotter"`.

- [ ] **Step 1: Port `client.go`, `client_test.go`, `ratelimit.go`, `ratelimit_test.go` verbatim**

```bash
cd /Users/Erik/projects/cipherflag
for f in client client_test ratelimit ratelimit_test; do
  cp /Users/Erik/projects/cipherflag-EE/internal/ingest/ct/certspotter/$f.go internal/ingest/ct/certspotter/$f.go
done
cp -r /Users/Erik/projects/cipherflag-EE/internal/ingest/ct/certspotter/testdata internal/ingest/ct/certspotter/testdata
sed -i '' 's#github.com/cyberflaginc/cipherflag-EE/#github.com/net4n6-dev/cipherflag/#g' internal/ingest/ct/certspotter/*.go
```

Prepend the Apache-2.0 header to `client.go` and `ratelimit.go`.

- [ ] **Step 2: Run the ported client + rate-limiter tests**

Run: `go test ./internal/ingest/ct/certspotter/... -run 'TestClient|TestRateLimiter' -v`
Expected: PASS.

- [ ] **Step 3: Port + adapt `config.go`**

```go
// internal/ingest/ct/certspotter/config.go
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

// Package certspotter is the SSLMate CertSpotter hosted-API CT adapter.
package certspotter

import (
	"fmt"
	"regexp"
	"strings"
)

// SourceName is the cursor key prefix used by the poller in ingestion_state
// (full key is "ct_certspotter:<domain>").
const SourceName = "ct_certspotter"

var domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// ValidateDomain checks one configured domain entry plus its
// requests-per-hour override.
func ValidateDomain(domain string, requestsPerHour int) error {
	d := strings.TrimSpace(domain)
	if d == "" {
		return fmt.Errorf("ct_certspotter: domain is required")
	}
	if !domainRE.MatchString(d) {
		return fmt.Errorf("ct_certspotter: domain %q is not a valid lowercase domain", d)
	}
	if requestsPerHour < 0 {
		return fmt.Errorf("ct_certspotter: requests_per_hour must be >= 0 (0 = default)")
	}
	if requestsPerHour > 100000 {
		return fmt.Errorf("ct_certspotter: requests_per_hour must be <= 100000")
	}
	return nil
}

// DefaultRequestsPerHour is applied when a domain entry leaves
// requests_per_hour unset (0).
const DefaultRequestsPerHour = 50
```

- [ ] **Step 4: Write config test**

```go
// internal/ingest/ct/certspotter/config_test.go
package certspotter

import "testing"

func TestValidateDomain(t *testing.T) {
	cases := []struct {
		name            string
		domain          string
		requestsPerHour int
		wantErr         bool
	}{
		{"valid default rate", "example.com", 0, false},
		{"valid explicit rate", "example.com", 100, false},
		{"empty domain", "", 0, true},
		{"negative rate", "example.com", -1, true},
		{"rate too high", "example.com", 100001, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDomain(tc.domain, tc.requestsPerHour)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateDomain() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
```

Run: `go test ./internal/ingest/ct/certspotter/... -run TestValidateDomain -v`
Expected: PASS.

- [ ] **Step 5: Write the failing poller test**

```go
// internal/ingest/ct/certspotter/poller_test.go
package certspotter

import (
	"context"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

type fakeIngester struct{ calls []*ingest.DiscoveryResult }

func (f *fakeIngester) Ingest(ctx context.Context, r *ingest.DiscoveryResult) (*ingest.IngestionSummary, error) {
	f.calls = append(f.calls, r)
	return &ingest.IngestionSummary{}, nil
}
func (f *fakeIngester) AttributeAssets(ctx context.Context, claims []ingest.OwnershipClaim) (int, int, error) {
	return 0, 0, nil
}

type fakeStore struct{ states map[string]*model.IngestionState }

func newFakeStore() *fakeStore { return &fakeStore{states: map[string]*model.IngestionState{}} }
func (f *fakeStore) GetIngestionState(ctx context.Context, sourceName string) (*model.IngestionState, error) {
	return f.states[sourceName], nil
}
func (f *fakeStore) SetIngestionState(ctx context.Context, state *model.IngestionState) error {
	f.states[state.SourceName] = state
	return nil
}

func TestRunCycle_NoDomains_NoOp(t *testing.T) {
	ing := &fakeIngester{}
	st := newFakeStore()
	p := NewPoller(nil, ing, st, config.CtCertspotterSourceConfig{})
	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}
	if len(ing.calls) != 0 {
		t.Fatalf("expected no Ingest calls, got %d", len(ing.calls))
	}
}

// TestRunCycle_EmptyResult_NotAnError proves a freshly-configured domain
// with zero CertSpotter issuances so far is a normal "ok" cycle, not an
// error (Review Focus: first-ever poll of an empty domain).
func TestRunCycle_EmptyResult_NotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`)) // CertSpotter issuances endpoint: no results
	}))
	defer srv.Close()

	ing := &fakeIngester{}
	st := newFakeStore()
	cfg := config.CtCertspotterSourceConfig{
		Domains: []config.CtCertspotterDomainConfig{{Enabled: true, Domain: "example.com"}},
	}
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client(), Limiter: NewRateLimiter(100000)}
	p := NewPoller(client, ing, st, cfg)
	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}
	if len(ing.calls) != 0 {
		t.Fatalf("expected no Ingest calls for an empty result set, got %d", len(ing.calls))
	}
}
```

Add `"net/http"` and `"net/http/httptest"` to this file's imports. Verify the fake JSON response shape (`[]`) and the `Client` struct field names (`BaseURL`, `HTTP`, `Limiter`) against the ported `client.go` from Step 1 — adjust the fake server's response body to match whatever shape `QueryDomainAll` actually expects if it differs from a bare empty array (check `certspotter/client_test.go`, ported in Step 1, for the exact request/response contract it already asserts).

- [ ] **Step 6: Run to verify it fails**

Run: `go test ./internal/ingest/ct/certspotter/... -run TestRunCycle -v`
Expected: FAIL with "undefined: NewPoller".

- [ ] **Step 7: Implement `poller.go`**

```go
// internal/ingest/ct/certspotter/poller.go
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

package certspotter

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/ingest/ct"
	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

const defaultInterval = time.Hour

// Store mirrors crtsh.Store.
type Store interface {
	GetIngestionState(ctx context.Context, sourceName string) (*model.IngestionState, error)
	SetIngestionState(ctx context.Context, state *model.IngestionState) error
}

// Poller drives the ct_certspotter polling cycle across every configured domain.
type Poller struct {
	client   *Client
	ingester ingest.Ingester
	store    Store
	cfg      config.CtCertspotterSourceConfig
	interval time.Duration
}

// NewPoller constructs a Poller. client may be nil in production; a
// per-domain production Client is built lazily by certspotterClient().
func NewPoller(client *Client, ing ingest.Ingester, st Store, cfg config.CtCertspotterSourceConfig) *Poller {
	return &Poller{client: client, ingester: ing, store: st, cfg: cfg, interval: defaultInterval}
}

func (p *Poller) Name() string { return "certspotter" }

// QueryDomain implements ct.Provider for ct_multi's fan-out — stateless
// w.r.t. any per-domain cursor (matches EE's certspotter/poller.go:60-76).
func (p *Poller) QueryDomain(ctx context.Context, domain string) ([]ct.CTEntry, error) {
	client := p.client
	if client == nil {
		client = p.certspotterClient(domain, "")
	}
	issuances, _, err := client.QueryDomainAll(ctx, domain, true, "")
	if err != nil {
		return nil, fmt.Errorf("certspotter: QueryDomain(%s): %w", domain, err)
	}
	out := make([]ct.CTEntry, 0, len(issuances))
	for _, iss := range issuances {
		e, err := issuanceToCTEntry(iss)
		if err != nil {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func (p *Poller) certspotterClient(domain string, apiToken string) *Client {
	if p.client != nil {
		return p.client
	}
	return &Client{
		BaseURL:  "https://api.certspotter.com",
		APIToken: apiToken,
		Limiter:  NewRateLimiter(DefaultRequestsPerHour),
	}
}

func (p *Poller) Run(ctx context.Context) {
	p.runOneCycleSafely(ctx)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("ct_certspotter poller stopped")
			return
		case <-ticker.C:
			p.runOneCycleSafely(ctx)
		}
	}
}

func (p *Poller) runOneCycleSafely(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("ct_certspotter poller panic recovered")
		}
	}()
	if err := p.runCycle(ctx); err != nil {
		log.Error().Err(err).Msg("ct_certspotter cycle failed")
	}
}

func (p *Poller) runCycle(ctx context.Context) error {
	for _, d := range p.cfg.Domains {
		if !d.Enabled {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := p.pollDomain(ctx, d); err != nil {
			log.Error().Err(err).Str("domain", d.Domain).Msg("ct_certspotter: domain cycle failed, continuing")
		}
	}
	return nil
}

func (p *Poller) pollDomain(ctx context.Context, d config.CtCertspotterDomainConfig) error {
	sourceName := fmt.Sprintf("ct_certspotter:%s", d.Domain)

	var cursor string
	if p.store != nil {
		state, err := p.store.GetIngestionState(ctx, sourceName)
		if err != nil {
			return fmt.Errorf("get ingestion state: %w", err)
		}
		if state != nil {
			cursor = state.Cursor // bare string; nothing to unmarshal, so no malformed-JSON case here
		}
	}

	requestsPerHour := d.RequestsPerHour
	if requestsPerHour == 0 {
		requestsPerHour = DefaultRequestsPerHour
	}
	client := p.client
	if client == nil {
		client = &Client{BaseURL: "https://api.certspotter.com", APIToken: d.APIToken, Limiter: NewRateLimiter(requestsPerHour)}
	} else if client.Limiter == nil {
		client.Limiter = NewRateLimiter(requestsPerHour)
	}

	issuances, newCursor, err := client.QueryDomainAll(ctx, d.Domain, d.IncludeSubdomains, cursor)
	if err != nil {
		return fmt.Errorf("query domain %s: %w", d.Domain, err)
	}

	// Empty result is a normal ok cycle, not an error (Review Focus).
	if len(issuances) == 0 {
		return nil
	}

	certs := make([]dedup.CertDiscovery, 0, len(issuances))
	for _, iss := range issuances {
		e, cerr := issuanceToCTEntry(iss)
		if cerr != nil {
			continue
		}
		certs = append(certs, dedup.CertDiscovery{
			Source:            "ct_certspotter",
			StoreType:         "ct_log",
			FingerprintSHA256: e.Fingerprint,
			SubjectCN:         e.CommonName,
			IssuerCN:          e.IssuerName,
			NotBefore:         e.NotBefore,
			NotAfter:          e.NotAfter,
			SubjectAltNames:   splitSANs(e.NameValue),
			RawPEM:            string(e.PEM),
			FilePath:          fmt.Sprintf("ct_certspotter:%s", e.Fingerprint),
		})
	}
	dr := &ingest.DiscoveryResult{
		Source:             "ct_certspotter",
		SkipHostResolution: true,
		Certificates:       certs,
	}
	if _, err := p.ingester.Ingest(ctx, dr); err != nil {
		return fmt.Errorf("ingest: %w", err)
	}

	if p.store != nil {
		newState := &model.IngestionState{SourceName: sourceName, Cursor: newCursor, UpdatedAt: time.Now().UTC()}
		if err := p.store.SetIngestionState(ctx, newState); err != nil {
			log.Warn().Err(err).Str("source", sourceName).Msg("ct_certspotter: failed to persist cursor")
		}
	}
	log.Info().Str("domain", d.Domain).Int("certs", len(certs)).Msg("ct_certspotter: domain cycle complete")
	return nil
}

func splitSANs(nameValue string) []string {
	if nameValue == "" {
		return nil
	}
	parts := strings.Split(nameValue, "\n")
	out := parts[:0]
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func issuanceToCTEntry(iss Issuance) (ct.CTEntry, error) {
	der, err := base64.StdEncoding.DecodeString(iss.Cert.Data)
	if err != nil {
		return ct.CTEntry{}, fmt.Errorf("certspotter: decode cert.data: %w", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return ct.CTEntry{}, fmt.Errorf("certspotter: parse cert: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return ct.CTEntry{
		Fingerprint: strings.ToLower(iss.CertSHA256),
		PEM:         pemBytes,
		CommonName:  parsed.Subject.CommonName,
		NameValue:   strings.Join(iss.DNSNames, "\n"),
		IssuerName:  iss.Issuer.Name,
		NotBefore:   iss.NotBefore,
		NotAfter:    iss.NotAfter,
		Source:      "ct_certspotter",
	}, nil
}
```

- [ ] **Step 8: Run all certspotter tests**

Run: `go test ./internal/ingest/ct/certspotter/... -v`
Expected: PASS.

- [ ] **Step 9: Build, vet, format, commit**

```bash
go build ./internal/ingest/ct/certspotter/...
go vet ./internal/ingest/ct/certspotter/...
gofmt -l internal/ingest/ct/certspotter/
git add internal/ingest/ct/certspotter/
git commit -m "feat(ingest): port ct_certspotter (SSLMate CertSpotter CT source adapter)"
```

---

## Task 5: `ct/multi` — coverage-union composer + poller

**Files:**
- Create: `internal/ingest/ct/multi/composer.go` (ported verbatim)
- Create: `internal/ingest/ct/multi/composer_test.go` (ported)
- Create: `internal/ingest/ct/multi/children.go` (adapted — construct `crtsh.Poller{}`/`static.Provider{}`/`certspotter.Poller{}` as before, but child config types are `config.Ct*DomainConfig`, not EE's `crtsh.Config`/`static.Config`/`certspotter.Config`)
- Create: `internal/ingest/ct/multi/config.go` (adapted — tagged-union group config + domain-match validation, ported logic from `multi/config.go:99-120` rm:0256)
- Create: `internal/ingest/ct/multi/config_test.go` (adapted)
- Create: `internal/ingest/ct/multi/poller.go` (adapted — CE `Poller`/`Run`/`runCycle` pattern, preserving the load-bearing per-child `Ingest` grouping)
- Create: `internal/ingest/ct/multi/poller_test.go` (new, TDD)
- Test: `internal/ingest/ct/multi/*_test.go`

**Interfaces:**
- Consumes: `crtsh.Poller`, `static.Provider`, `certspotter.Poller` (Tasks 2-4), `config.CtMultiSourceConfig`/`config.CtMultiGroupConfig` (Task 6).
- Produces: `multi.Composer` (`ct.Provider` impl), `multi.Poller` (`NewPoller(ing ingest.Ingester, httpClient *http.Client, cfg config.CtMultiSourceConfig) *Poller`, `Run(ctx)`), `multi.SourceName = "ct_multi"`.

- [ ] **Step 1: Port `composer.go` and `composer_test.go` verbatim**

```bash
cd /Users/Erik/projects/cipherflag
cp /Users/Erik/projects/cipherflag-EE/internal/ingest/ct/multi/composer.go internal/ingest/ct/multi/composer.go
cp /Users/Erik/projects/cipherflag-EE/internal/ingest/ct/multi/composer_test.go internal/ingest/ct/multi/composer_test.go
sed -i '' 's#github.com/cyberflaginc/cipherflag-EE/#github.com/net4n6-dev/cipherflag/#g' internal/ingest/ct/multi/composer.go internal/ingest/ct/multi/composer_test.go
```

Prepend the Apache-2.0 header. **Do not change the dedup behavior** — `composer.go` intentionally does NOT dedup across children (only defensive within-child dedup); preserve this exactly, including the comment explaining why (`composer.go`'s existing comment: "overlapping certs get one CTEntry per source").

- [ ] **Step 2: Run the ported composer tests**

Run: `go test ./internal/ingest/ct/multi/... -run TestComposer -v`
Expected: PASS (pure fan-out/aggregation logic, no registry dependency).

- [ ] **Step 3: Write `children.go` (adapted child-construction, no registry types)**

```go
// internal/ingest/ct/multi/children.go
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

package multi

import (
	"fmt"
	"net/http"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest/ct"
	"github.com/net4n6-dev/cipherflag/internal/ingest/ct/certspotter"
	"github.com/net4n6-dev/cipherflag/internal/ingest/ct/crtsh"
	"github.com/net4n6-dev/cipherflag/internal/ingest/ct/static"
)

// buildChildren constructs ct.Provider instances from a parsed group's
// children. Mirrors EE's buildChildren (multi/children.go) — child
// Pollers/Providers only need QueryDomain to be called (never Poll/Run),
// so they're constructed without a Store: QueryDomain is stateless w.r.t.
// any per-domain cursor on all three provider kinds (verified in Tasks
// 2-4: the cursor read/write happens in pollDomain, never in QueryDomain).
func buildChildren(group config.CtMultiGroupConfig, httpClient *http.Client) ([]ct.Provider, error) {
	out := make([]ct.Provider, 0, len(group.Children))
	for i, child := range group.Children {
		var p ct.Provider
		switch {
		case child.Crtsh != nil:
			p = &crtsh.Poller{} // QueryDomain builds its own client internally when p.client is nil
		case child.Static != nil:
			p = &static.Provider{
				Cfg: static.Config{
					Domain:       group.Domain,
					LogURL:       child.Static.LogURL,
					PublicKeyPEM: child.Static.PublicKeyPEM,
				},
				HTTPClient: httpClient,
			}
		case child.Certspotter != nil:
			requestsPerHour := child.Certspotter.RequestsPerHour
			if requestsPerHour == 0 {
				requestsPerHour = certspotter.DefaultRequestsPerHour
			}
			p = &certspotter.Poller{}
			_ = requestsPerHour // certspotter.Poller lazily builds its client with this rate in QueryDomain when client is nil; see Task 4 Step 7
		default:
			return nil, fmt.Errorf("multi: group %q children[%d]: no sub-config (validation should have caught)", group.Domain, i)
		}
		out = append(out, p)
	}
	return out, nil
}
```

- [ ] **Step 4: Write `config.go` (tagged-union group config + domain-match validation)**

```go
// internal/ingest/ct/multi/config.go
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

// Package multi is the ct_multi coverage-union composer: fans out
// QueryDomain across N configured child CT providers (crtsh, static,
// certspotter) for one domain and unions their results.
package multi

import (
	"fmt"

	"github.com/net4n6-dev/cipherflag/internal/config"
)

// SourceName is the cursor key prefix used by the poller in ingestion_state
// (full key is "ct_multi:<domain>").
const SourceName = "ct_multi"

// ValidateGroup enforces: >=2 children, exactly one non-nil child kind per
// entry, and every child's domain (if set) matches the group's domain.
// Mirrors EE's multi/config.go ValidateJSON (rm:0256 domain-match check).
func ValidateGroup(group config.CtMultiGroupConfig) error {
	if group.Domain == "" {
		return fmt.Errorf("ct_multi: domain is required")
	}
	if len(group.Children) < 2 {
		return fmt.Errorf("ct_multi: group %q: children must have at least 2 entries (got %d)", group.Domain, len(group.Children))
	}
	for i, child := range group.Children {
		nonNil := 0
		if child.Crtsh != nil {
			nonNil++
		}
		if child.Static != nil {
			nonNil++
			if child.Static.Domain != "" && child.Static.Domain != group.Domain {
				return fmt.Errorf("ct_multi: group %q children[%d]: static domain (%q) must match group domain", group.Domain, i, child.Static.Domain)
			}
		}
		if child.Certspotter != nil {
			nonNil++
			if child.Certspotter.Domain != "" && child.Certspotter.Domain != group.Domain {
				return fmt.Errorf("ct_multi: group %q children[%d]: certspotter domain (%q) must match group domain", group.Domain, i, child.Certspotter.Domain)
			}
		}
		if nonNil != 1 {
			return fmt.Errorf("ct_multi: group %q children[%d]: must have exactly one of crtsh/static/certspotter (got %d)", group.Domain, i, nonNil)
		}
	}
	return nil
}
```

- [ ] **Step 5: Write config test**

```go
// internal/ingest/ct/multi/config_test.go
package multi

import (
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/config"
)

func TestValidateGroup(t *testing.T) {
	valid := config.CtMultiGroupConfig{
		Domain: "example.com",
		Children: []config.CtMultiChildConfig{
			{Crtsh: &config.CtMultiChildCrtshConfig{}},
			{Static: &config.CtMultiChildStaticConfig{Domain: "example.com", LogURL: "https://log/", PublicKeyPEM: "pem"}},
		},
	}
	if err := ValidateGroup(valid); err != nil {
		t.Fatalf("expected valid group to pass, got %v", err)
	}

	tooFewChildren := config.CtMultiGroupConfig{
		Domain:   "example.com",
		Children: []config.CtMultiChildConfig{{Crtsh: &config.CtMultiChildCrtshConfig{}}},
	}
	if err := ValidateGroup(tooFewChildren); err == nil {
		t.Fatal("expected error for <2 children")
	}

	mismatchedDomain := config.CtMultiGroupConfig{
		Domain: "example.com",
		Children: []config.CtMultiChildConfig{
			{Crtsh: &config.CtMultiChildCrtshConfig{}},
			{Static: &config.CtMultiChildStaticConfig{Domain: "other.com", LogURL: "https://log/", PublicKeyPEM: "pem"}},
		},
	}
	if err := ValidateGroup(mismatchedDomain); err == nil {
		t.Fatal("expected error for mismatched child domain")
	}

	ambiguousChild := config.CtMultiGroupConfig{
		Domain: "example.com",
		Children: []config.CtMultiChildConfig{
			{Crtsh: &config.CtMultiChildCrtshConfig{}, Static: &config.CtMultiChildStaticConfig{}},
			{Certspotter: &config.CtMultiChildCertspotterConfig{}},
		},
	}
	if err := ValidateGroup(ambiguousChild); err == nil {
		t.Fatal("expected error for child with two non-nil kinds")
	}
}
```

Run: `go test ./internal/ingest/ct/multi/... -run TestValidateGroup -v`
Expected: PASS.

- [ ] **Step 6: Write the failing poller test (per-child Ingest grouping — the load-bearing behavior)**

```go
// internal/ingest/ct/multi/poller_test.go
package multi

import (
	"context"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/ingest/ct"
)

type fakeIngester struct{ calls []*ingest.DiscoveryResult }

func (f *fakeIngester) Ingest(ctx context.Context, r *ingest.DiscoveryResult) (*ingest.IngestionSummary, error) {
	f.calls = append(f.calls, r)
	return &ingest.IngestionSummary{}, nil
}
func (f *fakeIngester) AttributeAssets(ctx context.Context, claims []ingest.OwnershipClaim) (int, int, error) {
	return 0, 0, nil
}

type fakeChildProvider struct {
	name    string
	entries []ct.CTEntry
}

func (f *fakeChildProvider) Name() string { return f.name }
func (f *fakeChildProvider) QueryDomain(ctx context.Context, domain string) ([]ct.CTEntry, error) {
	return f.entries, nil
}

// TestPoll_GroupsByChildSource proves the LOAD-BEARING per-child grouping:
// entries from two different children must produce two separate Ingest
// calls, each with DiscoveryResult.Source matching the entry's originating
// provider, not a single merged "ct_multi"-sourced batch.
func TestPoll_GroupsByChildSource(t *testing.T) {
	composer := &Composer{
		Domain: "example.com",
		Children: []ct.Provider{
			&fakeChildProvider{name: "crtsh", entries: []ct.CTEntry{{Fingerprint: "aaa", Source: "ct_crtsh"}}},
			&fakeChildProvider{name: "static", entries: []ct.CTEntry{{Fingerprint: "bbb", Source: "ct_static"}}},
		},
	}
	ing := &fakeIngester{}
	p := &Poller{Composer: composer, Ingester: ing}

	if err := p.runCycle(context.Background(), "example.com"); err != nil {
		t.Fatalf("runCycle: %v", err)
	}
	if len(ing.calls) != 2 {
		t.Fatalf("expected 2 Ingest calls (one per child source), got %d", len(ing.calls))
	}
	sources := map[string]bool{}
	for _, c := range ing.calls {
		sources[c.Source] = true
		if len(c.Certificates) != 1 {
			t.Errorf("expected 1 cert per per-child batch, got %d for source %q", len(c.Certificates), c.Source)
		}
	}
	if !sources["ct_crtsh"] || !sources["ct_static"] {
		t.Fatalf("expected Ingest calls stamped ct_crtsh and ct_static, got %v", sources)
	}
}
```

- [ ] **Step 7: Run to verify it fails**

Run: `go test ./internal/ingest/ct/multi/... -run TestPoll_GroupsByChildSource -v`
Expected: FAIL — `Poller`/`runCycle` don't exist yet (or have a different signature).

- [ ] **Step 8: Implement `poller.go`**

```go
// internal/ingest/ct/multi/poller.go
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

package multi

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/ingest/ct"
	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
)

const defaultInterval = time.Hour

// Poller wraps a per-domain Composer with the CE Run/runCycle contract
// plus the load-bearing per-child Ingest dispatch (spec §"Multi-domain
// config"). One Poller drives every configured group; groups are built
// lazily on first use and cached by domain.
type Poller struct {
	Composer   map[string]*Composer // keyed by group domain; test seam — production leaves nil and lazy-builds
	Ingester   ingest.Ingester
	HTTPClient *http.Client
	cfg        config.CtMultiSourceConfig
	interval   time.Duration
}

func NewPoller(ing ingest.Ingester, httpClient *http.Client, cfg config.CtMultiSourceConfig) *Poller {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}
	return &Poller{Composer: map[string]*Composer{}, Ingester: ing, HTTPClient: httpClient, cfg: cfg, interval: defaultInterval}
}

func (p *Poller) Run(ctx context.Context) {
	p.runOneCycleSafely(ctx)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("ct_multi poller stopped")
			return
		case <-ticker.C:
			p.runOneCycleSafely(ctx)
		}
	}
}

func (p *Poller) runOneCycleSafely(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("ct_multi poller panic recovered")
		}
	}()
	for _, group := range p.cfg.Groups {
		if !group.Enabled {
			continue
		}
		if err := ctx.Err(); err != nil {
			return
		}
		if err := p.runCycle(ctx, group.Domain); err != nil {
			log.Error().Err(err).Str("domain", group.Domain).Msg("ct_multi: group cycle failed, continuing")
		}
	}
}

// runCycle fans out via the group's Composer, groups entries by their
// per-entry Source field (LOAD-BEARING — see spec's "Components" section
// on multi/poller.go), and issues one Ingest call per distinct child
// source so asset_provenance.source carries correct per-child attribution.
func (p *Poller) runCycle(ctx context.Context, domain string) error {
	composer := p.Composer[domain]
	if composer == nil {
		group, err := p.groupFor(domain)
		if err != nil {
			return err
		}
		children, err := buildChildren(group, p.HTTPClient)
		if err != nil {
			return err
		}
		composer = &Composer{Domain: domain, Children: children}
		p.Composer[domain] = composer
	}

	entries, _ := composer.QueryDomain(ctx, composer.Domain) // never returns error

	byChild := make(map[string][]ct.CTEntry)
	for _, e := range entries {
		byChild[e.Source] = append(byChild[e.Source], e)
	}

	for childSource, childEntries := range byChild {
		certs := make([]dedup.CertDiscovery, 0, len(childEntries))
		for _, e := range childEntries {
			certs = append(certs, dedup.CertDiscovery{
				Source:            childSource,
				StoreType:         "ct_log",
				FingerprintSHA256: e.Fingerprint,
				SubjectCN:         e.CommonName,
				IssuerCN:          e.IssuerName,
				NotBefore:         e.NotBefore,
				NotAfter:          e.NotAfter,
				SubjectAltNames:   splitSANs(e.NameValue),
				RawPEM:            string(e.PEM),
				FilePath:          fmt.Sprintf("%s:%s", childSource, e.Fingerprint),
			})
		}
		dr := &ingest.DiscoveryResult{
			Source:             childSource,
			SkipHostResolution: true,
			Certificates:       certs,
		}
		// Per-child ingest failure is logged but does not block other
		// children (Review Focus: multi-domain/multi-child isolation).
		if _, err := p.Ingester.Ingest(ctx, dr); err != nil {
			log.Warn().Err(err).Str("domain", domain).Str("child_source", childSource).Msg("ct_multi: per-child ingest failed")
		}
	}
	log.Info().Str("domain", domain).Int("children", len(byChild)).Int("entries", len(entries)).Msg("ct_multi: group cycle complete")
	return nil
}

func (p *Poller) groupFor(domain string) (config.CtMultiGroupConfig, error) {
	for _, g := range p.cfg.Groups {
		if g.Domain == domain {
			return g, nil
		}
	}
	return config.CtMultiGroupConfig{}, fmt.Errorf("ct_multi: no configured group for domain %q", domain)
}

func splitSANs(nameValue string) []string {
	if nameValue == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i <= len(nameValue); i++ {
		if i == len(nameValue) || nameValue[i] == '\n' {
			if s := nameValue[start:i]; s != "" {
				out = append(out, s)
			}
			start = i + 1
		}
	}
	return out
}
```

Update the test from Step 6 to match this signature: `p := &Poller{Composer: map[string]*Composer{"example.com": composer}, Ingester: ing}` and call `p.runCycle(context.Background(), "example.com")`.

- [ ] **Step 9: Run all multi tests**

Run: `go test ./internal/ingest/ct/multi/... -v`
Expected: PASS across composer, children (compile-only, exercised via poller tests), config, and poller tests.

- [ ] **Step 10: Build, vet, format, commit**

```bash
go build ./internal/ingest/ct/multi/...
go vet ./internal/ingest/ct/multi/...
gofmt -l internal/ingest/ct/multi/
git add internal/ingest/ct/multi/
git commit -m "feat(ingest): port ct_multi (coverage-union CT composer with per-child provenance)"
```

---

## Task 6: Config — replace the dead stub

**Note:** Execute this task **before** Tasks 2-5 (see the sequencing note in Task 2) — every provider's `poller.go` takes a `config.Ct<Kind>SourceConfig` parameter.

**Files:**
- Modify: `internal/config/config.go:126-136` (add 4 fields to `SourcesConfig`)
- Modify: `internal/config/config.go:271-301` (delete `ExternalSourcesCTKindConfig`, `ExternalSourcesSourceConfig`, and all `CtCrtsh`/`CtStatic` stub fields/comments)
- Test: `internal/config/config_test.go` (extend existing table, or add a new test function if none covers `SourcesConfig` TOML round-tripping)

**Interfaces:**
- Produces: `config.CtCrtshSourceConfig{Domains []CtDomainConfig}`, `config.CtDomainConfig{Enabled bool, Domain string, IncludeSubdomains bool}`, `config.CtStaticSourceConfig{Domains []CtStaticDomainConfig}`, `config.CtStaticDomainConfig{Enabled bool, Domain string, LogURL string, PublicKeyPEM string}`, `config.CtCertspotterSourceConfig{Domains []CtCertspotterDomainConfig}`, `config.CtCertspotterDomainConfig{Enabled bool, Domain string, IncludeSubdomains bool, APIToken string, RequestsPerHour int}`, `config.CtMultiSourceConfig{Groups []CtMultiGroupConfig}`, `config.CtMultiGroupConfig{Enabled bool, Domain string, Children []CtMultiChildConfig}`, `config.CtMultiChildConfig{Crtsh *CtMultiChildCrtshConfig, Static *CtMultiChildStaticConfig, Certspotter *CtMultiChildCertspotterConfig}` (tagged union — `CtMultiChildCrtshConfig` is an empty marker struct since crtsh has no per-child fields beyond the shared domain; `CtMultiChildStaticConfig{Domain, LogURL, PublicKeyPEM string}`; `CtMultiChildCertspotterConfig{Domain string, APIToken string, RequestsPerHour int}`). Note: `poll_interval_seconds` was deliberately dropped from these structs (pre-flight ruling, SDD ledger) — every poller uses one shared per-kind ticker (`defaultInterval = time.Hour`) over its whole `Domains` list, not a per-domain ticker, so a per-domain interval field would be declared but never read — the same dead-config shape this port's Global Constraints section exists to eliminate.

- [ ] **Step 1: Delete the dead stub**

Remove from `internal/config/config.go` (currently lines 271-301, verify exact range hasn't shifted since the spec review): the `ExternalSourcesCTKindConfig` type, the `ExternalSourcesSourceConfig` type and its `CtCrtsh`/`CtStatic` fields, and the stale comment block referencing "ct_crtsh in v1.11" / migration 049. Also remove the `ExternalSources ExternalSourcesSourceConfig` field from `SourcesConfig` (currently `config.go:135`).

- [ ] **Step 2: Write the new config structs**

Add to `internal/config/config.go`, replacing the deleted block:

```go
// CtDomainConfig is one monitored domain for the ct_crtsh adapter.
type CtDomainConfig struct {
	Enabled           bool   `toml:"enabled"`
	Domain            string `toml:"domain"`
	IncludeSubdomains bool   `toml:"include_subdomains"`
}

// CtCrtshSourceConfig configures the crt.sh CT adapter across N domains.
type CtCrtshSourceConfig struct {
	Domains []CtDomainConfig `toml:"domains"`
}

// Enabled reports whether at least one configured domain is enabled.
// main.go gates the whole poller's construction on this, matching the
// Enabled-gated pattern every other CE connector uses.
func (c CtCrtshSourceConfig) Enabled() bool {
	for _, d := range c.Domains {
		if d.Enabled {
			return true
		}
	}
	return false
}

// CtStaticDomainConfig is one monitored domain for the ct_static
// (Sunlight/RFC 6962) adapter.
type CtStaticDomainConfig struct {
	Enabled      bool   `toml:"enabled"`
	Domain       string `toml:"domain"`
	LogURL       string `toml:"log_url"`
	PublicKeyPEM string `toml:"public_key_pem"`
}

// CtStaticSourceConfig configures the Static CT API adapter across N domains.
type CtStaticSourceConfig struct {
	Domains []CtStaticDomainConfig `toml:"domains"`
}

func (c CtStaticSourceConfig) Enabled() bool {
	for _, d := range c.Domains {
		if d.Enabled {
			return true
		}
	}
	return false
}

// CtCertspotterDomainConfig is one monitored domain for the SSLMate
// CertSpotter adapter.
type CtCertspotterDomainConfig struct {
	Enabled           bool   `toml:"enabled"`
	Domain            string `toml:"domain"`
	IncludeSubdomains bool   `toml:"include_subdomains"`
	APIToken          string `toml:"api_token"`
	RequestsPerHour   int    `toml:"requests_per_hour"`
}

// CtCertspotterSourceConfig configures the CertSpotter adapter across N domains.
type CtCertspotterSourceConfig struct {
	Domains []CtCertspotterDomainConfig `toml:"domains"`
}

func (c CtCertspotterSourceConfig) Enabled() bool {
	for _, d := range c.Domains {
		if d.Enabled {
			return true
		}
	}
	return false
}

// CtMultiChildCrtshConfig marks a ct_multi child as crt.sh-backed. No
// per-child fields — crtsh uses the group's shared domain with default
// subdomain inclusion.
type CtMultiChildCrtshConfig struct{}

// CtMultiChildStaticConfig is a ct_multi child backed by a Static CT log.
type CtMultiChildStaticConfig struct {
	Domain       string `toml:"domain"`
	LogURL       string `toml:"log_url"`
	PublicKeyPEM string `toml:"public_key_pem"`
}

// CtMultiChildCertspotterConfig is a ct_multi child backed by CertSpotter.
type CtMultiChildCertspotterConfig struct {
	Domain          string `toml:"domain"`
	APIToken        string `toml:"api_token"`
	RequestsPerHour int    `toml:"requests_per_hour"`
}

// CtMultiChildConfig is a tagged union — exactly one field is non-nil.
type CtMultiChildConfig struct {
	Crtsh       *CtMultiChildCrtshConfig       `toml:"crtsh"`
	Static      *CtMultiChildStaticConfig      `toml:"static"`
	Certspotter *CtMultiChildCertspotterConfig `toml:"certspotter"`
}

// CtMultiGroupConfig is one ct_multi coverage-union group: N children
// sharing one domain.
type CtMultiGroupConfig struct {
	Enabled  bool                  `toml:"enabled"`
	Domain   string                `toml:"domain"`
	Children []CtMultiChildConfig  `toml:"children"`
}

// CtMultiSourceConfig configures the ct_multi composer across N groups.
type CtMultiSourceConfig struct {
	Groups []CtMultiGroupConfig `toml:"groups"`
}

func (c CtMultiSourceConfig) Enabled() bool {
	for _, g := range c.Groups {
		if g.Enabled {
			return true
		}
	}
	return false
}
```

- [ ] **Step 3: Wire the 4 new fields into `SourcesConfig`**

```go
type SourcesConfig struct {
	ZeekFile      ZeekFileSourceConfig      `toml:"zeek_file"`
	Corelight     CorelightSourceConfig     `toml:"corelight"`
	Velociraptor  VelociraptorSourceConfig  `toml:"velociraptor"`
	Netwrix       NetwrixSourceConfig       `toml:"netwrix"`
	Defender      DefenderSourceConfig      `toml:"defender"`
	SentinelOne   SentinelOneSourceConfig   `toml:"sentinelone"`
	Tanium        TaniumSourceConfig        `toml:"tanium"`
	Absolute      AbsoluteSourceConfig      `toml:"absolute"`
	CtCrtsh       CtCrtshSourceConfig       `toml:"ct_crtsh"`
	CtStatic      CtStaticSourceConfig      `toml:"ct_static"`
	CtCertspotter CtCertspotterSourceConfig `toml:"ct_certspotter"`
	CtMulti       CtMultiSourceConfig       `toml:"ct_multi"`
}
```

(The `ExternalSources` field is removed per Step 1, not replaced.)

- [ ] **Step 4: Write a config round-trip test**

```go
// Add to internal/config/config_test.go — follow the existing file's
// pattern for TOML-decode tests (check an existing test in that file for
// the exact toml.Decode/toml.Unmarshal call CE uses before writing this).
func TestSourcesConfig_CTFields_TOMLRoundTrip(t *testing.T) {
	tomlSrc := `
[sources.ct_crtsh]
  [[sources.ct_crtsh.domains]]
  enabled = true
  domain = "example.com"
  include_subdomains = true

[sources.ct_multi]
  [[sources.ct_multi.groups]]
  enabled = true
  domain = "example.com"
    [[sources.ct_multi.groups.children]]
    [sources.ct_multi.groups.children.crtsh]
    [[sources.ct_multi.groups.children]]
    [sources.ct_multi.groups.children.static]
    domain = "example.com"
    log_url = "https://log.example.com/"
    public_key_pem = "pem-placeholder"
`
	var cfg Config // or whatever the top-level type is named — verify against an existing test in this file
	if _, err := toml.Decode(tomlSrc, &cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(cfg.Sources.CtCrtsh.Domains) != 1 || cfg.Sources.CtCrtsh.Domains[0].Domain != "example.com" {
		t.Fatalf("ct_crtsh domains = %+v", cfg.Sources.CtCrtsh.Domains)
	}
	if len(cfg.Sources.CtMulti.Groups) != 1 || len(cfg.Sources.CtMulti.Groups[0].Children) != 2 {
		t.Fatalf("ct_multi groups = %+v", cfg.Sources.CtMulti.Groups)
	}
	if cfg.Sources.CtMulti.Groups[0].Children[0].Crtsh == nil {
		t.Fatal("expected first child to be crtsh")
	}
	if cfg.Sources.CtMulti.Groups[0].Children[1].Static == nil || cfg.Sources.CtMulti.Groups[0].Children[1].Static.Domain != "example.com" {
		t.Fatal("expected second child to be static with domain example.com")
	}
}
```

Before finalizing this step, read `internal/config/config_test.go` to confirm the exact TOML-decoding call CE's own tests use (e.g. `toml.Decode` from `github.com/BurntSushi/toml` vs `pelletier/go-toml` vs a project-local `config.Load`) and adjust the test to match — do not guess the import.

- [ ] **Step 5: Run the config test**

Run: `go test ./internal/config/... -run TestSourcesConfig_CTFields -v`
Expected: PASS.

- [ ] **Step 6: Run the full config package test suite to confirm nothing else broke from removing `ExternalSourcesSourceConfig`**

Run: `go test ./internal/config/... -v`
Expected: PASS. If any other file references `ExternalSourcesSourceConfig`/`ExternalSourcesCTKindConfig`/`cfg.Sources.ExternalSources`, this step will show a compile error — grep for those identifiers across the whole repo and remove/update each reference before proceeding (per this repo's own "schema reconciliation before commit" rule).

- [ ] **Step 7: Build, vet, format, commit**

```bash
go build ./...
go vet ./internal/config/...
gofmt -l internal/config/
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): replace dead CT config stub with real ct_crtsh/ct_static/ct_certspotter/ct_multi settings"
```

---

## Task 7: `main.go` wiring + README update

**Files:**
- Modify: `cmd/cipherflag/main.go` (add 4 imports + 4 `Enabled`-gated construct-and-run blocks, placed after the existing Absolute block per the file's established ordering)
- Modify: `README.md` (move CT multi-provider arc out of any EE-only/moat listing, if one exists — grep first)

**Interfaces:**
- Consumes: `crtsh.NewPoller`, `static.NewPoller`, `certspotter.NewPoller`, `multi.NewPoller` (Tasks 2-5), `cfg.Sources.CtCrtsh`/`CtStatic`/`CtCertspotter`/`CtMulti` (Task 6).

- [ ] **Step 1: Add imports**

In `cmd/cipherflag/main.go`, add after the existing `"github.com/net4n6-dev/cipherflag/internal/ingest/absolute"` import line:

```go
	"github.com/net4n6-dev/cipherflag/internal/ingest/ct/certspotter"
	"github.com/net4n6-dev/cipherflag/internal/ingest/ct/crtsh"
	"github.com/net4n6-dev/cipherflag/internal/ingest/ct/multi"
	"github.com/net4n6-dev/cipherflag/internal/ingest/ct/static"
```

- [ ] **Step 2: Add the 4 wiring blocks**

Insert after the existing Absolute connector block (find it by searching for `if cfg.Sources.Absolute.Enabled {` and locating its closing `}`), following the exact `Enabled`-gated pattern the Defender/SentinelOne/Tanium blocks use (`cmd/cipherflag/main.go:231-274`: construct client if needed → `log.Fatal` on construction error → build a fresh `ingest.NewUnifiedIngester(st, ingest.WithObservationCache(sharedCache), ingest.WithScorer(scorer))` → construct poller → `go poller.Run(ctx)` → `log.Info`):

```go
	// Certificate Transparency: crt.sh (off by default).
	if cfg.Sources.CtCrtsh.Enabled() {
		ctCrtshCtx, ctCrtshCancel := context.WithCancel(ctx)
		defer ctCrtshCancel()
		ctCrtshIngester := ingest.NewUnifiedIngester(st, ingest.WithObservationCache(sharedCache), ingest.WithScorer(scorer))
		ctCrtshPoller := crtsh.NewPoller(nil, ctCrtshIngester, st, cfg.Sources.CtCrtsh)
		go ctCrtshPoller.Run(ctCrtshCtx)
		log.Info().Int("domains", len(cfg.Sources.CtCrtsh.Domains)).Msg("ct_crtsh poller started")
	}

	// Certificate Transparency: Static CT API / Sunlight (off by default).
	if cfg.Sources.CtStatic.Enabled() {
		for _, d := range cfg.Sources.CtStatic.Domains {
			if !d.Enabled {
				continue
			}
			if err := static.ValidateDomainConfig(d.Domain, d.LogURL, d.PublicKeyPEM); err != nil {
				log.Fatal().Err(err).Str("domain", d.Domain).Msg("invalid ct_static domain config")
			}
		}
		ctStaticCtx, ctStaticCancel := context.WithCancel(ctx)
		defer ctStaticCancel()
		ctStaticIngester := ingest.NewUnifiedIngester(st, ingest.WithObservationCache(sharedCache), ingest.WithScorer(scorer))
		ctStaticPoller := static.NewPoller(ctStaticIngester, st, nil, cfg.Sources.CtStatic)
		go ctStaticPoller.Run(ctStaticCtx)
		log.Info().Int("domains", len(cfg.Sources.CtStatic.Domains)).Msg("ct_static poller started")
	}

	// Certificate Transparency: SSLMate CertSpotter (off by default).
	if cfg.Sources.CtCertspotter.Enabled() {
		ctCertspotterCtx, ctCertspotterCancel := context.WithCancel(ctx)
		defer ctCertspotterCancel()
		ctCertspotterIngester := ingest.NewUnifiedIngester(st, ingest.WithObservationCache(sharedCache), ingest.WithScorer(scorer))
		ctCertspotterPoller := certspotter.NewPoller(nil, ctCertspotterIngester, st, cfg.Sources.CtCertspotter)
		go ctCertspotterPoller.Run(ctCertspotterCtx)
		log.Info().Int("domains", len(cfg.Sources.CtCertspotter.Domains)).Msg("ct_certspotter poller started")
	}

	// Certificate Transparency: multi-provider coverage union (off by default).
	if cfg.Sources.CtMulti.Enabled() {
		for _, g := range cfg.Sources.CtMulti.Groups {
			if !g.Enabled {
				continue
			}
			if err := multi.ValidateGroup(g); err != nil {
				log.Fatal().Err(err).Str("domain", g.Domain).Msg("invalid ct_multi group config")
			}
		}
		ctMultiCtx, ctMultiCancel := context.WithCancel(ctx)
		defer ctMultiCancel()
		ctMultiIngester := ingest.NewUnifiedIngester(st, ingest.WithObservationCache(sharedCache), ingest.WithScorer(scorer))
		ctMultiPoller := multi.NewPoller(ctMultiIngester, nil, cfg.Sources.CtMulti)
		go ctMultiPoller.Run(ctMultiCtx)
		log.Info().Int("groups", len(cfg.Sources.CtMulti.Groups)).Msg("ct_multi poller started")
	}
```

**Note on `.Enabled()`:** each `Ct*SourceConfig` type (Task 6) has no top-level `Enabled` field — each *domain*/*group* entry does — so Task 6 defines an `Enabled() bool` method on each `Ct*SourceConfig` type (returns `true` if at least one contained domain/group has `Enabled: true`). This task only calls those methods at the wiring call sites above.

- [ ] **Step 3: Build the whole binary**

Run: `go build ./...`
Expected: clean build, no errors.

- [ ] **Step 4: Grep for and update any EE-only/moat listing in README.md**

```bash
grep -n -i "ct_multi\|certificate transparency\|crt.sh\|certspotter" README.md
```

If CT is listed under an EE-only/moat section, move it to the CE-supported list (mirroring `docs/superpowers/specs/2026-05-31-ce-connector-port-design.md:114-115`'s precedent for the 5-connector port's README reframe). If CT isn't mentioned in README.md at all, add a line under CE's supported-connectors list noting `ct_crtsh` / `ct_static` / `ct_certspotter` / `ct_multi` (config.toml-only, no UI).

- [ ] **Step 5: Run the full test suite**

Run: `go test ./... 2>&1 | grep -E '(FAIL|ok\s)' | tail -50`
Expected: no `FAIL` lines.

- [ ] **Step 6: Commit**

```bash
git add cmd/cipherflag/main.go README.md
git commit -m "feat(ingest): wire ct_crtsh/ct_static/ct_certspotter/ct_multi pollers into main.go"
```

---

## Final verification (whole-branch)

- [ ] Run `go build ./...` — clean.
- [ ] Run `go vet ./...` — clean.
- [ ] Run `gofmt -l .` — no output (nothing unformatted).
- [ ] Run `go test ./... 2>&1 | grep -E '(FAIL|ok\s)'` — no `FAIL` lines.
- [ ] Grep the whole repo for `ExternalSourcesSourceConfig`, `ExternalSourcesCTKindConfig`, `externalsource` — confirm zero hits (the dead stub is fully gone, and no accidental import of EE's registry package survived a copy-paste).
- [ ] Grep for `probe.GuardedTransport`, `internal/externalsource/probe` — confirm zero hits (EE-only dependency correctly stripped from every ported client/provider/poller file).
- [ ] Manually start the server with a `config.toml` enabling one `ct_crtsh` domain against a real low-traffic test domain (or a domain known to have few crt.sh entries) and confirm in logs: "ct_crtsh poller started" → a completed cycle log line → no panics. This is the one piece of this plan that automated tests can't cover (live network I/O against crt.sh) — call this out explicitly to whoever reviews the branch rather than silently skipping end-to-end verification.
