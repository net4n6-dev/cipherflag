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

package store

import (
	"context"
	"fmt"
	"time"
)

// ApplicationSummary is the listing-card view of one application.
// Derived from: distinct unnest(application_tags) across asset tables,
// LEFT JOIN asset_health_reports for per-asset grade/score, aggregated
// in Go to produce weakest-link grade + mean score + finding count.
//
// Posture semantics:
//   - CompositeGrade = worst grade among assets that have a health
//     report. Ungraded assets (hosts, repos typically) are excluded
//     from grading but still counted in TotalAssets.
//   - AverageScore = mean score across assets with a health report.
//   - FindingCount = sum of findings across ALL tagged assets.
//   - CompositeGrade == "" when no tagged asset has a report.
type ApplicationSummary struct {
	Tag            string         `json:"tag"`
	AssetCounts    map[string]int `json:"asset_counts"`
	TotalAssets    int            `json:"total_assets"`
	CompositeGrade string         `json:"composite_grade"`
	AverageScore   int            `json:"average_score"`
	FindingCount   int            `json:"finding_count"`
	ScoredAssets   int            `json:"scored_assets"`
	// Deadline rollups: number of tagged findings whose ScopeDeadline is
	// past (overdue) or within the next 30 days. Powers AQ-AP-02.
	FindingsOverdue int `json:"findings_overdue"`
	FindingsDue30d  int `json:"findings_due_30d"`
}

// ApplicationAssetRef identifies one asset belonging to an application.
// Label is a human-readable identifier (CN / file_path / repo_slug / etc.).
// Grade, Score, FindingCount come from asset_health_reports (empty / 0
// when no report exists for this asset).
type ApplicationAssetRef struct {
	AssetType       string `json:"asset_type"`
	AssetID         string `json:"asset_id"`
	Label           string `json:"label"`
	Grade           string `json:"grade"`
	Score           int    `json:"score"`
	FindingCount    int    `json:"finding_count"`
	FindingsOverdue int    `json:"findings_overdue"`
	FindingsDue30d  int    `json:"findings_due_30d"`
}

// ApplicationDetail is the full-detail view used by GET /applications/{tag}.
// Assets are sorted by grade-descending (worst first) then label so the
// Neighborhood section of the detail page immediately surfaces the
// worst-contributing components (AQ-AP-03).
type ApplicationDetail struct {
	Tag             string                `json:"tag"`
	AssetCounts     map[string]int        `json:"asset_counts"`
	TotalAssets     int                   `json:"total_assets"`
	CompositeGrade  string                `json:"composite_grade"`
	AverageScore    int                   `json:"average_score"`
	FindingCount    int                   `json:"finding_count"`
	ScoredAssets    int                   `json:"scored_assets"`
	FindingsOverdue int                   `json:"findings_overdue"`
	FindingsDue30d  int                   `json:"findings_due_30d"`
	Assets          []ApplicationAssetRef `json:"assets"`

	// Score delta decomposition (AQ-CE-03), kept for API shape. Populated only
	// where the EE-only application posture snapshot runner exists; in CE both
	// stay zero-valued. ScoreDelta7d would be the current AverageScore minus
	// the oldest snapshot's in the last 7 days; ReferenceSnapshotAt that
	// snapshot's captured_at.
	ScoreDelta7d         int                 `json:"score_delta_7d"`
	ReferenceSnapshotAt  time.Time           `json:"reference_snapshot_at"`
	TopContributingRules []RuleContribution  `json:"top_contributing_rules"`
}

// RuleContribution is one row in the "what's dragging my score down"
// table. Aggregated from all findings on the application's tagged
// assets; sorted by TotalDeduction desc so operators see the biggest
// score impacts first. Zero-point findings (rules with Deduction=0,
// e.g. KEY-005 positive-indicator) are excluded.
type RuleContribution struct {
	RuleID         string `json:"rule_id"`
	Title          string `json:"title"`
	Severity       string `json:"severity"`
	Category       string `json:"category"`
	InstanceCount  int    `json:"instance_count"`
	TotalDeduction int    `json:"total_deduction"`
}

// gradeOrdinal maps a letter grade to a comparable int where higher =
// worse. Unrecognised or empty grades return 0 (skip-in-rollup sentinel).
// Used for weakest-link composite computation and worst-first sorting.
func gradeOrdinal(g string) int {
	switch g {
	case "A+", "A":
		return 1
	case "B":
		return 2
	case "C":
		return 3
	case "D":
		return 4
	case "F":
		return 5
	}
	return 0
}

// composeGrade picks the worst grade from a slice; returns "" if none.
func composeGrade(grades []string) string {
	worst, worstOrd := "", 0
	for _, g := range grades {
		ord := gradeOrdinal(g)
		if ord > worstOrd {
			worstOrd, worst = ord, g
		}
	}
	return worst
}

// ListApplications returns one ApplicationSummary per distinct tag across
// the seven tag-carrying asset tables. Each summary includes the weakest-
// link composite grade, mean score, and finding count aggregated from
// asset_health_reports via LEFT JOIN (so ungraded asset types like hosts
// and repos still contribute to asset counts but not to grading).
//
// The query returns one row per (tag, asset_type, asset) rather than
// pre-aggregating — Go-side aggregation keeps the composite-grade logic
// in one place and lets gradeOrdinal() be unit-tested independently.
//
// If `before` is non-nil, the caller wants AQ-AP-02 filtering — only
// applications with ≥1 finding whose scope_deadline ≤ `before` are
// returned. The overdue + due_30d counts in every row reflect the
// unfiltered state (so operators still see the full posture footprint).
func (s *PostgresStore) ListApplications(ctx context.Context, before *time.Time) ([]ApplicationSummary, error) {
	rows, err := s.pool.Query(ctx, `
		WITH tagged AS (
			SELECT unnest(c.application_tags) AS tag, 'certificate' AS asset_type, c.fingerprint_sha256 AS asset_id
			FROM certificates c WHERE array_length(c.application_tags, 1) > 0
			UNION ALL
			SELECT unnest(k.application_tags), 'ssh_key', k.id::text
			FROM ssh_keys k WHERE array_length(k.application_tags, 1) > 0
			UNION ALL
			SELECT unnest(l.application_tags), 'crypto_library', l.id::text
			FROM crypto_libraries l WHERE array_length(l.application_tags, 1) > 0
			UNION ALL
			SELECT unnest(cfg.application_tags), 'crypto_config', cfg.id::text
			FROM crypto_configs cfg WHERE array_length(cfg.application_tags, 1) > 0
			-- CE-flavor: no protocol_endpoint leg (EE-only, Layer 4.1c).
			UNION ALL
			SELECT unnest(h.application_tags), 'host', h.id::text
			FROM hosts h WHERE array_length(h.application_tags, 1) > 0
			UNION ALL
			SELECT unnest(r.application_tags), 'repository', r.id::text
			FROM repositories r WHERE array_length(r.application_tags, 1) > 0
		)
		SELECT t.tag, t.asset_type,
		       COALESCE(hr.grade, '') AS grade,
		       COALESCE(hr.score, 0) AS score,
		       COALESCE(
		           CASE WHEN jsonb_typeof(hr.findings) = 'array'
		                THEN jsonb_array_length(hr.findings)
		                ELSE 0
		           END, 0) AS finding_count,
		       -- Overdue: deadline < now. Guard against non-array findings
		       -- shapes (Layer-6 repo scanner writes a richer JSONB object
		       -- via AssetHealthReport.RawFindings — see hotfix 8775044).
		       COALESCE(
		           CASE WHEN jsonb_typeof(hr.findings) = 'array' THEN
		               (SELECT COUNT(*) FROM jsonb_array_elements(hr.findings) f
		                WHERE f ? 'scope_deadline'
		                  AND (f->>'scope_deadline')::timestamptz < NOW())
		           ELSE 0 END, 0) AS overdue_count,
		       -- Due in next 30 days (not yet overdue).
		       COALESCE(
		           CASE WHEN jsonb_typeof(hr.findings) = 'array' THEN
		               (SELECT COUNT(*) FROM jsonb_array_elements(hr.findings) f
		                WHERE f ? 'scope_deadline'
		                  AND (f->>'scope_deadline')::timestamptz >= NOW()
		                  AND (f->>'scope_deadline')::timestamptz < NOW() + INTERVAL '30 days')
		           ELSE 0 END, 0) AS due_30d_count
		FROM tagged t
		LEFT JOIN asset_health_reports hr
		  ON hr.asset_type = t.asset_type AND hr.asset_id = t.asset_id
	`)
	if err != nil {
		return nil, fmt.Errorf("list applications: %w", err)
	}
	defer rows.Close()

	// Accumulator: per-tag intermediate state (needs grade slice for
	// weakest-link composition; sum + count for mean score).
	type accum struct {
		sum           ApplicationSummary
		grades        []string
		scoreSum      int
		scoredCount   int
	}
	byTag := map[string]*accum{}

	for rows.Next() {
		var tag, assetType, grade string
		var score, findingCount, overdueCount, due30dCount int
		if err := rows.Scan(&tag, &assetType, &grade, &score, &findingCount, &overdueCount, &due30dCount); err != nil {
			return nil, err
		}
		a, ok := byTag[tag]
		if !ok {
			a = &accum{sum: ApplicationSummary{Tag: tag, AssetCounts: map[string]int{}}}
			byTag[tag] = a
		}
		a.sum.AssetCounts[assetType]++
		a.sum.TotalAssets++
		a.sum.FindingCount += findingCount
		a.sum.FindingsOverdue += overdueCount
		a.sum.FindingsDue30d += due30dCount
		if grade != "" && gradeOrdinal(grade) > 0 {
			a.grades = append(a.grades, grade)
			a.scoreSum += score
			a.scoredCount++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]ApplicationSummary, 0, len(byTag))
	for _, a := range byTag {
		a.sum.CompositeGrade = composeGrade(a.grades)
		a.sum.ScoredAssets = a.scoredCount
		if a.scoredCount > 0 {
			a.sum.AverageScore = a.scoreSum / a.scoredCount
		}
		out = append(out, a.sum)
	}
	// total_assets DESC, tag ASC.
	sortApplicationsByTotalDesc(out)

	// When a cutoff is supplied we need to run one focused subquery to
	// identify which applications have ≥1 finding with deadline ≤ cutoff.
	// We can't reuse the main query's counts because those are bucketed
	// (overdue / due_30d), and `before` is arbitrary. Go back to the DB
	// for a single-purpose tag filter.
	if before != nil {
		keep, err := s.tagsWithDeadlineBefore(ctx, *before)
		if err != nil {
			return nil, err
		}
		filtered := out[:0]
		for _, app := range out {
			if keep[app.Tag] {
				filtered = append(filtered, app)
			}
		}
		out = filtered
	}

	return out, nil
}

// tagsWithDeadlineBefore returns the set of application_tags that have at
// least one finding with scope_deadline ≤ cutoff across the tag-carrying
// asset tables. Keys are tag names; value is always true.
func (s *PostgresStore) tagsWithDeadlineBefore(ctx context.Context, cutoff time.Time) (map[string]bool, error) {
	rows, err := s.pool.Query(ctx, `
		WITH tagged AS (
			SELECT unnest(c.application_tags) AS tag, 'certificate' AS asset_type, c.fingerprint_sha256 AS asset_id
			FROM certificates c WHERE array_length(c.application_tags, 1) > 0
			UNION ALL
			SELECT unnest(k.application_tags), 'ssh_key', k.id::text
			FROM ssh_keys k WHERE array_length(k.application_tags, 1) > 0
			UNION ALL
			SELECT unnest(l.application_tags), 'crypto_library', l.id::text
			FROM crypto_libraries l WHERE array_length(l.application_tags, 1) > 0
			UNION ALL
			SELECT unnest(cfg.application_tags), 'crypto_config', cfg.id::text
			FROM crypto_configs cfg WHERE array_length(cfg.application_tags, 1) > 0
			-- CE-flavor: no protocol_endpoint leg (EE-only, Layer 4.1c).
			UNION ALL
			SELECT unnest(h.application_tags), 'host', h.id::text
			FROM hosts h WHERE array_length(h.application_tags, 1) > 0
			UNION ALL
			SELECT unnest(r.application_tags), 'repository', r.id::text
			FROM repositories r WHERE array_length(r.application_tags, 1) > 0
		)
		SELECT DISTINCT t.tag
		FROM tagged t
		JOIN asset_health_reports hr
		  ON hr.asset_type = t.asset_type AND hr.asset_id = t.asset_id
		WHERE jsonb_typeof(hr.findings) = 'array'
		  AND EXISTS (
		      SELECT 1 FROM jsonb_array_elements(hr.findings) f
		      WHERE f ? 'scope_deadline'
		        AND (f->>'scope_deadline')::timestamptz <= $1
		  )
	`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("tags with deadline before: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var tag string
		if err := rows.Scan(&tag); err != nil {
			return nil, err
		}
		out[tag] = true
	}
	return out, rows.Err()
}

// GetApplication returns every asset tagged with `tag` plus per-asset
// posture (grade, score, finding_count from asset_health_reports) and
// application-level rollups (weakest-link composite grade, mean score,
// total findings). Assets are sorted worst-first by grade ordinal so the
// detail page surfaces the biggest contributors to posture degradation
// (AQ-AP-03).
//
// Labels mirror the detail-page identifier conventions:
//
//	certificate       → subject.common_name (fallback to fingerprint)
//	ssh_key           → file_path
//	crypto_library    → library_name + ' ' + version
//	crypto_config     → file_path
//	host              → canonical_hostname
//	repository        → url
func (s *PostgresStore) GetApplication(ctx context.Context, tag string) (*ApplicationDetail, error) {
	if tag == "" {
		return nil, fmt.Errorf("get application: empty tag")
	}

	rows, err := s.pool.Query(ctx, `
		WITH tagged AS (
			SELECT 'certificate' AS asset_type,
			       fingerprint_sha256 AS asset_id,
			       COALESCE(NULLIF(subject_cn, ''), fingerprint_sha256) AS label
			FROM certificates WHERE $1 = ANY(application_tags)
			UNION ALL
			SELECT 'ssh_key', id::text, COALESCE(NULLIF(file_path, ''), id::text) FROM ssh_keys        WHERE $1 = ANY(application_tags)
			UNION ALL
			SELECT 'crypto_library', id::text, library_name || ' ' || version FROM crypto_libraries    WHERE $1 = ANY(application_tags)
			UNION ALL
			SELECT 'crypto_config', id::text, COALESCE(NULLIF(file_path, ''), id::text) FROM crypto_configs WHERE $1 = ANY(application_tags)
			-- CE-flavor: no protocol_endpoint leg (EE-only, Layer 4.1c).
			UNION ALL
			SELECT 'host', id::text, COALESCE(NULLIF(canonical_hostname, ''), id::text) FROM hosts     WHERE $1 = ANY(application_tags)
			UNION ALL
			SELECT 'repository', id::text, COALESCE(NULLIF(url, ''), id::text) FROM repositories        WHERE $1 = ANY(application_tags)
		)
		SELECT t.asset_type, t.asset_id, t.label,
		       COALESCE(hr.grade, '') AS grade,
		       COALESCE(hr.score, 0) AS score,
		       COALESCE(
		           CASE WHEN jsonb_typeof(hr.findings) = 'array'
		                THEN jsonb_array_length(hr.findings)
		                ELSE 0
		           END, 0) AS finding_count,
		       COALESCE(
		           CASE WHEN jsonb_typeof(hr.findings) = 'array' THEN
		               (SELECT COUNT(*) FROM jsonb_array_elements(hr.findings) f
		                WHERE f ? 'scope_deadline'
		                  AND (f->>'scope_deadline')::timestamptz < NOW())
		           ELSE 0 END, 0) AS overdue_count,
		       COALESCE(
		           CASE WHEN jsonb_typeof(hr.findings) = 'array' THEN
		               (SELECT COUNT(*) FROM jsonb_array_elements(hr.findings) f
		                WHERE f ? 'scope_deadline'
		                  AND (f->>'scope_deadline')::timestamptz >= NOW()
		                  AND (f->>'scope_deadline')::timestamptz < NOW() + INTERVAL '30 days')
		           ELSE 0 END, 0) AS due_30d_count
		FROM tagged t
		LEFT JOIN asset_health_reports hr
		  ON hr.asset_type = t.asset_type AND hr.asset_id = t.asset_id
	`, tag)
	if err != nil {
		return nil, fmt.Errorf("get application %q: %w", tag, err)
	}
	defer rows.Close()

	detail := &ApplicationDetail{
		Tag:                  tag,
		AssetCounts:          map[string]int{},
		Assets:               []ApplicationAssetRef{},
		TopContributingRules: []RuleContribution{},
	}
	grades := []string{}
	scoreSum, scoredCount := 0, 0

	for rows.Next() {
		var ref ApplicationAssetRef
		if err := rows.Scan(&ref.AssetType, &ref.AssetID, &ref.Label, &ref.Grade, &ref.Score, &ref.FindingCount, &ref.FindingsOverdue, &ref.FindingsDue30d); err != nil {
			return nil, err
		}
		detail.Assets = append(detail.Assets, ref)
		detail.AssetCounts[ref.AssetType]++
		detail.TotalAssets++
		detail.FindingCount += ref.FindingCount
		detail.FindingsOverdue += ref.FindingsOverdue
		detail.FindingsDue30d += ref.FindingsDue30d
		if ref.Grade != "" && gradeOrdinal(ref.Grade) > 0 {
			grades = append(grades, ref.Grade)
			scoreSum += ref.Score
			scoredCount++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	detail.CompositeGrade = composeGrade(grades)
	detail.ScoredAssets = scoredCount
	if scoredCount > 0 {
		detail.AverageScore = scoreSum / scoredCount
	}

	// Worst-first: higher gradeOrdinal → earlier in the list. Within the
	// same grade, sort by label ASC. Ungraded assets (ordinal 0) sink to
	// the bottom in label order.
	sortAssetsByWorstFirst(detail.Assets)

	// CE-flavor: no score-delta decomposition. It needs application posture
	// snapshots (EE-only, AQ-CE-03); CE has no snapshot table or writer, so
	// ScoreDelta7d and ReferenceSnapshotAt stay at their zero values.

	// Top-contributing rules: aggregate current findings on tagged assets
	// by rule_id. Reuses ListApplicationScopeAssets (tolerant of the
	// repo-scanner's wrapped-JSONB shape) so the whole walk is one
	// additional DB round-trip rather than a new custom query.
	if scopeRows, err := s.ListApplicationScopeAssets(ctx, tag); err == nil {
		detail.TopContributingRules = aggregateTopRules(scopeRows)
	}

	return detail, nil
}

// aggregateTopRules walks every finding on every scope row and groups
// by rule_id, summing Deduction across instances. Returns the top 10
// rules by TotalDeduction desc (or all rules if fewer than 10 distinct
// rule_ids fired). Zero-deduction rules (positive indicators like
// KEY-005) are excluded — they don't "contribute" to score loss.
func aggregateTopRules(rows []ScopeAssetRow) []RuleContribution {
	agg := map[string]*RuleContribution{}
	for _, r := range rows {
		for _, f := range r.Report.Findings {
			if f.Deduction <= 0 {
				continue
			}
			existing, ok := agg[f.RuleID]
			if !ok {
				existing = &RuleContribution{
					RuleID:   f.RuleID,
					Title:    f.Title,
					Severity: string(f.Severity),
					Category: string(f.Category),
				}
				agg[f.RuleID] = existing
			}
			existing.InstanceCount++
			existing.TotalDeduction += f.Deduction
		}
	}
	out := make([]RuleContribution, 0, len(agg))
	for _, c := range agg {
		out = append(out, *c)
	}
	sortRulesByImpactDesc(out)
	if len(out) > 10 {
		out = out[:10]
	}
	return out
}

func sortRulesByImpactDesc(rules []RuleContribution) {
	for i := 1; i < len(rules); i++ {
		cur := rules[i]
		j := i - 1
		for j >= 0 && lessRule(cur, rules[j]) {
			rules[j+1] = rules[j]
			j--
		}
		rules[j+1] = cur
	}
}
func lessRule(a, b RuleContribution) bool {
	if a.TotalDeduction != b.TotalDeduction {
		return a.TotalDeduction > b.TotalDeduction
	}
	if a.InstanceCount != b.InstanceCount {
		return a.InstanceCount > b.InstanceCount
	}
	return a.RuleID < b.RuleID
}

// sortAssetsByWorstFirst puts worse-grade assets first so the detail
// page's Neighborhood section surfaces the biggest contributors to
// posture degradation (AQ-AP-03). Stable; secondary key is label ASC.
func sortAssetsByWorstFirst(assets []ApplicationAssetRef) {
	for i := 1; i < len(assets); i++ {
		cur := assets[i]
		j := i - 1
		for j >= 0 && lessAsset(cur, assets[j]) {
			assets[j+1] = assets[j]
			j--
		}
		assets[j+1] = cur
	}
}
func lessAsset(a, b ApplicationAssetRef) bool {
	oa, ob := gradeOrdinal(a.Grade), gradeOrdinal(b.Grade)
	if oa != ob {
		return oa > ob // higher ordinal = worse = comes first
	}
	return a.Label < b.Label
}

// SeedApplicationTagsFromPatterns is a seed-only helper that assigns
// application_tags to existing assets using simple pattern rules:
//
//   certificates       → slug of subject_org (when present)
//   hosts              → slug of the 2nd-to-last hostname component, when
//                        canonical_hostname has a recognisable domain
//                        (e.g. "portal.acmecorp.internal" → "acmecorp")
//   ssh_keys / libs / configs → inherit their host's application_tags
//
// Idempotent within a single seed run: duplicates within an array are
// collapsed via SELECT DISTINCT. Safe to re-run; each pass appends-and-
// dedups rather than replacing.
//
// Intended for demo data. Production tagging is operator-driven.
func (s *PostgresStore) SeedApplicationTagsFromPatterns(ctx context.Context) error {
	// Pattern 1 — certificates: slug of subject_org.
	if _, err := s.pool.Exec(ctx, `
		UPDATE certificates
		SET application_tags = (
			SELECT ARRAY(SELECT DISTINCT elem FROM unnest(application_tags || ARRAY[
				lower(trim(BOTH '-' FROM regexp_replace(trim(subject_org), '[^a-zA-Z0-9]+', '-', 'g')))
			]) AS elem WHERE elem <> '')
		)
		WHERE subject_org IS NOT NULL AND subject_org <> ''
	`); err != nil {
		return fmt.Errorf("tag certificates: %w", err)
	}

	// Pattern 2 — hosts: 2nd-to-last domain component from canonical_hostname.
	// "portal.acmecorp.internal" → "acmecorp"; "api.corp.example.com" → "example".
	// Uses substring(... FROM 'regex') which returns a SCALAR (the first
	// capture group); regexp_matches() would return a set and cannot sit
	// inside ARRAY[] at the point of tag construction.
	if _, err := s.pool.Exec(ctx, `
		UPDATE hosts
		SET application_tags = (
			SELECT ARRAY(SELECT DISTINCT elem FROM unnest(application_tags || ARRAY[
				lower(substring(canonical_hostname FROM '([a-zA-Z0-9-]+)\.[a-zA-Z0-9-]+$'))
			]) AS elem WHERE elem <> '' AND elem IS NOT NULL)
		)
		WHERE canonical_hostname IS NOT NULL
		  AND canonical_hostname <> ''
		  AND canonical_hostname ~ '\.[a-zA-Z0-9-]+$'
	`); err != nil {
		return fmt.Errorf("tag hosts: %w", err)
	}

	// Pattern 3 — ssh_keys, crypto_libraries, crypto_configs: inherit their
	// host's application_tags. Uses a straightforward correlated update.
	for _, table := range []string{"ssh_keys", "crypto_libraries", "crypto_configs"} {
		q := fmt.Sprintf(`
			UPDATE %s AS a
			SET application_tags = (
				SELECT ARRAY(SELECT DISTINCT elem
				             FROM unnest(a.application_tags || h.application_tags) AS elem
				             WHERE elem <> '')
			)
			FROM hosts h
			WHERE a.host_id = h.id
			  AND array_length(h.application_tags, 1) > 0
		`, table)
		if _, err := s.pool.Exec(ctx, q); err != nil {
			return fmt.Errorf("tag %s: %w", table, err)
		}
	}

	return nil
}

// sortApplicationsByTotalDesc sorts in place: total_assets DESC, tag ASC.
func sortApplicationsByTotalDesc(apps []ApplicationSummary) {
	for i := 1; i < len(apps); i++ {
		cur := apps[i]
		j := i - 1
		for j >= 0 && lessApp(cur, apps[j]) {
			apps[j+1] = apps[j]
			j--
		}
		apps[j+1] = cur
	}
}
func lessApp(a, b ApplicationSummary) bool {
	if a.TotalAssets != b.TotalAssets {
		return a.TotalAssets > b.TotalAssets
	}
	return a.Tag < b.Tag
}
