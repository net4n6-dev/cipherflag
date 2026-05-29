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

// Package scoring dispatches asset scoring and hosts the per-asset-type
// scorers (cert scorer stays at internal/analysis/scorer.go per the
// Layer 4 master design's graceful migration decision).
//
// Scoring is change-driven: UnifiedIngester.Ingest calls ScoreAsset
// after a cache miss + successful Dedup. A cron Sweeper rescores rows
// whose rule_engine_version is stale.
package scoring

// CurrentRuleEngineVersion identifies this build's rule set. Bump when
// adding / removing / materially changing rules. Rows with a stored
// rule_engine_version < CurrentRuleEngineVersion are rescored by the
// cron sweep on the next cycle.
//
// Version history:
//   - 1: Layer 4.1 Multi-Asset Scoring (15 new rules across SSH/lib/config
//        + existing 24 cert rules).
//   - 2: Layer 4.4 Risk Prioritization Engine — adds RiskScore +
//        RiskFactors population inline with scoring. Bumping to 2 causes
//        the cron sweeper to rescore every stored row, naturally
//        backfilling the new columns. Partial stale-sweep index rotated
//        in migration 009 to match.
//   - 3: Layer 4.1b CVE-Based Library Rules — adds LIB-001 (critical CVE)
//        and LIB-002 (high/medium CVE). Bumping to 3 triggers the cron
//        sweeper to rescore all library rows, backfilling CVE findings.
//   - 4: Layer 4.1c Protocol Scoring Rules — adds PROTO-001 (SSHv1),
//        PROTO-002/003/004 (weak SSH kex/cipher/MAC), PROTO-005 (TLS
//        1.0/1.1), PROTO-006 (null/export cipher). Bumping to 4 triggers
//        the cron sweeper to rescore all protocol endpoint rows.
//   - 5: Layer 4 Catalog Hardening — comprehensive EOL/FIPS/PQC catalogs
//        regenerated from upstream + per-finding evidence.source_url. Bumping
//        to 5 causes the cron sweeper to re-classify every stored row,
//        backfilling Evidence on existing findings.
const CurrentRuleEngineVersion = 5
