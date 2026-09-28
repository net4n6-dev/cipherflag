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

package ingest

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/certparse"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// BlankCertificateStore is what RepairBlankCertificates needs from the store.
type BlankCertificateStore interface {
	ListBlankCertificatesWithPEM(ctx context.Context, after string, limit int) ([]store.BlankCertificate, error)
	UpsertCertificate(ctx context.Context, cert *model.Certificate) error
}

// RepairResult counts what a repair pass did. Skipped rows are blank rows
// whose stored PEM does not parse or names a different certificate; they
// are left as they are.
type RepairResult struct {
	Repaired int
	Skipped  int
}

// repairBatchSize is how many blank rows are read per page (a var so tests
// can exercise paging).
var repairBatchSize = 500

// RepairBlankCertificates rebuilds certificates that CE before 2.3.0 stored
// blank (a PEM-only /api/v1/ingest discovery kept only its fingerprint) from
// the PEM stored with them. Each is written through UpsertCertificate,
// whose conflict rule only fills empty columns, keeping the row's own
// last_seen (a repair is not a sighting), and then passed to score. Rows
// whose PEM does not parse, or parses to a different fingerprint, are
// skipped and logged. Pages by fingerprint, so a skipped row is never read
// twice in one pass. Safe to run on every startup: with nothing blank it is
// one index probe.
func RepairBlankCertificates(ctx context.Context, st BlankCertificateStore, score func(ctx context.Context, fingerprint string) error) (RepairResult, error) {
	var res RepairResult
	after := ""
	for {
		page, err := st.ListBlankCertificatesWithPEM(ctx, after, repairBatchSize)
		if err != nil {
			return res, fmt.Errorf("list blank certificates: %w", err)
		}
		if len(page) == 0 {
			return res, nil
		}
		for _, b := range page {
			after = b.FingerprintSHA256
			parsed, err := certparse.ParsePEM([]byte(b.RawPEM))
			if err != nil {
				log.Warn().Err(err).Str("fingerprint", b.FingerprintSHA256).
					Msg("certificate repair: stored PEM does not parse; left as it is")
				res.Skipped++
				continue
			}
			if !strings.EqualFold(parsed.FingerprintSHA256, b.FingerprintSHA256) {
				log.Warn().Str("fingerprint", b.FingerprintSHA256).Str("pem_fingerprint", parsed.FingerprintSHA256).
					Msg("certificate repair: stored PEM is a different certificate; left as it is")
				res.Skipped++
				continue
			}
			parsed.FingerprintSHA256 = b.FingerprintSHA256
			parsed.RawPEM = b.RawPEM
			parsed.SourceDiscovery = model.DiscoverySource(b.SourceDiscovery)
			parsed.FirstSeen = b.FirstSeen
			parsed.LastSeen = b.LastSeen
			if err := st.UpsertCertificate(ctx, parsed); err != nil {
				return res, fmt.Errorf("repair certificate %s: %w", b.FingerprintSHA256, err)
			}
			res.Repaired++
			if err := score(ctx, b.FingerprintSHA256); err != nil {
				log.Warn().Err(err).Str("fingerprint", b.FingerprintSHA256).
					Msg("certificate repair: scoring failed; the sweeper will retry")
			}
		}
	}
}
