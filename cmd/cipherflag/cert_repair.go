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

package main

import (
	"context"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/ingest"
)

// startCertificateRepair repairs certificates stored blank before 2.3.0 (a
// PEM-only /api/v1/ingest discovery kept only its fingerprint) from their
// stored PEM, and closes the returned channel when it is done. It runs in the
// background: a large backlog must not hold the API down, and serve starts it
// after the CBOM runtime so the scored events it produces are drained rather
// than dropped. With nothing blank it is one index probe. Cancelling ctx
// (shutdown) stops it; what is left is repaired on the next start.
func startCertificateRepair(ctx context.Context, st ingest.BlankCertificateStore, score func(ctx context.Context, fingerprint string) error) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		res, err := ingest.RepairBlankCertificates(ctx, st, score)
		switch {
		case err != nil && ctx.Err() != nil:
			log.Info().Int("repaired", res.Repaired).
				Msg("certificate repair stopped at shutdown; it resumes on the next start")
		case err != nil:
			log.Error().Err(err).Int("repaired", res.Repaired).Msg("certificate repair failed; serving anyway")
		case res.Repaired > 0 || res.Skipped > 0:
			log.Info().Int("repaired", res.Repaired).Int("skipped", res.Skipped).
				Msg("repaired certificates stored without metadata by an earlier version")
		}
	}()
	return done
}
