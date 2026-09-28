// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package static

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/ingest/ct"
)

// Provider is the ct_static Static-CT-API consumer. One Provider per
// source instance (the config carries one log_url + origin + public_key_pem).
// The poller in poller.go constructs a fresh Provider per domain per
// poll cycle — Provider itself is stateless and HTTP-only so ct_multi
// (Task 5) can construct + call it directly without touching the store
// layer.
//
// Compile-time assertion that Provider satisfies ct.Provider.
var _ ct.Provider = (*Provider)(nil)

// Config is the per-call configuration a static.Provider needs to poll
// one domain against one Static CT log: the log's monitoring URL, its
// checkpoint origin (signature key name), its public key (PEM; ECDSA
// P-256 for every production log, or Ed25519), the domain being filtered
// for, and the Merkle-walk cache scratchpad. Distinct from
// config.CtStaticDomainConfig (internal/config, Task 6), which is the
// TOML-sourced operator-facing config; poller.go's pollDomain converts
// one into the other every cycle.
type Config struct {
	Domain string
	LogURL string
	// Origin is the log's checkpoint origin — its submission URL without
	// scheme or trailing slash (static-ct-api). It is both the expected
	// first line of the checkpoint and the name on the log's signature
	// line. It is NOT derivable from LogURL in general: most production
	// logs serve monitoring from a different host than submission.
	Origin       string
	PublicKeyPEM string

	// Cache is the per-domain Merkle-walk scratchpad. Callers (poller.go)
	// populate it from the persisted ingestion_state cursor before each
	// call; Provider does not persist it itself — see LastSeenTreeSize.
	// nil (always the case under ct_multi) means "no persisted state".
	Cache *Cache
}

// Cache is the per-domain Merkle-walk scratchpad. LastTreeSize is the
// tree size of the last successfully processed STH; QueryDomain only
// walks leaves with indices >= LastTreeSize. LastTreeSize == 0 means
// "no persisted state" — it does NOT mean "walk from leaf 0"; see
// Provider.QueryDomain's forward-watching note.
type Cache struct {
	LastTreeSize uint64
}

// Provider implements ct.Provider by consuming a Static CT API log.
type Provider struct {
	Cfg        Config
	HTTPClient *http.Client

	// LastSeenTreeSize is set by QueryDomain after a successful walk (or
	// a bootstrap to the current head) so the poller (poller.go) can
	// persist it to the per-source cache scratchpad without re-fetching
	// the checkpoint. It is left unchanged when a walk fails, so the
	// failed range is retried. When the walk completes but a matched
	// leaf's inclusion-proof fetch failed, it is set to that leaf's index
	// (not the checkpoint's tree size), so the next call re-walks from
	// the first leaf that was not fully processed instead of losing it.
	// It also serves as this instance's in-memory cursor for subsequent
	// calls (see startTreeSize).
	LastSeenTreeSize uint64

	// LastVerifiedCount is the number of SAN-matched leaves whose
	// inclusion proof verified successfully on the most recent
	// QueryDomain call. Read by poller.go's pollDomain and emitted as the
	// leaves_verified field of its "domain cycle complete" log line.
	LastVerifiedCount uint64

	// LastProofFetchFailures is the number of SAN-matched leaves that
	// were skipped on the most recent QueryDomain call because their
	// hash-tile fetch failed (per the split failure policy). Such leaves
	// are retried on the next call (LastSeenTreeSize stops at the first
	// of them). Read by
	// poller.go's pollDomain and emitted as the proof_fetch_failures
	// field of its "domain cycle complete" log line. (ct_multi does not
	// surface these per-leaf counters; its static child's per-call
	// failures surface through ChildStatus.)
	LastProofFetchFailures uint64
}

// Name implements ct.Provider — a short identifier used for logging and
// ct_multi's per-child status. Provenance attribution uses
// CTEntry.Source ("ct_static"), not Name().
func (p *Provider) Name() string { return "static" }

// startTreeSize decides where this QueryDomain call's walk begins, given
// the freshly verified checkpoint's tree size. bootstrap reports that
// there was no prior position at all, in which case the caller records
// the current head and walks nothing.
//
// Precedence:
//  1. Cfg.Cache.LastTreeSize > 0 — the persisted cursor (standalone
//     ct_static poller; poller.go loads it from ingestion_state).
//  2. p.LastSeenTreeSize > 0 — this same Provider instance's own
//     high-water mark from a previous successful call. This is what
//     makes ct_multi's static child work: ct_multi deliberately has no
//     persisted cursor (Cfg.Cache is always nil there), but it caches
//     its Composer — and therefore this Provider — per group for the
//     life of the process, so the in-memory mark carries across hourly
//     cycles. (poller.go builds a fresh Provider per cycle, so this
//     fallback never applies to the standalone path.)
//  3. Otherwise: bootstrap.
func (p *Provider) startTreeSize() (start uint64, bootstrap bool) {
	if p.Cfg.Cache != nil && p.Cfg.Cache.LastTreeSize > 0 {
		return p.Cfg.Cache.LastTreeSize, false
	}
	if p.LastSeenTreeSize > 0 {
		return p.LastSeenTreeSize, false
	}
	return 0, true
}

// QueryDomain implements ct.Provider. Walks all tiles between the
// starting position (see startTreeSize) and the freshly-fetched
// checkpoint tree size, parses each leaf cert, and emits CTEntry for
// every cert whose SANs match `domain` (or its subdomains) and whose
// inclusion proof verifies.
//
// FORWARD-WATCHING ONLY — deliberate scoping decision, not a gap: with
// no prior position (no persisted cursor and no earlier call on this
// instance) QueryDomain does NOT walk the log from leaf 0. It records the
// current checkpoint's tree size as its starting point
// (LastSeenTreeSize), walks zero leaves, and returns (nil, nil); later
// calls see only certificates logged after that moment. A real Sunlight
// shard holds hundreds of millions of leaves (multi-MB data tiles, 256
// leaves each), so a from-genesis walk is infeasible on a cold start —
// and, before this change, ct_multi's cursor-less static child repeated
// that full walk on every hourly cycle. Historical coverage is the job of
// ct_crtsh and ct_certspotter, which query by domain (the coverage-union
// design ct_multi exists for). Consequence for operators: ct_static only
// reports certificates issued after it was first enabled for a domain;
// after a restart ct_multi's static child re-bootstraps at the then-
// current head, so leaves logged while the process was down are not seen
// by that child.
//
// QueryDomain does NOT update Cfg.Cache — persisting LastSeenTreeSize is
// the standalone poller's responsibility — so a ct_multi fan-out call
// never drifts the standalone poller's persisted scratchpad.
func (p *Provider) QueryDomain(ctx context.Context, domain string) ([]ct.CTEntry, error) {
	pubKey, err := ParseLogPublicKeyPEM(p.Cfg.PublicKeyPEM)
	if err != nil {
		return nil, err
	}
	if err := ValidateOrigin(p.Cfg.Origin); err != nil {
		return nil, err
	}
	hc := p.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}

	// 1. Fetch + verify the checkpoint.
	cpBytes, err := fetchCheckpoint(ctx, hc, p.Cfg.LogURL)
	if err != nil {
		return nil, err
	}
	sth, err := ParseAndVerifyCheckpoint(cpBytes, p.Cfg.Origin, pubKey)
	if err != nil {
		return nil, err
	}

	// 2. Decide where to start (see startTreeSize and the
	// forward-watching note on QueryDomain).
	p.LastVerifiedCount = 0
	p.LastProofFetchFailures = 0
	startTree, bootstrap := p.startTreeSize()
	if bootstrap {
		log.Info().
			Str("domain", domain).
			Str("log_url", p.Cfg.LogURL).
			Uint64("tree_size", sth.TreeSize).
			Msg("static: no prior cursor; starting to watch from the current tree head (no historical backfill)")
		p.LastSeenTreeSize = sth.TreeSize
		return nil, nil
	}
	if startTree >= sth.TreeSize {
		return nil, nil // already up to date
	}

	// 3. Walk tiles. Static CT data tiles each hold up to 256 leaves;
	// tile index = floor(leaf_index / 256). The ending tile is the
	// floor of (sth.TreeSize-1)/256.
	startTile := int64(startTree / 256)
	endTile := int64((sth.TreeSize - 1) / 256) // #nosec G115 -- sth.TreeSize is bounds-checked against math.MaxInt64 in sth.go's ParseAndVerifyCheckpoint before an STH is ever returned

	hashReader := newTileHashReader(ctx, hc, p.Cfg.LogURL, int64(sth.TreeSize), sth.RootHash) // #nosec G115 -- see above

	out := make([]ct.CTEntry, 0, 64)
	// resumeAt records the first (lowest — the walk is in ascending leaf
	// order) matched leaf whose inclusion proof could not be checked
	// because a hash-tile fetch failed. The walk still completes so later
	// matches are emitted, but the cursor must not move past this leaf:
	// otherwise a transient 429/5xx on one hash tile would permanently
	// drop that certificate. Leaves re-walked next time that were already
	// emitted are harmless — ingest is idempotent by fingerprint.
	var (
		resumeAt   uint64
		haveResume bool
	)
	for tile := startTile; tile <= endTile; tile++ {
		tileBytes, err := FetchLeafTile(ctx, hc, p.Cfg.LogURL, tile, int64(sth.TreeSize)) // #nosec G115 -- see above
		if err != nil {
			return nil, err
		}
		leaves, err := ParseLeafTile(tileBytes)
		if err != nil {
			return nil, fmt.Errorf("static: parse tile %d: %w", tile, err)
		}
		for i, leaf := range leaves {
			leafIndex := uint64(tile)*256 + uint64(i)
			if leafIndex < startTree || leafIndex >= sth.TreeSize {
				continue
			}
			// certDER is the full DER bytes of the submitted certificate
			// — the bytes used for fingerprinting, PEM emission, and
			// x509.ParseCertificate. For x509_entry that's leaf.Certificate
			// directly. For precert_entry the wire format puts the TBS in
			// signed_entry (= leaf.Certificate) and the full submitted
			// precert in the trailing pre_certificate field
			// (= leaf.PreCertificate); only PreCertificate is parseable as
			// a full X.509 cert. Skip precert leaves with no PreCertificate
			// (defensive — should never happen for spec-conformant tiles).
			var certDER []byte
			switch leaf.EntryType {
			case 0:
				certDER = leaf.Certificate
			case 1:
				certDER = leaf.PreCertificate
			default:
				continue
			}
			if certDER == nil {
				continue
			}
			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				continue
			}
			if !certMatchesDomain(cert, domain) {
				continue
			}
			if err := verifyLeafInclusion(leaf, int64(leafIndex), sth, hashReader); err != nil {
				if errors.Is(err, errProofFetch) {
					// Fetch failure (network / HTTP / parse) — log + skip this leaf
					// for this call, continue the walk, and hold the cursor at this
					// leaf so the next call retries it. Counted in
					// LastProofFetchFailures and surfaced in the poll Summary by
					// the Poller.
					log.Warn().
						Err(err).
						Uint64("leaf_index", leafIndex).
						Str("domain", domain).
						Msg("static: inclusion proof fetch failed; skipping leaf this cycle, will retry")
					p.LastProofFetchFailures++
					if !haveResume {
						resumeAt, haveResume = leafIndex, true
					}
					continue
				}
				// Cryptographic mismatch — abort the entire poll.
				return nil, fmt.Errorf("static: inclusion proof verification failed at leaf %d: %w", leafIndex, err)
			}
			p.LastVerifiedCount++
			pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
			fp := sha256.Sum256(certDER)
			out = append(out, ct.CTEntry{
				Fingerprint: hex.EncodeToString(fp[:]),
				PEM:         pemBlock,
				CommonName:  cert.Subject.CommonName,
				NameValue:   joinSANs(cert.DNSNames),
				IssuerName:  cert.Issuer.CommonName,
				NotBefore:   cert.NotBefore,
				NotAfter:    cert.NotAfter,
				Source:      "ct_static",
			})
		}
	}
	if haveResume {
		// resumeAt >= startTree > 0 (the walk path is only reached with a
		// non-zero start), so this never collapses to the "no cursor" 0.
		p.LastSeenTreeSize = resumeAt
	} else {
		p.LastSeenTreeSize = sth.TreeSize
	}
	return out, nil
}

// fetchCheckpoint GETs <logURL>checkpoint and returns the raw body.
func fetchCheckpoint(ctx context.Context, hc *http.Client, logURL string) ([]byte, error) {
	u := logURL + "checkpoint"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("static: fetchCheckpoint: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("static: fetchCheckpoint: %s returned %d", u, resp.StatusCode)
	}
	const cpMaxBytes = 64 << 10
	body, err := io.ReadAll(io.LimitReader(resp.Body, cpMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("static: fetchCheckpoint: read: %w", err)
	}
	if len(body) > cpMaxBytes {
		return nil, fmt.Errorf("static: fetchCheckpoint: body too large (>%d bytes)", cpMaxBytes)
	}
	return body, nil
}

// certMatchesDomain returns true if any DNS-SAN equals `domain` or is
// a subdomain of it. Wildcard SANs (`*.example.com`) match the parent
// domain.
func certMatchesDomain(cert *x509.Certificate, domain string) bool {
	for _, san := range cert.DNSNames {
		if sanMatches(san, domain) {
			return true
		}
	}
	return false
}

func sanMatches(san, domain string) bool {
	san = strings.ToLower(san)
	domain = strings.ToLower(domain)
	if san == domain {
		return true
	}
	if len(san) > len(domain) && strings.HasSuffix(san, "."+domain) {
		return true
	}
	if strings.HasPrefix(san, "*.") && san[2:] == domain {
		return true
	}
	return false
}

func joinSANs(sans []string) string {
	return strings.Join(sans, "\n")
}

// verifyLeafInclusion builds the audit path for leaf at leafIndex via
// the given hashReader, then checks it against the STH's root. Returns
// nil on success; on failure returns the raw error — either an
// errProofFetch-wrapped fetch error from the hashReader, or a
// cryptographic-mismatch error from VerifyInclusion. The caller in
// QueryDomain applies the split failure policy: errors.Is(err, errProofFetch)
// → log + skip; other → abort the entire poll.
//
// The leaf hash input is computed via EncodeTileLeaf(leaf, leafIndex, false)
// — the RFC 6962 MerkleTreeLeaf record that Sunlight's reference
// MerkleTreeLeaf() emits (filippo.io/sunlight/tile.go). The `false`
// archival flag is the native-Sunlight production case (leaf_index
// extension present). This matches the bytes real Sunlight logs sign
// over, so inclusion proofs verify against production logs.
// leafIndex is always in [0, sth.TreeSize) — the sole caller (QueryDomain)
// checks `leafIndex >= sth.TreeSize` before calling this — and sth.TreeSize
// is itself bounds-checked against math.MaxInt64 in sth.go, so every
// conversion below is provably safe (gosec G115).
func verifyLeafInclusion(leaf LeafData, leafIndex int64, sth *STH, hashReader tlog.HashReader) error {
	proof, err := tlog.ProveRecord(int64(sth.TreeSize), leafIndex, hashReader) // #nosec G115
	if err != nil {
		// The hashReader wraps HTTP errors with errProofFetch; if so,
		// tlog will propagate the wrapped error here.
		return err
	}
	leafBytes := EncodeTileLeaf(leaf, uint64(leafIndex), false)                            // #nosec G115
	return VerifyInclusion(leafBytes, leafIndex, int64(sth.TreeSize), sth.RootHash, proof) // #nosec G115
}
