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
	"net/url"
	"strings"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/ingest/ct"
)

// Provider is the ct_static Static-CT-API consumer. One Provider per
// source instance (the config carries one log_url + public_key_pem).
// The poller in poller.go constructs a fresh Provider per domain per
// poll cycle — Provider itself is stateless and HTTP-only so ct_multi
// (Task 5) can construct + call it directly without touching the store
// layer.
//
// Compile-time assertion that Provider satisfies ct.Provider.
var _ ct.Provider = (*Provider)(nil)

// Config is the per-call configuration a static.Provider needs to poll
// one domain against one Static CT log: the log's base URL, its
// Ed25519 public key (PEM), the domain being filtered for, and the
// Merkle-walk cache scratchpad. Distinct from
// config.CtStaticDomainConfig (internal/config, Task 6), which is the
// TOML-sourced operator-facing config; poller.go's pollDomain converts
// one into the other every cycle.
type Config struct {
	Domain       string
	LogURL       string
	PublicKeyPEM string

	// Cache is the per-domain Merkle-walk scratchpad. Callers (poller.go)
	// populate it from the persisted ingestion_state cursor before each
	// call; Provider does not persist it itself — see LastSeenTreeSize.
	Cache *Cache
}

// Cache is the per-domain Merkle-walk scratchpad. LastTreeSize is the
// tree size of the last successfully processed STH; QueryDomain only
// walks leaves with indices >= LastTreeSize.
type Cache struct {
	LastTreeSize uint64
}

// Provider implements ct.Provider by consuming a Static CT API log.
type Provider struct {
	Cfg        Config
	HTTPClient *http.Client
	// KeyName is the operator-supplied or convention-derived name that
	// appears in the signed-note signature line. For Sunlight logs this
	// is typically the log's hostname (e.g. "sunlight.letsencrypt.org").
	// Plan A defaults to the host portion of LogURL if unset.
	KeyName string

	// LastSeenTreeSize is set by QueryDomain after STH verification so
	// the poller (poller.go) can persist it to the per-source cache
	// scratchpad without re-fetching the checkpoint.
	LastSeenTreeSize uint64

	// LastVerifiedCount is the number of SAN-matched leaves whose
	// inclusion proof verified successfully on the most recent
	// QueryDomain call. Read by the poller to populate the
	// leaves_verified summary field.
	LastVerifiedCount uint64

	// LastProofFetchFailures is the number of SAN-matched leaves that
	// were skipped on the most recent QueryDomain call because their
	// path-tile fetch failed (per the split failure policy). Read by
	// the poller to populate the proof_fetch_failures summary field.
	LastProofFetchFailures uint64
}

// Name implements ct.Provider — stable provider id used by ct_multi
// for asset_provenance.source attribution and by the poller's
// per-cert ingest stamp.
func (p *Provider) Name() string { return "static" }

// QueryDomain implements ct.Provider. Walks all tiles between the
// per-source cached LastTreeSize and the freshly-fetched checkpoint
// tree size, parses each leaf cert, and emits CTEntry for every cert
// whose SANs match `domain` (or its subdomains).
//
// QueryDomain does NOT update the per-source cache — that is the
// poller's responsibility, so a ct_multi fan-out call doesn't drift
// the per-source scratchpad.
func (p *Provider) QueryDomain(ctx context.Context, domain string) ([]ct.CTEntry, error) {
	pubKey, err := ParseEd25519PublicKeyPEM(p.Cfg.PublicKeyPEM)
	if err != nil {
		return nil, err
	}
	hc := p.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	keyName := p.KeyName
	if keyName == "" {
		keyName, err = deriveKeyName(p.Cfg.LogURL)
		if err != nil {
			return nil, err
		}
	}

	// 1. Fetch + verify the checkpoint.
	cpBytes, err := fetchCheckpoint(ctx, hc, p.Cfg.LogURL)
	if err != nil {
		return nil, err
	}
	sth, err := ParseAndVerifyCheckpoint(cpBytes, pubKey, keyName)
	if err != nil {
		return nil, err
	}

	// 2. Walk tiles. Static CT data tiles each hold up to 256 leaves;
	// tile index = floor(leaf_index / 256). The starting tile index is
	// derived from the cached LastTreeSize; the ending tile is the
	// floor of (sth.TreeSize-1)/256.
	var startTree uint64
	if p.Cfg.Cache != nil {
		startTree = p.Cfg.Cache.LastTreeSize
	}
	if startTree >= sth.TreeSize {
		return nil, nil // already up to date
	}
	startTile := int64(startTree / 256)
	endTile := int64((sth.TreeSize - 1) / 256) // #nosec G115 -- sth.TreeSize is bounds-checked against math.MaxInt64 in sth.go's ParseAndVerifyCheckpoint before an STH is ever returned

	p.LastVerifiedCount = 0
	p.LastProofFetchFailures = 0
	hashReader := newTileHashReader(ctx, hc, p.Cfg.LogURL, int64(sth.TreeSize)) // #nosec G115 -- see above

	out := make([]ct.CTEntry, 0, 64)
	for tile := startTile; tile <= endTile; tile++ {
		tileBytes, err := FetchLeafTile(ctx, hc, p.Cfg.LogURL, tile)
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
					// Fetch failure (network / HTTP / parse) — log + skip this leaf;
					// continue the poll. Counted in LastProofFetchFailures and surfaced
					// in the poll Summary by the Poller.
					log.Warn().
						Err(err).
						Uint64("leaf_index", leafIndex).
						Str("domain", domain).
						Msg("static: inclusion proof fetch failed; skipping leaf")
					p.LastProofFetchFailures++
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
	p.LastSeenTreeSize = sth.TreeSize
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

// deriveKeyName returns the host portion of logURL — the Sunlight
// convention is keyName = log hostname.
func deriveKeyName(logURL string) (string, error) {
	u, err := url.Parse(logURL)
	if err != nil {
		return "", fmt.Errorf("static: deriveKeyName: parse: %w", err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("static: deriveKeyName: %q has no host", logURL)
	}
	return u.Host, nil
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
func verifyLeafInclusion(leaf LeafData, leafIndex int64, sth *STH, hashReader *tileHashReader) error {
	proof, err := tlog.ProveRecord(int64(sth.TreeSize), leafIndex, hashReader) // #nosec G115
	if err != nil {
		// The hashReader wraps HTTP errors with errProofFetch; if so,
		// tlog will propagate the wrapped error here.
		return err
	}
	leafBytes := EncodeTileLeaf(leaf, uint64(leafIndex), false)                            // #nosec G115
	return VerifyInclusion(leafBytes, leafIndex, int64(sth.TreeSize), sth.RootHash, proof) // #nosec G115
}
