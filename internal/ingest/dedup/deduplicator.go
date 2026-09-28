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

package dedup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/certparse"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// Discovery sub-types — flat structs for adapter use.

type CertDiscovery struct {
	FingerprintSHA256  string
	SubjectCN          string
	IssuerCN           string
	SerialNumber       string
	NotBefore          time.Time
	NotAfter           time.Time
	KeyAlgorithm       string
	KeySizeBits        int
	SignatureAlgorithm string
	SubjectAltNames    []string
	IsCA               bool
	RawPEM             string
	Source             string
	FilePath           string
	StoreType          string
	RawMetadata        map[string]any // optional; set by import path for provenance audit

	// Parsed is RawPEM already parsed, set by the ingester when it had to
	// parse the PEM for the fingerprint, so it is not parsed twice. Never
	// read from JSON: /api/v1/ingest decodes CertDiscovery from the client.
	Parsed *model.Certificate `json:"-"`
}

// ErrPEMMismatch is returned by DedupCertificate when a discovery's
// fingerprint names a different certificate than its RawPEM.
var ErrPEMMismatch = errors.New("certificate fingerprint does not match its RawPEM")

type SSHKeyDiscovery struct {
	KeyType           string
	KeySizeBits       int
	FingerprintSHA256 string
	FilePath          string
	OwnerUser         string
	IsAuthorized      bool
	IsProtected       bool
	GrantsRoot        bool
	Comment           string
	Source            string
	RawMetadata       map[string]any
}

type LibraryDiscovery struct {
	LibraryName    string
	Version        string
	PackageName    string
	PackageManager string
	InstallPath    string
	PQCCapable     bool
	Source         string
	RawMetadata    map[string]any
}

type ProtocolDiscovery struct {
	ServerIP      string
	ServerPort    int
	Protocol      string
	Version       string
	Algorithms    map[string]string
	IsQuantumSafe bool
	Source        string
	ObservedAt    time.Time

	// ConfiguredPolicy is the adapter-declared TLS policy snapshot
	// (e.g. AWS ELB listener's SslPolicy + cert ARNs). Persisted into
	// protocol_endpoints.configured_policy JSONB. Empty for observed-
	// via-passive-traffic adapters (zeek, scanner) — they don't have
	// a declared policy, only the handshake-revealed posture.
	//
	// See internal/store/migrations/031_protocol_endpoints_configured_policy.sql.
	ConfiguredPolicy json.RawMessage

	// SourceKey is the adapter's stable correlation key for the source
	// resource that produced this protocol observation (e.g. AWS ELB
	// listener ARN). Mirrors CertDiscovery's FilePath role —
	// populated through to IngestedAsset.SourceKey so the AWS Poller
	// can correlate per-LB tags to per-listener IngestedAssets after
	// Ingest. Empty for adapters that don't need post-Ingest correlation.
	//
	// See internal/ingest/ownership.go IngestedAsset.SourceKey.
	SourceKey string
}

type ConfigDiscovery struct {
	ConfigType  string
	FilePath    string
	Settings    map[string]string
	Findings    []model.ConfigIssue
	Source      string
	RawMetadata map[string]any
}

// Deduplicator handles asset deduplication during ingestion.
type Deduplicator struct {
	store store.CryptoStore
}

// NewDeduplicator creates a new Deduplicator.
func NewDeduplicator(st store.CryptoStore) *Deduplicator {
	return &Deduplicator{store: st}
}

func (d *Deduplicator) DedupCertificate(ctx context.Context, hostID string, disc *CertDiscovery) (assetID string, isNew bool, err error) {
	fp := strings.ToLower(disc.FingerprintSHA256)

	existing, err := d.store.GetCertificate(ctx, fp)
	if err != nil {
		return "", false, fmt.Errorf("check existing cert: %w", err)
	}

	now := time.Now()
	if existing != nil {
		// Existing: record the re-observation. UpsertCertificate writes
		// last_seen from the row it is given, so stamp it; writing back the
		// row as read left last_seen at the first ingest forever. A stored
		// row still missing metadata is offered the full certificate;
		// UpsertCertificate fills only the columns that are empty, so
		// nothing already set is overwritten. A complete row is written
		// back as read, without parsing the PEM again.
		if !incompleteCert(existing, disc) {
			existing.LastSeen = now
			if err := d.store.UpsertCertificate(ctx, existing); err != nil {
				return "", false, fmt.Errorf("update existing cert: %w", err)
			}
			return fp, false, nil
		}
		cert, err := candidateFromDiscovery(disc, fp)
		if err != nil {
			return "", false, err
		}
		cert.FirstSeen, cert.LastSeen = existing.FirstSeen, now
		if err := d.store.UpsertCertificate(ctx, cert); err != nil {
			return "", false, fmt.Errorf("update existing cert: %w", err)
		}
		return fp, false, nil
	}

	cert, err := candidateFromDiscovery(disc, fp)
	if err != nil {
		return "", false, err
	}
	cert.FirstSeen, cert.LastSeen = now, now
	if err := d.store.UpsertCertificate(ctx, cert); err != nil {
		return "", false, fmt.Errorf("insert new cert: %w", err)
	}
	return fp, true, nil
}

// incompleteCert reports whether a stored certificate is missing metadata a
// new observation could supply: a core field that is empty (or an
// 'Unknown' algorithm), or no PEM when the discovery has one.
func incompleteCert(c *model.Certificate, disc *CertDiscovery) bool {
	return c.Subject.CommonName == "" || c.NotAfter.IsZero() || c.KeySizeBits == 0 ||
		unknownAlg(string(c.KeyAlgorithm)) || unknownAlg(string(c.SignatureAlgorithm)) ||
		(c.RawPEM == "" && disc.RawPEM != "")
}

func unknownAlg(alg string) bool {
	return alg == "" || alg == string(model.KeyUnknown)
}

// candidateFromDiscovery is the certificate row a discovery describes. With a
// PEM, it starts from the parsed certificate, so every column (organization,
// key usage, key IDs, SPKI fingerprint, OCSP and CRL locations) is filled,
// not only the flat fields a CertDiscovery carries; the discovery's own
// non-empty values go on top, except an 'Unknown' algorithm, and a
// discovery cannot un-CA a CA. A PEM for a different certificate than fp
// is ErrPEMMismatch. A PEM that does not parse leaves the discovery's
// fields, as before.
func candidateFromDiscovery(disc *CertDiscovery, fp string) (*model.Certificate, error) {
	cert := disc.Parsed
	if cert == nil && disc.RawPEM != "" {
		if parsed, err := certparse.ParsePEM([]byte(disc.RawPEM)); err == nil {
			cert = parsed
		}
	}
	if cert == nil {
		cert = &model.Certificate{}
	} else if !strings.EqualFold(cert.FingerprintSHA256, fp) {
		return nil, fmt.Errorf("%w: fingerprint %s, PEM %s", ErrPEMMismatch, fp, cert.FingerprintSHA256)
	} else {
		c := *cert
		cert = &c
	}

	if disc.SubjectCN != "" {
		cert.Subject.CommonName = disc.SubjectCN
	}
	if disc.IssuerCN != "" {
		cert.Issuer.CommonName = disc.IssuerCN
	}
	if disc.SerialNumber != "" {
		cert.SerialNumber = disc.SerialNumber
	}
	if !disc.NotBefore.IsZero() {
		cert.NotBefore = disc.NotBefore
	}
	if !disc.NotAfter.IsZero() {
		cert.NotAfter = disc.NotAfter
	}
	if !unknownAlg(disc.KeyAlgorithm) || cert.KeyAlgorithm == "" {
		cert.KeyAlgorithm = model.KeyAlgorithm(disc.KeyAlgorithm)
	}
	if disc.KeySizeBits != 0 {
		cert.KeySizeBits = disc.KeySizeBits
	}
	if !unknownAlg(disc.SignatureAlgorithm) || cert.SignatureAlgorithm == "" {
		cert.SignatureAlgorithm = model.SignatureAlgorithm(disc.SignatureAlgorithm)
	}
	if len(disc.SubjectAltNames) > 0 {
		cert.SubjectAltNames = disc.SubjectAltNames
	}
	cert.IsCA = cert.IsCA || disc.IsCA
	cert.FingerprintSHA256 = fp
	cert.RawPEM = disc.RawPEM
	cert.SourceDiscovery = model.DiscoverySource(disc.Source)
	return cert, nil
}

func (d *Deduplicator) DedupSSHKey(ctx context.Context, hostID string, disc *SSHKeyDiscovery) (assetID string, isNew bool, err error) {
	fp := strings.ToLower(disc.FingerprintSHA256)

	key := &model.SSHKey{
		HostID:            hostID,
		KeyType:           disc.KeyType,
		KeySizeBits:       disc.KeySizeBits,
		FingerprintSHA256: fp,
		FilePath:          disc.FilePath,
		OwnerUser:         disc.OwnerUser,
		IsAuthorized:      disc.IsAuthorized,
		IsProtected:       disc.IsProtected,
		GrantsRoot:        disc.GrantsRoot,
		Comment:           disc.Comment,
		Source:            disc.Source,
		DiscoveryStatus:   "active",
	}

	if err := d.store.UpsertSSHKey(ctx, key); err != nil {
		return "", false, fmt.Errorf("upsert ssh key: %w", err)
	}

	// UpsertSSHKey uses ON CONFLICT — if first_seen == last_seen it is new
	isNew = key.FirstSeen.Equal(key.LastSeen)
	return key.ID, isNew, nil
}

func (d *Deduplicator) DedupLibrary(ctx context.Context, hostID string, disc *LibraryDiscovery) (assetID string, isNew bool, err error) {
	lib := &model.CryptoLibrary{
		HostID:          hostID,
		LibraryName:     strings.ToLower(disc.LibraryName),
		Version:         strings.TrimSpace(disc.Version),
		PackageName:     disc.PackageName,
		PackageManager:  disc.PackageManager,
		InstallPath:     disc.InstallPath,
		PQCCapable:      disc.PQCCapable,
		Source:          disc.Source,
		DiscoveryStatus: "active",
	}

	if err := d.store.UpsertCryptoLibrary(ctx, lib); err != nil {
		return "", false, fmt.Errorf("upsert crypto library: %w", err)
	}

	isNew = lib.FirstSeen.Equal(lib.LastSeen)
	return lib.ID, isNew, nil
}

func (d *Deduplicator) DedupConfig(ctx context.Context, hostID string, disc *ConfigDiscovery) (assetID string, isNew bool, err error) {
	cfg := &model.CryptoConfig{
		HostID:          hostID,
		ConfigType:      disc.ConfigType,
		FilePath:        disc.FilePath,
		Settings:        disc.Settings,
		Findings:        disc.Findings,
		Source:          disc.Source,
		DiscoveryStatus: "active",
	}

	if err := d.store.UpsertCryptoConfig(ctx, cfg); err != nil {
		return "", false, fmt.Errorf("upsert crypto config: %w", err)
	}

	isNew = cfg.FirstSeen.Equal(cfg.LastSeen)
	return cfg.ID, isNew, nil
}
