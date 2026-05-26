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
	"fmt"
	"strings"
	"time"

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
}

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

	if existing != nil {
		// Existing: upsert to update last_seen and discovery_status
		if err := d.store.UpsertCertificate(ctx, existing); err != nil {
			return "", false, fmt.Errorf("update existing cert: %w", err)
		}
		return fp, false, nil
	}

	// New certificate
	cert := &model.Certificate{
		FingerprintSHA256:  fp,
		Subject:            model.DistinguishedName{CommonName: disc.SubjectCN},
		Issuer:             model.DistinguishedName{CommonName: disc.IssuerCN},
		SerialNumber:       disc.SerialNumber,
		NotBefore:          disc.NotBefore,
		NotAfter:           disc.NotAfter,
		KeyAlgorithm:       model.KeyAlgorithm(disc.KeyAlgorithm),
		KeySizeBits:        disc.KeySizeBits,
		SignatureAlgorithm: model.SignatureAlgorithm(disc.SignatureAlgorithm),
		SubjectAltNames:    disc.SubjectAltNames,
		IsCA:               disc.IsCA,
		RawPEM:             disc.RawPEM,
		SourceDiscovery:    model.DiscoverySource(disc.Source),
		FirstSeen:          time.Now(),
		LastSeen:           time.Now(),
	}

	if err := d.store.UpsertCertificate(ctx, cert); err != nil {
		return "", false, fmt.Errorf("insert new cert: %w", err)
	}
	return fp, true, nil
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
