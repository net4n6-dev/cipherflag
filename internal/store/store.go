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
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// CertSearchQuery defines search/filter/pagination for certificate listing.
type CertSearchQuery struct {
	Search             string // Full-text search across CN, SANs, fingerprint, org
	Grade              string // Filter by grade (e.g., "F", "D,F")
	Source             string // Filter by discovery source
	IssuerCN           string // Filter by issuer common name
	SubjectOU          string // Filter by subject organizational unit
	IssuerOrg          string // Filter by issuer organization
	KeyAlgorithm       string // Filter by key algorithm (RSA, ECDSA, Ed25519)
	SignatureAlgo      string // Filter by signature algorithm
	ServerName         string // Filter by observed server name (joins observations)
	TLSVersion         string // Filter by observed TLS version (joins observations)
	CipherStrength     string // Filter by observed cipher strength (joins observations)
	IsCA               *bool  // Filter CA certs
	Expired            *bool  // Filter expired only
	ExpiringWithinDays *int   // Filter certs expiring within N days
	SortBy             string // "expiry", "grade", "cn", "last_seen"
	SortDir            string // "asc", "desc"
	Page               int
	PageSize           int
}

// CertSearchResult is a paginated result from SearchCertificates.
type CertSearchResult struct {
	Certificates []model.Certificate `json:"certificates"`
	// Grades is a fingerprint → health-report grade map for the rows in
	// Certificates. Lets /assets and other list views render grade columns
	// without a per-row health-report fetch. Certs with no health report
	// are absent from the map (not "" / "?" — callers distinguish missing
	// from graded).
	Grades   map[string]string `json:"grades"`
	Total    int               `json:"total"`
	Page     int               `json:"page"`
	PageSize int               `json:"page_size"`
}

// SummaryStats holds dashboard aggregate statistics.
type SummaryStats struct {
	TotalCerts        int            `json:"total_certs"`
	TotalObservations int            `json:"total_observations"`
	GradeDistribution map[string]int `json:"grade_distribution"`
	ExpiringIn30Days  int            `json:"expiring_in_30_days"`
	ExpiringIn90Days  int            `json:"expiring_in_90_days"`
	Expired           int            `json:"expired"`
	TotalFindings     int            `json:"total_findings"`
	CriticalFindings  int            `json:"critical_findings"`
	SourceStats       map[string]int `json:"source_stats"`
	SSHKeyCount       int            `json:"ssh_key_count"`
	LibraryCount      int            `json:"library_count"`
	ConfigCount       int            `json:"config_count"`
	ProtocolCount     int            `json:"protocol_count"`
	HostCountActive   int            `json:"host_count_active"`
	HostCountStale    int            `json:"host_count_stale"`
	HostCountRemoved  int            `json:"host_count_removed"`
	PQCVulnerable     int            `json:"pqc_vulnerable"`
	PQCWeakened       int            `json:"pqc_weakened"`
	PQCSafe           int            `json:"pqc_safe"`
	PQCHybrid         int            `json:"pqc_hybrid"`
	PQCUnknown        int            `json:"pqc_unknown"`
	CriticalRiskCount int            `json:"critical_risk_count"`
}

// CipherStats holds cipher suite analytics.
type CipherStats struct {
	SuiteDistribution    []CipherCount  `json:"suite_distribution"`
	StrengthDistribution map[string]int `json:"strength_distribution"`
	TLSVersionDist       map[string]int `json:"tls_version_distribution"`
	TLSCipherMatrix      []TLSCipherRow `json:"tls_cipher_matrix"`
}

type CipherCount struct {
	Suite    string `json:"suite"`
	Strength string `json:"strength"`
	Count    int    `json:"count"`
}

type TLSCipherRow struct {
	TLSVersion string `json:"tls_version"`
	Strength   string `json:"strength"`
	Count      int    `json:"count"`
}

// PKITreeNode represents a CA in the PKI tree with its children/leaf counts.
type PKITreeNode struct {
	Fingerprint  string        `json:"fingerprint"`
	SubjectCN    string        `json:"subject_cn"`
	SubjectOrg   string        `json:"subject_org"`
	Country      string        `json:"country"`
	KeyAlgorithm string        `json:"key_algorithm"`
	KeySizeBits  int           `json:"key_size_bits"`
	Grade        string        `json:"grade"`
	Score        int           `json:"score"`
	NotAfter     string        `json:"not_after"`
	NodeType     string        `json:"node_type"` // "root" or "intermediate"
	LeafCount    int           `json:"leaf_count"`
	Children     []PKITreeNode `json:"children,omitempty"`
}

// PKITreeResponse is the full PKI hierarchy.
type PKITreeResponse struct {
	Roots       []PKITreeNode `json:"roots"`
	OrphanCount int           `json:"orphan_count"`
	TotalCAs    int           `json:"total_cas"`
	TotalLeaves int           `json:"total_leaves"`
}

// IssuerStat holds issuer breakdown for treemap.
type IssuerStat struct {
	IssuerCN     string `json:"issuer_cn"`
	IssuerOrg    string `json:"issuer_org"`
	Country      string `json:"country"`
	CertCount    int    `json:"cert_count"`
	AvgScore     int    `json:"avg_score"`
	MinGrade     string `json:"min_grade"`
	ExpiredCount int    `json:"expired_count"`
}

// ExpiryBucket holds expiry timeline data.
type ExpiryBucket struct {
	WeekStart string `json:"week_start"`
	Count     int    `json:"count"`
	Expired   int    `json:"expired"`
	Critical  int    `json:"critical"`
}

// ExpiryTimeline is the response for the expiry timeline endpoint.
type ExpiryTimeline struct {
	Buckets        []ExpiryBucket `json:"buckets"`
	TotalCerts     int            `json:"total_certs"`
	AlreadyExpired int            `json:"already_expired"`
}

// CertStore is the primary storage interface.
type CertStore interface {
	// Certificates
	UpsertCertificate(ctx context.Context, cert *model.Certificate) error
	GetCertificate(ctx context.Context, fingerprint string) (*model.Certificate, error)
	SearchCertificates(ctx context.Context, q CertSearchQuery) (*CertSearchResult, error)
	BatchUpsertCertificates(ctx context.Context, certs []*model.Certificate) error

	// Observations
	RecordObservation(ctx context.Context, obs *model.CertificateObservation) error
	GetObservations(ctx context.Context, fingerprint string, limit int) ([]model.CertificateObservation, error)
	BatchRecordObservations(ctx context.Context, obs []*model.CertificateObservation) error

	// Endpoint Profiles
	UpsertEndpointProfile(ctx context.Context, ep *model.EndpointProfile) error
	GetEndpointProfile(ctx context.Context, ip string, port int) (*model.EndpointProfile, error)
	GetAllEndpointProfiles(ctx context.Context) ([]model.EndpointProfile, error)

	// Health Reports
	SaveHealthReport(ctx context.Context, report *model.HealthReport) error
	GetHealthReport(ctx context.Context, fingerprint string) (*model.HealthReport, error)
	GetAllHealthReports(ctx context.Context) ([]model.HealthReport, error)

	// Aggregations
	GetSummaryStats(ctx context.Context) (*SummaryStats, error)
	GetCipherStats(ctx context.Context) (*CipherStats, error)

	// PKI tree + analytics
	GetPKITree(ctx context.Context) (*PKITreeResponse, error)
	GetIssuerStats(ctx context.Context) ([]IssuerStat, error)
	GetExpiryTimeline(ctx context.Context) (*ExpiryTimeline, error)
	GetChainFlow(ctx context.Context) (*model.ChainFlowResponse, error)
	GetOwnershipStats(ctx context.Context) (*model.OwnershipResponse, error)
	GetDeploymentStats(ctx context.Context) (*model.DeploymentResponse, error)
	GetCryptoPosture(ctx context.Context) (*model.CryptoPostureResponse, error)
	GetExpiryForecast(ctx context.Context) (*model.ExpiryForecastResponse, error)
	GetSourceLineage(ctx context.Context) (*model.SourceLineageResponse, error)

	// Graph data
	GetAllCertificatesForGraph(ctx context.Context) ([]model.Certificate, error)
	GetAggregatedLandscape(ctx context.Context) (*model.AggregatedLandscapeResponse, error)
	GetCAChildren(ctx context.Context, fingerprint string, limit, offset int) (*model.CAChildrenResponse, error)
	GetBlastRadius(ctx context.Context, fingerprint string, limit int) (*model.BlastRadiusResponse, error)

	// Ingestion state
	GetIngestionState(ctx context.Context, sourceName string) (*model.IngestionState, error)
	SetIngestionState(ctx context.Context, state *model.IngestionState) error

	// Venafi push export
	GetCertsForVenafiPush(ctx context.Context, pushInterval time.Duration, limit int) ([]model.Certificate, error)
	GetLatestObservationsForCerts(ctx context.Context, fingerprints []string) (map[string]*model.CertificateObservation, error)
	MarkVenafiPushSuccess(ctx context.Context, fingerprints []string) error
	MarkVenafiPushFailure(ctx context.Context, fingerprints []string) error
	GetVenafiPushStats(ctx context.Context) (*model.VenafiPushStats, error)

	// PCAP Jobs (legacy CE-v1; retained for binary compatibility, no API surface)
	CreatePCAPJob(ctx context.Context, job *model.PCAPJob) error
	GetPCAPJob(ctx context.Context, id string) (*model.PCAPJob, error)
	UpdatePCAPJob(ctx context.Context, job *model.PCAPJob) error
	ListPCAPJobs(ctx context.Context, limit int) ([]model.PCAPJob, error)

	// Reports
	GetDomainReport(ctx context.Context, domain string) (*model.DomainReport, error)
	GetCAReport(ctx context.Context, fingerprint string, issuerCN string) (*model.CAReport, error)
	GetComplianceReport(ctx context.Context) (*model.ComplianceReport, error)
	GetExpiryReport(ctx context.Context, days int) (*model.ExpiryReport, error)

	// Global search
	GlobalSearch(ctx context.Context, query string, limit int) (*model.GlobalSearchResult, error)

	// Users
	HasUsers(ctx context.Context) (bool, error)
	GetUserByEmail(ctx context.Context, email string) (*model.User, error)
	GetUserByID(ctx context.Context, id string) (*model.User, error)
	ListUsers(ctx context.Context) ([]model.User, error)
	CreateUser(ctx context.Context, user *model.User) error
	UpdateUser(ctx context.Context, id string, displayName string, role string) error
	UpdateUserPassword(ctx context.Context, id string, passwordHash string) error
	UpdateUserLastLogin(ctx context.Context, id string) error
	DeleteUser(ctx context.Context, id string) error

	// Lifecycle
	Migrate(ctx context.Context) error
	Close() error
}

// ── CryptoStore: multi-asset extension ──────────────────────────────────────

// HostSearchQuery defines search/filter/pagination for host listing.
type HostSearchQuery struct {
	Search   string
	OSFamily string
	Source   string
	HostType string
	Limit    int
	Offset   int
}

// HostSearchResult is a paginated result from ListHosts.
type HostSearchResult struct {
	Hosts []model.Host `json:"hosts"`
	Total int          `json:"total"`
}

// SSHKeySearchQuery defines search/filter/pagination for SSH key listing.
type SSHKeySearchQuery struct {
	HostID  string
	KeyType string
	Status  string
	Search  string
	Limit   int
	Offset  int
}

// SSHKeySearchResult is a paginated result from ListSSHKeys.
type SSHKeySearchResult struct {
	Keys  []model.SSHKey `json:"keys"`
	Total int            `json:"total"`
}

// LibrarySearchQuery defines search/filter/pagination for crypto library listing.
type LibrarySearchQuery struct {
	HostID      string
	LibraryName string
	HasCVE      *bool
	PQCCapable  *bool
	Status      string
	Search      string
	Limit       int
	Offset      int
}

// LibrarySearchResult is a paginated result from ListCryptoLibraries.
type LibrarySearchResult struct {
	Libraries []model.CryptoLibrary `json:"libraries"`
	Total     int                   `json:"total"`
}

// ConfigSearchQuery defines search/filter/pagination for crypto config listing.
type ConfigSearchQuery struct {
	HostID     string
	ConfigType string
	Status     string
	Search     string
	Limit      int
	Offset     int
}

// ConfigSearchResult is a paginated result from ListCryptoConfigs.
type ConfigSearchResult struct {
	Configs []model.CryptoConfig `json:"configs"`
	Total   int                  `json:"total"`
}

// AttritionConfig holds thresholds for asset staleness management.
type AttritionConfig struct {
	CycleStaleThreshold   int
	CycleRemovedThreshold int
	NetworkStaleDays      int
	NetworkRemovedDays    int
	CycleBasedSources     []string
	NetworkBasedSources   []string
}

// AttritionSummary reports the result of a staleness sweep.
type AttritionSummary struct {
	MarkedStale   int            `json:"marked_stale"`
	MarkedRemoved int            `json:"marked_removed"`
	ByAssetType   map[string]int `json:"by_asset_type"`
}

// ScanJobQuery filters list-scan-jobs queries.
type ScanJobQuery struct {
	RepoID string
	Status string
	Limit  int
	Offset int
}

// RepoFindingQuery filters the JSONB findings on a single repository's
// asset_health_reports row.
type RepoFindingQuery struct {
	RepoID     string   // required
	Severities []string // optional; empty = all
	Buckets    []string // optional; empty = all
	DetectedBy string   // optional substring match on any element
	Limit      int
	Offset     int
}

// RepoFindingRow is the projected row returned from ListRepositoryFindings.
// The pipeline stored findings inside asset_health_reports.findings JSONB;
// this query unpacks them back out as individual rows for the API.
type RepoFindingRow struct {
	RepoID      string         `json:"repo_id"`
	RuleID      string         `json:"rule_id"`
	Severity    string         `json:"severity"`
	Bucket      string         `json:"bucket"`
	Path        string         `json:"path"`
	Confidence  float64        `json:"confidence"`
	DetectedBy  []string       `json:"detected_by"`
	Fingerprint string         `json:"fingerprint,omitempty"`
	ScanID      string         `json:"scan_id"`
	Raw         map[string]any `json:"raw,omitempty"`
}

// StaleAssetRow is a minimal (asset_type, asset_id) tuple returned by
// sweep queries. Scorer uses these IDs to fetch the full asset via the
// asset-specific Get methods.
type StaleAssetRow struct {
	AssetType string
	AssetID   string
}

// ScopeAssetQuery selects assets that have provenance on the given hosts.
type ScopeAssetQuery struct {
	HostIDs      []string // required — caller must resolve patterns first
	AssetTypes   []string // empty = all four types (cert/ssh_key/library/config)
	MinRiskScore int      // 0 = no floor
}

// ScopeAssetRow is a (assetType, assetID, healthReport) triple returned
// by ListScopeAssets. The Report is the most recently scored record.
// Sources is the deduplicated set of asset_provenance.source values for
// this asset across all provenance rows visible to the query. It is used
// by the CBOM emit pipeline to derive CryptoExecutionEnvironment.
// LibraryName and LibraryVersion are populated for AssetType=="crypto_library"
// rows; they are empty strings for all other asset types.
type ScopeAssetRow struct {
	AssetType      string
	AssetID        string
	Report         model.AssetHealthReport
	Sources        []string // deduplicated asset_provenance.source values
	LibraryName    string   // non-empty for crypto_library rows; used by CBOM FIPS lookup
	LibraryVersion string   // non-empty for crypto_library rows; used by CBOM FIPS lookup
}

// MultiSearchItem is a single result from a multi-type search.
type MultiSearchItem struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	Label    string `json:"label"`
	Sublabel string `json:"sublabel,omitempty"`
	Grade    string `json:"grade,omitempty"`
}

// MultiSearchResult is the response from SearchMultiType.
type MultiSearchResult struct {
	Items []MultiSearchItem `json:"items"`
	Total int               `json:"total"`
}

// LibraryDistItem is a single row from the library distribution query.
type LibraryDistItem struct {
	Library   string `json:"library"`
	Version   string `json:"version"`
	HostCount int    `json:"host_count"`
	HasCVEs   bool   `json:"has_cves"`
}

// AgeBucket is a single age-range bucket in SSH key analytics.
type AgeBucket struct {
	Bucket string `json:"bucket"`
	Count  int    `json:"count"`
}

// ProtectionStats counts protected vs unprotected SSH keys.
type ProtectionStats struct {
	Protected   int `json:"protected"`
	Unprotected int `json:"unprotected"`
}

// SSHKeyAnalytics is the full SSH key analytics response.
//
// StrengthDistribution buckets classical-cryptography strength derived from
// (key_type, key_size_bits): "weak" (DSA, RSA<2048), "acceptable" (RSA=2048),
// "strong" (RSA>=3072, ECDSA), "modern" (Ed25519).
//
// SharedKeysCount is the number of distinct fingerprints present on ≥2 hosts
// (lateral-movement risk signal). SharedKeysInstances is the total ssh_keys
// rows involved in those shared-fingerprint sets.
type SSHKeyAnalytics struct {
	KeyTypes             map[string]int  `json:"key_types"`
	AgeDistribution      []AgeBucket     `json:"age_distribution"`
	Protection           ProtectionStats `json:"protection"`
	RootAuthorizedCount  int             `json:"root_authorized_count"`
	StrengthDistribution map[string]int  `json:"strength_distribution"`
	SharedKeysCount      int             `json:"shared_keys_count"`
	SharedKeysInstances  int             `json:"shared_keys_instances"`
	SourceBreakdown      map[string]int  `json:"source_breakdown"`
	TotalKeys            int             `json:"total_keys"`
}

// CryptoStore extends CertStore with multi-asset crypto posture methods.
//
// CE-flavor: EE-only methods (risk-engine, blast-radius, host-dependency
// edges, PQC-migration planner, protocol endpoints, external-source
// registry, AD CS events, briefing cache, AI ledger, multi-tenant teams)
// are NOT declared on this interface. Their concrete implementations live
// only in CipherFlag EE; CE callers use the deterministic-only subset
// surfaced here.
type CryptoStore interface {
	CertStore

	// Hosts
	UpsertHost(ctx context.Context, host *model.Host) error
	GetHost(ctx context.Context, id string) (*model.Host, error)
	FindHostByIP(ctx context.Context, ip string) (*model.Host, error)
	FindHostByHostname(ctx context.Context, hostname string) (*model.Host, error)
	ListHosts(ctx context.Context, query HostSearchQuery) (*HostSearchResult, error)
	MergeHosts(ctx context.Context, targetID, sourceID string) error

	// Host Identifiers
	UpsertHostIdentifier(ctx context.Context, ident *model.HostIdentifier) error
	FindHostBySourceID(ctx context.Context, source, sourceHostID string) (*model.Host, error)

	// SSH Keys
	UpsertSSHKey(ctx context.Context, key *model.SSHKey) error
	GetSSHKey(ctx context.Context, id string) (*model.SSHKey, error)
	ListSSHKeys(ctx context.Context, query SSHKeySearchQuery) (*SSHKeySearchResult, error)

	// Crypto Libraries
	UpsertCryptoLibrary(ctx context.Context, lib *model.CryptoLibrary) error
	GetCryptoLibrary(ctx context.Context, id string) (*model.CryptoLibrary, error)
	ListCryptoLibraries(ctx context.Context, query LibrarySearchQuery) (*LibrarySearchResult, error)
	GetCryptoLibraryCVEs(ctx context.Context, libraryName, version string) ([]model.CryptoLibraryCVE, error)

	// Crypto Configs
	UpsertCryptoConfig(ctx context.Context, cfg *model.CryptoConfig) error
	GetCryptoConfig(ctx context.Context, id string) (*model.CryptoConfig, error)
	ListCryptoConfigs(ctx context.Context, query ConfigSearchQuery) (*ConfigSearchResult, error)

	// Asset Health (multi-type)
	SaveAssetHealthReport(ctx context.Context, report *model.AssetHealthReport) error
	GetAssetHealthReport(ctx context.Context, assetType, assetID string) (*model.AssetHealthReport, error)
	// MergeFindingsForAsset replaces only the findings whose rule_id is present
	// in the supplied slice, preserving all other scorers' findings. An atomic
	// UPSERT — no external transaction required. See provenance.go for the
	// implementation.
	MergeFindingsForAsset(ctx context.Context, assetType, assetID string, findings []model.HealthFinding) error

	// Provenance
	RecordProvenance(ctx context.Context, prov *model.AssetProvenance) error
	GetProvenance(ctx context.Context, assetType, assetID string) ([]model.AssetProvenance, error)

	// CBOM scope support
	GetProvenanceHostIDs(ctx context.Context, assetType, assetID string) ([]string, error)
	GetHostIDsByPatterns(ctx context.Context, patterns []string) ([]string, error)
	ListScopeAssets(ctx context.Context, q ScopeAssetQuery) ([]ScopeAssetRow, error)
	ListApplicationScopeAssets(ctx context.Context, tag string) ([]ScopeAssetRow, error)
	ListAllAssetHealthReports(ctx context.Context) ([]ScopeAssetRow, error)

	// Attrition
	MarkStaleAssets(ctx context.Context, cfg AttritionConfig) (*AttritionSummary, error)
	ReactivateAsset(ctx context.Context, assetType, assetID string) error

	// Applications (Layer 0 — tag-based Application entity; see
	// docs/analyst-question-catalog.md §Domain 9 AQ-AP-*).
	//
	// ListApplications accepts an optional `before` time.Time (nil = no
	// filter). When non-nil, only applications with ≥1 finding whose
	// scope_deadline ≤ cutoff are returned — powers AQ-AP-02.
	ListApplications(ctx context.Context, before *time.Time) ([]ApplicationSummary, error)
	GetApplication(ctx context.Context, tag string) (*ApplicationDetail, error)
	SeedApplicationTagsFromPatterns(ctx context.Context) error

	// Algorithmic Hygiene (AQ-AH-01) — list of (asset, weak algorithm)
	// occurrences across all asset tables that carry algorithm spellings.
	ListWeakAlgorithmOccurrences(ctx context.Context, filter WeakAlgoFilter) ([]WeakAlgoOccurrence, error)

	// v1.5.0 host↔IP sighting ledger.
	UpsertHostIPSighting(ctx context.Context, sighting *HostIPSighting) error
	GetHostIPSightingsForIP(ctx context.Context, ip string, at time.Time) ([]HostIPSighting, error)
	PruneHostIPSightings(ctx context.Context, cutoff time.Time) (int64, error)
	CountHostIPSightings(ctx context.Context, source string) (int, error)

	// v1.6.0 shadow-CA registry.
	ListShadowCAs(ctx context.Context) ([]ShadowCA, error)
	ListDeclaredCAs(ctx context.Context) ([]DeclaredCA, error)
	DeclareCA(ctx context.Context, req *DeclareCARequest) error
	RevokeDeclaredCA(ctx context.Context, fingerprint string) error
	IsDeclared(ctx context.Context, fingerprint string) (bool, error)

	// v1.7.0 application metadata + HNDL.
	UpsertApplicationMetadata(ctx context.Context, req *DeclareApplicationMetadataRequest) error
	GetApplicationMetadata(ctx context.Context, tag string) (*ApplicationMetadata, error)
	ListApplicationMetadata(ctx context.Context) ([]ApplicationMetadata, error)
	DeleteApplicationMetadata(ctx context.Context, tag string) error
	ListHNDLAtRiskAssets(ctx context.Context, crqcHorizonYear int) ([]HNDLAtRiskAsset, error)

	// v1.8.0 ownership ledger (teams registry is EE-only; CE retains the
	// ownership-by-team-slug semantic but no teams CRUD surface).
	UpsertOwnershipSighting(ctx context.Context, sighting *OwnershipSighting) error
	DeleteOwnershipSighting(ctx context.Context, id string) error
	DeleteOwnershipStamp(ctx context.Context, assetType, assetID, team string) error
	ResolveOwner(ctx context.Context, assetType, assetID string) (*OwnershipResolution, error)
	ResolveOwnerBatch(ctx context.Context, refs []AssetRef) (map[AssetRef]*OwnershipResolution, error)
	ListUnownedVulnerableAssets(ctx context.Context, horizonYear int) ([]UnownedVulnerableAsset, error)
	BackfillOwnershipFromApplicationMetadata(ctx context.Context) (int, error)
	BackfillOwnershipFromDeclaredCAs(ctx context.Context) (int, error)
	BackfillOwnershipFromCertSubjects(ctx context.Context) (int, error)
	PruneStaleOwnershipSightings(ctx context.Context, maxAge time.Duration) (int, error)

	// Agent Tokens
	CreateAgentToken(ctx context.Context, token *model.AgentToken) error
	GetAgentToken(ctx context.Context, tokenHash string) (*model.AgentToken, error)
	ListAgentTokens(ctx context.Context) ([]model.AgentToken, error)
	RevokeAgentToken(ctx context.Context, id string) error
	UpdateAgentTokenLastUsed(ctx context.Context, id string) error

	// Sweep queries (Layer 4.1)
	ListStaleAssetHealthRows(ctx context.Context, currentVersion, limit int) ([]StaleAssetRow, error)
	ListUnscoredAssets(ctx context.Context, limit int) ([]StaleAssetRow, error)

	// Repositories (Layer 6.1a + 6.1b-4 scheduler)
	UpsertRepository(ctx context.Context, r *model.Repository) error
	GetRepository(ctx context.Context, id string) (*model.Repository, error)
	FindRepositoryByURL(ctx context.Context, providerID, url string) (*model.Repository, error)
	ListRepositories(ctx context.Context, providerID string, limit, offset int) ([]model.Repository, error)
	DeleteRepository(ctx context.Context, id string) error
	ListScheduledRepos(ctx context.Context) ([]model.Repository, error)
	UpdateRepositoryLastScheduledAt(ctx context.Context, id string, when time.Time) error
	HasActiveScanJob(ctx context.Context, repoID string) (bool, error)

	// Lineage Links (Layer 6.1a)
	CreateLineageLink(ctx context.Context, l *model.LineageLink) error
	ListLineageFrom(ctx context.Context, fromAssetType, fromAssetID string) ([]model.LineageLink, error)
	ListLineageTo(ctx context.Context, toAssetType, toAssetID string) ([]model.LineageLink, error)
	CountLineageLinks(ctx context.Context) (int, error)

	// Providers (Layer 6.1b-1)
	UpsertProvider(ctx context.Context, p *model.Provider) error
	GetProvider(ctx context.Context, id string) (*model.Provider, error)
	FindProviderByKindURL(ctx context.Context, kind, baseURL string) (*model.Provider, error)
	ListProviders(ctx context.Context) ([]model.Provider, error)
	DeleteProvider(ctx context.Context, id string) error

	// Scan Jobs (Layer 6.1b-2 + 6.1b-4)
	EnqueueScanJob(ctx context.Context, j *model.ScanJob) error
	ClaimScanJob(ctx context.Context, workerID string) (*model.ScanJob, error)
	UpdateScanJob(ctx context.Context, j *model.ScanJob) error
	GetScanJob(ctx context.Context, id string) (*model.ScanJob, error)
	CancelScanJob(ctx context.Context, id string) error
	ListScanJobs(ctx context.Context, q ScanJobQuery) ([]model.ScanJob, error)
	ListRepositoryFindings(ctx context.Context, q RepoFindingQuery) ([]RepoFindingRow, error)

	// Repo Scan Cache (Layer 6.1b-2 + 6.1b-4 GC; asset_type discriminator added 6.2a)
	GetCacheEntry(ctx context.Context, blobSHA []byte, ruleVersion, promptHash, scanMode, assetType string) (*model.RepoScanCacheEntry, error)
	PutCacheEntry(ctx context.Context, e *model.RepoScanCacheEntry) error
	SweepCache(ctx context.Context, assetType, activeRuleVersion, activePromptContentHash string, olderThan time.Time) (int, error)

	// Multi-type search
	SearchMultiType(ctx context.Context, query string, limit int) (*MultiSearchResult, error)

	// Analytics
	GetLibraryDistribution(ctx context.Context) ([]LibraryDistItem, error)
	GetSSHKeyAnalytics(ctx context.Context) (*SSHKeyAnalytics, error)

	// Ingestion stats (used by config/sources handler)
	CountAssetsBySource(ctx context.Context, sourceName string) (int, error)
}
