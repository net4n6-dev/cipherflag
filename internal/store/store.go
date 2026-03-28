package store

import (
	"context"
	"time"

	"github.com/cyberflag-ai/cipherflag/internal/model"
)

// CertSearchQuery defines search/filter/pagination for certificate listing.
type CertSearchQuery struct {
	Search        string // Full-text search across CN, SANs, fingerprint, org
	Grade         string // Filter by grade (e.g., "F", "D,F")
	Source        string // Filter by discovery source
	IssuerCN      string // Filter by issuer common name
	SubjectOU     string // Filter by subject organizational unit
	IssuerOrg     string // Filter by issuer organization
	KeyAlgorithm  string // Filter by key algorithm (RSA, ECDSA, Ed25519)
	SignatureAlgo string // Filter by signature algorithm
	ServerName    string // Filter by observed server name (joins observations)
	IsCA          *bool  // Filter CA certs
	Expired  *bool  // Filter expired only
	ExpiringWithinDays *int // Filter certs expiring within N days
	SortBy   string // "expiry", "grade", "cn", "last_seen"
	SortDir  string // "asc", "desc"
	Page     int
	PageSize int
}

// CertSearchResult is a paginated result from SearchCertificates.
type CertSearchResult struct {
	Certificates []model.Certificate `json:"certificates"`
	Total        int                 `json:"total"`
	Page         int                 `json:"page"`
	PageSize     int                 `json:"page_size"`
}

// SummaryStats holds dashboard aggregate statistics.
type SummaryStats struct {
	TotalCerts         int            `json:"total_certs"`
	TotalObservations  int            `json:"total_observations"`
	GradeDistribution  map[string]int `json:"grade_distribution"`
	ExpiringIn30Days   int            `json:"expiring_in_30_days"`
	ExpiringIn90Days   int            `json:"expiring_in_90_days"`
	Expired            int            `json:"expired"`
	TotalFindings      int            `json:"total_findings"`
	CriticalFindings   int            `json:"critical_findings"`
	SourceStats        map[string]int `json:"source_stats"`
}

// CipherStats holds cipher suite analytics.
type CipherStats struct {
	SuiteDistribution    []CipherCount   `json:"suite_distribution"`
	StrengthDistribution map[string]int  `json:"strength_distribution"`
	TLSVersionDist       map[string]int  `json:"tls_version_distribution"`
	TLSCipherMatrix      []TLSCipherRow  `json:"tls_cipher_matrix"`
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
	Fingerprint   string         `json:"fingerprint"`
	SubjectCN     string         `json:"subject_cn"`
	SubjectOrg    string         `json:"subject_org"`
	Country       string         `json:"country"`
	KeyAlgorithm  string         `json:"key_algorithm"`
	KeySizeBits   int            `json:"key_size_bits"`
	Grade         string         `json:"grade"`
	Score         int            `json:"score"`
	NotAfter      string         `json:"not_after"`
	NodeType      string         `json:"node_type"` // "root" or "intermediate"
	LeafCount     int            `json:"leaf_count"`
	Children      []PKITreeNode  `json:"children,omitempty"`
}

// PKITreeResponse is the full PKI hierarchy.
type PKITreeResponse struct {
	Roots          []PKITreeNode `json:"roots"`
	OrphanCount    int           `json:"orphan_count"`
	TotalCAs       int           `json:"total_cas"`
	TotalLeaves    int           `json:"total_leaves"`
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
	Buckets     []ExpiryBucket `json:"buckets"`
	TotalCerts  int            `json:"total_certs"`
	AlreadyExpired int         `json:"already_expired"`
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

	// PCAP Jobs
	CreatePCAPJob(ctx context.Context, job *model.PCAPJob) error
	GetPCAPJob(ctx context.Context, id string) (*model.PCAPJob, error)
	UpdatePCAPJob(ctx context.Context, job *model.PCAPJob) error
	ListPCAPJobs(ctx context.Context, limit int) ([]model.PCAPJob, error)

	// Venafi push
	GetCertsForVenafiPush(ctx context.Context, pushInterval time.Duration, limit int) ([]model.Certificate, error)
	GetLatestObservationsForCerts(ctx context.Context, fingerprints []string) (map[string]*model.CertificateObservation, error)
	MarkVenafiPushSuccess(ctx context.Context, fingerprints []string) error
	MarkVenafiPushFailure(ctx context.Context, fingerprints []string) error
	GetVenafiPushStats(ctx context.Context) (*model.VenafiPushStats, error)

	// Global search
	GlobalSearch(ctx context.Context, query string, limit int) (*model.GlobalSearchResult, error)

	// Lifecycle
	Migrate(ctx context.Context) error
	Close() error
}
