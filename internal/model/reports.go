package model

// ── Domain Report ───────────────────────────────────────────────────────────

type DomainReportSummary struct {
	Domain        string `json:"domain"`
	TotalCerts    int    `json:"total_certs"`
	WorstGrade    string `json:"worst_grade"`
	Expired       int    `json:"expired"`
	Expiring30d   int    `json:"expiring_30d"`
	WildcardCount int    `json:"wildcard_count"`
}

type DomainReportCert struct {
	Fingerprint   string `json:"fingerprint"`
	SubjectCN     string `json:"subject_cn"`
	IssuerCN      string `json:"issuer_cn"`
	Grade         string `json:"grade"`
	KeyAlgorithm  string `json:"key_algorithm"`
	KeySizeBits   int    `json:"key_size_bits"`
	NotAfter      string `json:"not_after"`
	DaysRemaining int    `json:"days_remaining"`
	FirstSeen     string `json:"first_seen"`
	LastSeen      string `json:"last_seen"`
	MatchType     string `json:"match_type"`
	Source        string `json:"source"`
}

type DomainReportDeployment struct {
	CertFingerprint string `json:"cert_fingerprint"`
	ServerName      string `json:"server_name"`
	ServerIP        string `json:"server_ip"`
	ServerPort      int    `json:"server_port"`
	TLSVersion      string `json:"tls_version"`
	Cipher          string `json:"cipher"`
	LastObserved    string `json:"last_observed"`
}

type DomainReportFinding struct {
	Title          string `json:"title"`
	Severity       string `json:"severity"`
	Category       string `json:"category"`
	AffectedCount  int    `json:"affected_count"`
	TotalDeduction int    `json:"total_deduction"`
}

type DomainReportWildcard struct {
	Fingerprint string   `json:"fingerprint"`
	SubjectCN   string   `json:"subject_cn"`
	SANs        []string `json:"sans"`
	Grade       string   `json:"grade"`
	NotAfter    string   `json:"not_after"`
}

type DomainReport struct {
	Summary      DomainReportSummary      `json:"summary"`
	Certificates []DomainReportCert       `json:"certificates"`
	Deployments  []DomainReportDeployment `json:"deployments"`
	Findings     []DomainReportFinding    `json:"findings"`
	Wildcards    []DomainReportWildcard   `json:"wildcards"`
}

// ── CA Report ───────────────────────────────────────────────────────────────

type CAReportIdentity struct {
	Fingerprint  string `json:"fingerprint"`
	SubjectCN    string `json:"subject_cn"`
	Organization string `json:"organization"`
	KeyAlgorithm string `json:"key_algorithm"`
	KeySizeBits  int    `json:"key_size_bits"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	Grade        string `json:"grade"`
	IsSelfSigned bool   `json:"is_self_signed"`
	ChainPosition string `json:"chain_position"`
}

type CAReportSummary struct {
	TotalIssued       int            `json:"total_issued"`
	GradeDistribution map[string]int `json:"grade_distribution"`
	Expired           int            `json:"expired"`
	Expiring30d       int            `json:"expiring_30d"`
	Expiring90d       int            `json:"expiring_90d"`
	WildcardCount     int            `json:"wildcard_count"`
}

type CAReportCert struct {
	Fingerprint   string `json:"fingerprint"`
	SubjectCN     string `json:"subject_cn"`
	Grade         string `json:"grade"`
	KeyAlgorithm  string `json:"key_algorithm"`
	KeySizeBits   int    `json:"key_size_bits"`
	NotAfter      string `json:"not_after"`
	DaysRemaining int    `json:"days_remaining"`
	FirstSeen     string `json:"first_seen"`
	LastSeen      string `json:"last_seen"`
	Source        string `json:"source"`
	IsWildcard    bool   `json:"is_wildcard"`
}

type CAReportCrypto struct {
	KeyAlgorithms      map[string]int `json:"key_algorithms"`
	SignatureAlgorithms map[string]int `json:"signature_algorithms"`
	KeySizes           map[string]int `json:"key_sizes"`
}

type CAReportChainEntry struct {
	Fingerprint string `json:"fingerprint"`
	SubjectCN   string `json:"subject_cn"`
	NodeType    string `json:"type"`
}

type CAReportChain struct {
	IssuedBy *CAReportChainEntry  `json:"issued_by"`
	IssuesTo []CAReportChainEntry `json:"issues_to"`
}

type CAReport struct {
	CA           CAReportIdentity      `json:"ca"`
	Summary      CAReportSummary       `json:"summary"`
	Certificates []CAReportCert        `json:"certificates"`
	Crypto       CAReportCrypto        `json:"crypto"`
	Chain        CAReportChain         `json:"chain"`
	Findings     []DomainReportFinding `json:"findings"`
}

// ── Compliance Report ───────────────────────────────────────────────────────

type ComplianceReportIssue struct {
	Fingerprint string `json:"fingerprint"`
	SubjectCN   string `json:"subject_cn"`
	Grade       string `json:"grade"`
	RuleID      string `json:"rule_id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Remediation string `json:"remediation"`
}

type ComplianceReportPriority struct {
	RuleID         string `json:"rule_id"`
	Title          string `json:"title"`
	Severity       string `json:"severity"`
	AffectedCount  int    `json:"affected_count"`
	TotalDeduction int    `json:"total_deduction"`
	Remediation    string `json:"remediation"`
}

type ComplianceReportNonAgile struct {
	Fingerprint  string `json:"fingerprint"`
	SubjectCN    string `json:"subject_cn"`
	IssuerCN     string `json:"issuer_cn"`
	ValidityDays int    `json:"validity_days"`
	KeyAlgorithm string `json:"key_algorithm"`
	Source       string `json:"source"`
}

type ComplianceReportWildcard struct {
	Fingerprint string `json:"fingerprint"`
	SubjectCN   string `json:"subject_cn"`
	SANCount    int    `json:"san_count"`
	Grade       string `json:"grade"`
	NotAfter    string `json:"not_after"`
	IssuerCN    string `json:"issuer_cn"`
}

type ComplianceReport struct {
	ComplianceScore float64                    `json:"compliance_score"`
	TotalCerts      int                        `json:"total_certs"`
	Compliant       int                        `json:"compliant"`
	NonCompliant    int                        `json:"non_compliant"`
	CriticalIssues  []ComplianceReportIssue    `json:"critical_issues"`
	Priorities      []ComplianceReportPriority `json:"remediation_priorities"`
	NonAgile        []ComplianceReportNonAgile `json:"non_agile"`
	Wildcards       []ComplianceReportWildcard `json:"wildcards"`
	ByCategory      map[string]int             `json:"by_category"`
}

// ── Expiry Risk Report ──────────────────────────────────────────────────────

type ExpiryReportCert struct {
	Fingerprint   string `json:"fingerprint"`
	SubjectCN     string `json:"subject_cn"`
	IssuerCN      string `json:"issuer_cn"`
	Grade         string `json:"grade"`
	DaysRemaining int    `json:"days_remaining"`
	SubjectOrg    string `json:"subject_org"`
	SubjectOU     string `json:"subject_ou"`
	KeyAlgorithm  string `json:"key_algorithm"`
	Source        string `json:"source"`
	FirstSeen     string `json:"first_seen"`
	LastSeen      string `json:"last_seen"`
}

type ExpiryReportByIssuer struct {
	IssuerOrg  string `json:"issuer_org"`
	Count      int    `json:"count"`
	WorstGrade string `json:"worst_grade"`
}

type ExpiryReportByOwner struct {
	SubjectOrg string `json:"subject_org"`
	SubjectOU  string `json:"subject_ou"`
	Count      int    `json:"count"`
}

type ExpiryReportGhost struct {
	Fingerprint    string `json:"fingerprint"`
	SubjectCN      string `json:"subject_cn"`
	IssuerCN       string `json:"issuer_cn"`
	ExpiredDaysAgo int    `json:"expired_days_ago"`
	LastObserved   string `json:"last_observed"`
	ServerName     string `json:"server_name"`
	ServerIP       string `json:"server_ip"`
}

type ExpiryReportDeployment struct {
	ServerName    string `json:"server_name"`
	ServerIP      string `json:"server_ip"`
	ServerPort    int    `json:"server_port"`
	CertCN        string `json:"cert_cn"`
	DaysRemaining int    `json:"days_remaining"`
}

type ExpiryReport struct {
	Days              int                      `json:"days"`
	TotalExpiring     int                      `json:"total_expiring"`
	Certificates      []ExpiryReportCert       `json:"certificates"`
	ByIssuer          []ExpiryReportByIssuer   `json:"by_issuer"`
	ByOwner           []ExpiryReportByOwner    `json:"by_owner"`
	AlreadyExpired    []ExpiryReportGhost      `json:"already_expired"`
	DeploymentsAtRisk []ExpiryReportDeployment `json:"deployments_at_risk"`
}
