package model

// ChainFlowNode represents a node in the Sankey chain flow diagram.
type ChainFlowNode struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	NodeType     string `json:"type"`
	CertCount    int    `json:"cert_count"`
	Grade        string `json:"grade"`
	ExpiredCount int    `json:"expired_count"`
}

// ChainFlowLink represents a link in the Sankey chain flow diagram.
type ChainFlowLink struct {
	Source       string `json:"source"`
	Target       string `json:"target"`
	Value        int    `json:"value"`
	WorstGrade   string `json:"worst_grade"`
	ExpiredCount int    `json:"expired_count"`
}

// ChainFlowResponse is the API response for the chain flow Sankey.
type ChainFlowResponse struct {
	Nodes []ChainFlowNode `json:"nodes"`
	Links []ChainFlowLink `json:"links"`
}

// OwnershipGroup represents a grouping of certs by issuer org + subject OU.
type OwnershipGroup struct {
	IssuerOrg        string  `json:"issuer_org"`
	SubjectOU        string  `json:"subject_ou"`
	CertCount        int     `json:"cert_count"`
	ExpiredCount     int     `json:"expired_count"`
	Expiring30dCount int     `json:"expiring_30d_count"`
	WorstGrade       string  `json:"worst_grade"`
	AvgScore         float64 `json:"avg_score"`
}

// OwnershipResponse is the API response for ownership analytics.
type OwnershipResponse struct {
	Groups       []OwnershipGroup `json:"groups"`
	TotalCerts   int              `json:"total_certs"`
	TotalIssuers int              `json:"total_issuers"`
	TotalOUs     int              `json:"total_ous"`
}

// DeploymentGroup represents a grouping of certs by observed domain.
type DeploymentGroup struct {
	Domain       string  `json:"domain"`
	CertCount    int     `json:"cert_count"`
	UniqueIPs    int     `json:"unique_ips"`
	ExpiredCount int     `json:"expired_count"`
	WorstGrade   string  `json:"worst_grade"`
	AvgScore     float64 `json:"avg_score"`
}

// DeploymentResponse is the API response for deployment analytics.
type DeploymentResponse struct {
	Groups             []DeploymentGroup `json:"groups"`
	TotalObservedCerts int               `json:"total_observed_certs"`
	TotalDomains       int               `json:"total_domains"`
}

// CryptoPostureResponse is the API response for crypto posture analytics.
type CryptoPostureResponse struct {
	KeyAlgorithms       []KeyAlgoCount   `json:"key_algorithms"`
	KeySizes            []KeySizeCount   `json:"key_sizes"`
	SignatureAlgorithms []SigAlgoCount   `json:"signature_algorithms"`
	TotalCerts          int              `json:"total_certs"`
}

// KeyAlgoCount holds key algorithm distribution.
type KeyAlgoCount struct {
	Algorithm string `json:"algorithm"`
	Count     int    `json:"count"`
}

// KeySizeCount holds key size distribution.
type KeySizeCount struct {
	Algorithm string `json:"algorithm"`
	SizeBits  int    `json:"size_bits"`
	Count     int    `json:"count"`
}

// SigAlgoCount holds signature algorithm distribution.
type SigAlgoCount struct {
	Algorithm string `json:"algorithm"`
	Count     int    `json:"count"`
}
