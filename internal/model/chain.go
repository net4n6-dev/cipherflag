package model

type ChainNode struct {
	Certificate  *Certificate  `json:"certificate"`
	HealthReport *HealthReport `json:"health_report,omitempty"`
	Level        string        `json:"level"` // "Root", "Intermediate", "End Entity"
	Depth        int           `json:"depth"`
}

type ChainTree struct {
	Nodes            []ChainNode     `json:"nodes"`
	Fingerprints     []string        `json:"fingerprints"` // Ordered leaf → root
	IsComplete       bool            `json:"is_complete"`
	ValidationErrors []HealthFinding `json:"validation_errors,omitempty"`
}

// GraphNode is a Cytoscape.js-compatible node representation.
type GraphNode struct {
	Data GraphNodeData `json:"data"`
}

type GraphNodeData struct {
	ID                string  `json:"id"`
	Label             string  `json:"label"`
	NodeType          string  `json:"type"`               // "root", "intermediate", "leaf", "endpoint"
	Grade             Grade   `json:"grade,omitempty"`
	Score             int     `json:"score,omitempty"`
	Risk              string  `json:"risk"`                // "critical", "high", "medium", "low"
	KeyAlgorithm      string  `json:"key_algorithm,omitempty"`
	KeySizeBits       int     `json:"key_size_bits,omitempty"`
	DaysUntilExpiry   int     `json:"days_until_expiry,omitempty"`
	ObservationCount  int     `json:"observation_count,omitempty"`
	IsCA              bool    `json:"is_ca,omitempty"`
	Parent            string  `json:"parent,omitempty"`    // Compound node grouping
	Issuer            string  `json:"issuer,omitempty"`
	PulseRate         float64 `json:"pulse_rate,omitempty"` // Animation speed hint
	SizeWeight        float64 `json:"size_weight"`          // Node size multiplier
}

// GraphEdge is a Cytoscape.js-compatible edge representation.
type GraphEdge struct {
	Data GraphEdgeData `json:"data"`
}

type GraphEdgeData struct {
	ID     string  `json:"id"`
	Source string  `json:"source"`
	Target string  `json:"target"`
	Risk   string  `json:"risk"`       // Inherits child health
	Weight float64 `json:"weight"`     // Edge thickness
	Fresh  bool    `json:"fresh"`      // Recently observed
}

// GraphResponse is the API response for graph-oriented endpoints.
type GraphResponse struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// AggregatedGraphNode represents a CA with aggregate stats for the landscape view.
type AggregatedGraphNode struct {
	Fingerprint      string  `json:"fingerprint"`
	CommonName       string  `json:"common_name"`
	Organization     string  `json:"organization"`
	NodeType         string  `json:"type"`
	CertCount        int     `json:"cert_count"`
	WorstGrade       string  `json:"worst_grade"`
	AvgScore         float64 `json:"avg_score"`
	ExpiredCount     int     `json:"expired_count"`
	Expiring30dCount int     `json:"expiring_30d_count"`
	KeyAlgorithm     string  `json:"key_algorithm"`
	KeySizeBits      int     `json:"key_size_bits"`
}

// AggregatedGraphEdge represents a parent→child CA relationship.
type AggregatedGraphEdge struct {
	Source     string `json:"source"`
	Target     string `json:"target"`
	ChildGrade string `json:"child_grade"`
}

// AggregatedLandscapeResponse is the API response for the aggregated landscape.
type AggregatedLandscapeResponse struct {
	Nodes []AggregatedGraphNode `json:"nodes"`
	Edges []AggregatedGraphEdge `json:"edges"`
}

// CAChildrenResponse is the API response for a CA's direct children.
type CAChildrenResponse struct {
	ParentFingerprint string                `json:"parent_fingerprint"`
	Nodes             []AggregatedGraphNode `json:"nodes"`
	Edges             []AggregatedGraphEdge `json:"edges"`
	Total             int                   `json:"total"`
	HasMore           bool                  `json:"has_more"`
}

// BlastRadiusSummary holds aggregate stats for a blast radius query.
type BlastRadiusSummary struct {
	TotalCerts    int `json:"total_certs"`
	Expired       int `json:"expired"`
	Expiring30d   int `json:"expiring_30d"`
	GradeF        int `json:"grade_f"`
	Intermediates int `json:"intermediates"`
}

// BlastRadiusResponse is the API response for a CA's blast radius.
type BlastRadiusResponse struct {
	RootFingerprint string                `json:"root_fingerprint"`
	Nodes           []AggregatedGraphNode `json:"nodes"`
	Edges           []AggregatedGraphEdge `json:"edges"`
	Summary         BlastRadiusSummary    `json:"summary"`
	Truncated       bool                  `json:"truncated"`
}
