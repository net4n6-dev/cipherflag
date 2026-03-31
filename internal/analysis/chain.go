package analysis

import (
	"fmt"
	"math"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// BuildGraphData transforms a slice of certificates and their health reports
// into Cytoscape.js-compatible graph elements for the landscape view.
func BuildGraphData(certs []model.Certificate, reports map[string]*model.HealthReport) *model.GraphResponse {
	resp := &model.GraphResponse{
		Nodes: []model.GraphNode{},
		Edges: []model.GraphEdge{},
	}

	// Index certs by subject CN for parent lookups (more reliable than Full DN)
	certBySubjectCN := make(map[string]*model.Certificate)
	for i := range certs {
		if certs[i].IsCA {
			certBySubjectCN[certs[i].Subject.CommonName] = &certs[i]
		}
	}

	// Track issuer compound groups for Cytoscape compound nodes
	issuerGroups := make(map[string]bool)

	for _, cert := range certs {
		report := reports[cert.FingerprintSHA256]

		nodeType := classifyNode(&cert)
		risk := "low"
		grade := model.GradeAPlus
		score := 100

		if report != nil {
			grade = report.Grade
			score = report.Score
			risk = gradeToRisk(report.Grade)
		}

		days := cert.DaysUntilExpiry()
		pulseRate := calcPulseRate(days)
		sizeWeight := calcSizeWeight(&cert, report)

		// Determine parent compound node (issuer org group)
		parentID := ""
		if cert.Issuer.Organization != "" && !cert.IsSelfSigned() {
			parentID = "group-" + sanitizeID(cert.Issuer.Organization)
			issuerGroups[parentID] = true
		}

		label := cert.Subject.CommonName
		if label == "" {
			label = cert.FingerprintSHA256[:12]
		}

		node := model.GraphNode{
			Data: model.GraphNodeData{
				ID:               cert.FingerprintSHA256,
				Label:            label,
				NodeType:         nodeType,
				Grade:            grade,
				Score:            score,
				Risk:             risk,
				KeyAlgorithm:     string(cert.KeyAlgorithm),
				KeySizeBits:      cert.KeySizeBits,
				DaysUntilExpiry:  days,
				IsCA:             cert.IsCA,
				Parent:           parentID,
				Issuer:           cert.Issuer.Full,
				PulseRate:        pulseRate,
				SizeWeight:       sizeWeight,
			},
		}
		resp.Nodes = append(resp.Nodes, node)

		// Create edge from this cert to its issuer (if issuer exists in our dataset)
		if !cert.IsSelfSigned() {
			issuerCert := certBySubjectCN[cert.Issuer.CommonName]
			if issuerCert != nil {
				edgeRisk := risk
				fresh := time.Since(cert.LastSeen) < 7*24*time.Hour

				edge := model.GraphEdge{
					Data: model.GraphEdgeData{
						ID:     fmt.Sprintf("e-%s-%s", cert.FingerprintSHA256[:8], issuerCert.FingerprintSHA256[:8]),
						Source: cert.FingerprintSHA256,
						Target: issuerCert.FingerprintSHA256,
						Risk:   edgeRisk,
						Weight: edgeWeight(report),
						Fresh:  fresh,
					},
				}
				resp.Edges = append(resp.Edges, edge)
			}
		}
	}

	// Add compound group nodes for issuers
	for groupID := range issuerGroups {
		orgName := groupID[6:] // strip "group-" prefix
		resp.Nodes = append(resp.Nodes, model.GraphNode{
			Data: model.GraphNodeData{
				ID:         groupID,
				Label:      orgName,
				NodeType:   "group",
				SizeWeight: 1,
			},
		})
	}

	return resp
}

// BuildChainTree builds a chain tree starting from a leaf certificate.
func BuildChainTree(leaf *model.Certificate, allCerts []model.Certificate, reports map[string]*model.HealthReport) *model.ChainTree {
	tree := &model.ChainTree{
		Nodes:        []model.ChainNode{},
		Fingerprints: []string{},
		IsComplete:   false,
	}

	visited := make(map[string]bool)
	current := leaf
	depth := 0

	// Build lookup by subject CN (primary) — more reliable than Full DN
	certBySubjectCN := make(map[string][]*model.Certificate)
	for i := range allCerts {
		cn := allCerts[i].Subject.CommonName
		certBySubjectCN[cn] = append(certBySubjectCN[cn], &allCerts[i])
	}

	findIssuer := func(cert *model.Certificate) *model.Certificate {
		candidates := certBySubjectCN[cert.Issuer.CommonName]
		if len(candidates) == 1 {
			return candidates[0]
		}
		// Multiple CAs with same CN — prefer matching org
		for _, c := range candidates {
			if c.IsCA && c.Subject.Organization == cert.Issuer.Organization {
				return c
			}
		}
		// Fallback: any CA with that CN
		for _, c := range candidates {
			if c.IsCA {
				return c
			}
		}
		if len(candidates) > 0 {
			return candidates[0]
		}
		return nil
	}

	for current != nil && !visited[current.FingerprintSHA256] {
		visited[current.FingerprintSHA256] = true

		level := "End Entity"
		if current.IsCA && current.IsSelfSigned() {
			level = "Root"
		} else if current.IsCA {
			level = "Intermediate"
		}

		node := model.ChainNode{
			Certificate:  current,
			HealthReport: reports[current.FingerprintSHA256],
			Level:        level,
			Depth:        depth,
		}
		tree.Nodes = append(tree.Nodes, node)
		tree.Fingerprints = append(tree.Fingerprints, current.FingerprintSHA256)

		if current.IsSelfSigned() {
			tree.IsComplete = true
			break
		}

		current = findIssuer(current)
		depth++
	}

	return tree
}

// BuildChainGraphData converts a ChainTree into Cytoscape.js elements for the chain view.
// Unlike BuildGraphData, this creates direct edges based on the chain walk order
// and omits compound group nodes.
func BuildChainGraphData(tree *model.ChainTree) *model.GraphResponse {
	resp := &model.GraphResponse{
		Nodes: []model.GraphNode{},
		Edges: []model.GraphEdge{},
	}

	for _, cn := range tree.Nodes {
		cert := cn.Certificate
		report := cn.HealthReport

		nodeType := classifyNode(cert)
		risk := "low"
		grade := model.GradeAPlus
		score := 100

		if report != nil {
			grade = report.Grade
			score = report.Score
			risk = gradeToRisk(report.Grade)
		}

		label := cert.Subject.CommonName
		if label == "" {
			label = cert.FingerprintSHA256[:12]
		}

		resp.Nodes = append(resp.Nodes, model.GraphNode{
			Data: model.GraphNodeData{
				ID:              cert.FingerprintSHA256,
				Label:           label,
				NodeType:        nodeType,
				Grade:           grade,
				Score:           score,
				Risk:            risk,
				KeyAlgorithm:    string(cert.KeyAlgorithm),
				KeySizeBits:     cert.KeySizeBits,
				DaysUntilExpiry: cert.DaysUntilExpiry(),
				IsCA:            cert.IsCA,
				Issuer:          cert.Issuer.CommonName,
				SizeWeight:      calcSizeWeight(cert, report),
			},
		})
	}

	// Create edges between consecutive chain nodes (child → parent)
	for i := 0; i < len(tree.Fingerprints)-1; i++ {
		resp.Edges = append(resp.Edges, model.GraphEdge{
			Data: model.GraphEdgeData{
				ID:     fmt.Sprintf("chain-%d", i),
				Source: tree.Fingerprints[i],
				Target: tree.Fingerprints[i+1],
				Risk:   "low",
				Weight: 2,
				Fresh:  true,
			},
		})
	}

	return resp
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func classifyNode(cert *model.Certificate) string {
	if cert.IsCA && cert.IsSelfSigned() {
		return "root"
	}
	if cert.IsCA {
		return "intermediate"
	}
	return "leaf"
}

func gradeToRisk(grade model.Grade) string {
	switch grade {
	case model.GradeF:
		return "critical"
	case model.GradeD:
		return "high"
	case model.GradeC:
		return "medium"
	default:
		return "low"
	}
}

func calcPulseRate(daysUntilExpiry int) float64 {
	if daysUntilExpiry < 0 {
		return 3.0 // Expired: fast pulse
	}
	if daysUntilExpiry < 7 {
		return 2.5
	}
	if daysUntilExpiry < 30 {
		return 1.5
	}
	if daysUntilExpiry < 90 {
		return 0.8
	}
	return 0.0 // Healthy: no pulse
}

func calcSizeWeight(cert *model.Certificate, report *model.HealthReport) float64 {
	base := 1.0
	if cert.IsCA {
		base = 2.0
		if cert.IsSelfSigned() {
			base = 3.0
		}
	}
	// Boost for poor health
	if report != nil && report.Score < 50 {
		base *= 1.5
	}
	return math.Min(base, 4.0)
}

func edgeWeight(report *model.HealthReport) float64 {
	if report == nil {
		return 1.0
	}
	if report.Score < 50 {
		return 3.0
	}
	if report.Score < 70 {
		return 2.0
	}
	return 1.0
}

func sanitizeID(s string) string {
	out := make([]byte, 0, len(s))
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			out = append(out, byte(c))
		} else {
			out = append(out, '_')
		}
	}
	return string(out)
}
