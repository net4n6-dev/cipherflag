const BASE = '/api/v1';

async function fetchJSON<T>(path: string): Promise<T> {
	const res = await fetch(`${BASE}${path}`);
	if (!res.ok) {
		throw new Error(`API error: ${res.status} ${res.statusText}`);
	}
	return res.json();
}

export interface GraphNode {
	data: {
		id: string;
		label: string;
		type: string;
		grade?: string;
		score?: number;
		risk: string;
		key_algorithm?: string;
		key_size_bits?: number;
		days_until_expiry?: number;
		observation_count?: number;
		is_ca?: boolean;
		parent?: string;
		issuer?: string;
		pulse_rate?: number;
		size_weight: number;
	};
}

export interface GraphEdge {
	data: {
		id: string;
		source: string;
		target: string;
		risk: string;
		weight: number;
		fresh: boolean;
	};
}

export interface GraphResponse {
	nodes: GraphNode[];
	edges: GraphEdge[];
}

export interface SummaryStats {
	total_certs: number;
	total_observations: number;
	grade_distribution: Record<string, number>;
	expiring_in_30_days: number;
	expiring_in_90_days: number;
	expired: number;
	total_findings: number;
	critical_findings: number;
	source_stats: Record<string, number>;
}

export interface Certificate {
	id: string;
	fingerprint_sha256: string;
	subject: { common_name: string; organization: string; full: string };
	issuer: { common_name: string; organization: string; full: string };
	not_before: string;
	not_after: string;
	key_algorithm: string;
	key_size_bits: number;
	signature_algorithm: string;
	subject_alt_names: string[];
	is_ca: boolean;
	source_discovery: string;
}

export interface HealthReport {
	cert_fingerprint: string;
	grade: string;
	score: number;
	findings: HealthFinding[];
	scored_at: string;
}

export interface HealthFinding {
	rule_id: string;
	title: string;
	severity: string;
	category: string;
	detail: string;
	remediation: string;
	deduction: number;
	immediate_fail?: boolean;
}

export interface CertDetail {
	certificate: Certificate;
	health_report: HealthReport | null;
}

export interface PKITreeNode {
	fingerprint: string;
	subject_cn: string;
	subject_org: string;
	country: string;
	key_algorithm: string;
	key_size_bits: number;
	grade: string;
	score: number;
	not_after: string;
	node_type: string;
	leaf_count: number;
	children?: PKITreeNode[];
}

export interface PKITreeResponse {
	roots: PKITreeNode[];
	orphan_count: number;
	total_cas: number;
	total_leaves: number;
}

export interface IssuerStat {
	issuer_cn: string;
	issuer_org: string;
	country: string;
	cert_count: number;
	avg_score: number;
	min_grade: string;
	expired_count: number;
}

export interface ExpiryBucket {
	week_start: string;
	count: number;
	expired: number;
	critical: number;
}

export interface ExpiryTimeline {
	buckets: ExpiryBucket[];
	total_certs: number;
	already_expired: number;
}

export interface CertSearchResult {
	certificates: Certificate[];
	total: number;
	page: number;
	page_size: number;
}

export interface ChainNode {
	certificate: Certificate;
	health_report: HealthReport | null;
	level: string;
	depth: number;
}

export interface ChainTree {
	nodes: ChainNode[];
	fingerprints: string[];
	is_complete: boolean;
	validation_errors: HealthFinding[];
}

export interface PCAPJob {
	id: string;
	filename: string;
	file_size: number;
	status: 'queued' | 'processing' | 'complete' | 'failed';
	certs_found: number;
	certs_new: number;
	error?: string;
	created_at: string;
	completed_at?: string;
}

export interface AggregatedGraphNode {
	fingerprint: string;
	common_name: string;
	organization: string;
	type: 'root' | 'intermediate' | 'leaf';
	cert_count: number;
	worst_grade: string;
	avg_score: number;
	expired_count: number;
	expiring_30d_count: number;
	key_algorithm: string;
	key_size_bits: number;
}

export interface AggregatedGraphEdge {
	source: string;
	target: string;
	child_grade: string;
}

export interface AggregatedLandscapeResponse {
	nodes: AggregatedGraphNode[];
	edges: AggregatedGraphEdge[];
}

export interface CAChildrenResponse {
	parent_fingerprint: string;
	nodes: AggregatedGraphNode[];
	edges: AggregatedGraphEdge[];
	total: number;
	has_more: boolean;
}

export interface BlastRadiusSummary {
	total_certs: number;
	expired: number;
	expiring_30d: number;
	grade_f: number;
	intermediates: number;
}

export interface BlastRadiusResponse {
	root_fingerprint: string;
	nodes: AggregatedGraphNode[];
	edges: AggregatedGraphEdge[];
	summary: BlastRadiusSummary;
	truncated: boolean;
}

export interface ChainFlowNode {
	id: string;
	label: string;
	type: 'root' | 'intermediate' | 'leaf-aggregate';
	cert_count: number;
	grade: string;
	expired_count: number;
}

export interface ChainFlowLink {
	source: string;
	target: string;
	value: number;
	worst_grade: string;
	expired_count: number;
}

export interface ChainFlowResponse {
	nodes: ChainFlowNode[];
	links: ChainFlowLink[];
}

export interface OwnershipGroup {
	issuer_org: string;
	subject_ou: string;
	cert_count: number;
	expired_count: number;
	expiring_30d_count: number;
	worst_grade: string;
	avg_score: number;
}

export interface OwnershipResponse {
	groups: OwnershipGroup[];
	total_certs: number;
	total_issuers: number;
	total_ous: number;
}

export interface DeploymentGroup {
	domain: string;
	cert_count: number;
	unique_ips: number;
	expired_count: number;
	worst_grade: string;
	avg_score: number;
}

export interface DeploymentResponse {
	groups: DeploymentGroup[];
	total_observed_certs: number;
	total_domains: number;
}

export const api = {
	getLandscape: () => fetchJSON<GraphResponse>('/graph/landscape'),
	getChainGraph: (fp: string) => fetchJSON<GraphResponse>(`/graph/chain/${fp}`),
	getSummary: () => fetchJSON<SummaryStats>('/stats/summary'),
	getCert: (fp: string) => fetchJSON<CertDetail>(`/certificates/${fp}`),
	getHealth: (fp: string) => fetchJSON<HealthReport>(`/certificates/${fp}/health`),
	getChain: (fp: string) => fetchJSON<ChainTree>(`/certificates/${fp}/chain`),
	getPKITree: () => fetchJSON<PKITreeResponse>('/pki/tree'),
	getIssuers: () => fetchJSON<{ issuers: IssuerStat[] }>('/stats/issuers'),
	getExpiryTimeline: () => fetchJSON<ExpiryTimeline>('/stats/expiry-timeline'),
	searchCerts: (params: string) => fetchJSON<CertSearchResult>(`/certificates?${params}`),
	getPCAPJob: (id: string) => fetchJSON<PCAPJob>(`/pcap/jobs/${id}`),
	listPCAPJobs: () => fetchJSON<{ jobs: PCAPJob[] }>('/pcap/jobs'),
	uploadPCAP: async (file: File): Promise<PCAPJob> => {
		const formData = new FormData();
		formData.append('file', file);
		const res = await fetch(`${BASE}/pcap/upload`, { method: 'POST', body: formData });
		if (!res.ok) throw new Error(`Upload failed: ${res.status}`);
		return res.json();
	},
	exportCerts: (format: 'csv' | 'json', params?: string) => {
		window.open(`${BASE}/export/certificates?format=${format}${params ? '&' + params : ''}`);
	},
	getAggregatedLandscape: () => fetchJSON<AggregatedLandscapeResponse>('/graph/landscape/aggregated'),
	getCAChildren: (fp: string, limit = 100, offset = 0) =>
		fetchJSON<CAChildrenResponse>(`/graph/ca/${fp}/children?limit=${limit}&offset=${offset}`),
	getBlastRadius: (fp: string) => fetchJSON<BlastRadiusResponse>(`/graph/ca/${fp}/blast-radius`),
	getChainFlow: () => fetchJSON<ChainFlowResponse>('/stats/chain-flow'),
	getOwnership: () => fetchJSON<OwnershipResponse>('/stats/ownership'),
	getDeployment: () => fetchJSON<DeploymentResponse>('/stats/deployment'),
};
