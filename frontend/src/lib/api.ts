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

export interface CipherCount {
	suite: string;
	strength: string;
	count: number;
}

export interface TLSCipherRow {
	tls_version: string;
	strength: string;
	count: number;
}

export interface CipherStats {
	suite_distribution: CipherCount[];
	strength_distribution: Record<string, number>;
	tls_version_distribution: Record<string, number>;
	tls_cipher_matrix: TLSCipherRow[];
}

export interface KeyAlgoCount {
	algorithm: string;
	count: number;
}

export interface KeySizeCount {
	algorithm: string;
	size_bits: number;
	count: number;
}

export interface SigAlgoCount {
	algorithm: string;
	count: number;
}

export interface CryptoPostureResponse {
	key_algorithms: KeyAlgoCount[];
	key_sizes: KeySizeCount[];
	signature_algorithms: SigAlgoCount[];
	total_certs: number;
}

export interface ExpiryIssuerCount {
	issuer_org: string;
	count: number;
}

export interface ExpiryForecastBucket {
	week_start: string;
	total_count: number;
	by_issuer: ExpiryIssuerCount[];
	by_grade: Record<string, number>;
}

export interface ExpiryForecastResponse {
	buckets: ExpiryForecastBucket[];
	already_expired: number;
	total_expiring: number;
	top_issuers: string[];
}

export interface SourceLineageGroup {
	source: string;
	cert_count: number;
	expired_count: number;
	expiring_30d_count: number;
	grade_distribution: Record<string, number>;
	key_algorithms: Record<string, number>;
	avg_score: number;
	first_seen: string;
	last_seen: string;
}

export interface SourceLineageResponse {
	sources: SourceLineageGroup[];
	total_certs: number;
}

export interface GlobalSearchCert {
	fingerprint: string;
	subject_cn: string;
	subject_org: string;
	issuer_cn: string;
	key_algorithm: string;
	not_after: string;
	grade: string;
	source: string;
	match_field: string;
}

export interface GlobalSearchObs {
	cert_fingerprint: string;
	server_name: string;
	server_ip: string;
	server_port: number;
	tls_version: string;
	subject_cn: string;
}

export interface GlobalSearchResult {
	certificates: GlobalSearchCert[];
	observations: GlobalSearchObs[];
	total: number;
	query: string;
}

// ── Report Types ────────────────────────────────────────────────────────────

export interface DomainReportSummary {
	domain: string;
	total_certs: number;
	worst_grade: string;
	expired: number;
	expiring_30d: number;
	wildcard_count: number;
}

export interface DomainReportCert {
	fingerprint: string;
	subject_cn: string;
	issuer_cn: string;
	grade: string;
	key_algorithm: string;
	key_size_bits: number;
	not_after: string;
	days_remaining: number;
	first_seen: string;
	last_seen: string;
	match_type: string;
	source: string;
}

export interface DomainReportDeployment {
	cert_fingerprint: string;
	server_name: string;
	server_ip: string;
	server_port: number;
	tls_version: string;
	cipher: string;
	last_observed: string;
}

export interface DomainReportFinding {
	title: string;
	severity: string;
	category: string;
	affected_count: number;
	total_deduction: number;
}

export interface DomainReportWildcard {
	fingerprint: string;
	subject_cn: string;
	sans: string[];
	grade: string;
	not_after: string;
}

export interface DomainReport {
	summary: DomainReportSummary;
	certificates: DomainReportCert[];
	deployments: DomainReportDeployment[];
	findings: DomainReportFinding[];
	wildcards: DomainReportWildcard[];
}

export interface CAReportIdentity {
	fingerprint: string;
	subject_cn: string;
	organization: string;
	key_algorithm: string;
	key_size_bits: number;
	not_before: string;
	not_after: string;
	grade: string;
	is_self_signed: boolean;
	chain_position: string;
}

export interface CAReportSummary {
	total_issued: number;
	grade_distribution: Record<string, number>;
	expired: number;
	expiring_30d: number;
	expiring_90d: number;
	wildcard_count: number;
}

export interface CAReportCert {
	fingerprint: string;
	subject_cn: string;
	grade: string;
	key_algorithm: string;
	key_size_bits: number;
	not_after: string;
	days_remaining: number;
	first_seen: string;
	last_seen: string;
	source: string;
	is_wildcard: boolean;
}

export interface CAReportCrypto {
	key_algorithms: Record<string, number>;
	signature_algorithms: Record<string, number>;
	key_sizes: Record<string, number>;
}

export interface CAReportChainEntry {
	fingerprint: string;
	subject_cn: string;
	type: string;
}

export interface CAReportChain {
	issued_by: CAReportChainEntry | null;
	issues_to: CAReportChainEntry[];
}

export interface CAReport {
	ca: CAReportIdentity;
	summary: CAReportSummary;
	certificates: CAReportCert[];
	crypto: CAReportCrypto;
	chain: CAReportChain;
	findings: DomainReportFinding[];
}

export interface ComplianceReportIssue {
	fingerprint: string;
	subject_cn: string;
	grade: string;
	rule_id: string;
	title: string;
	severity: string;
	category: string;
	remediation: string;
}

export interface ComplianceReportPriority {
	rule_id: string;
	title: string;
	severity: string;
	affected_count: number;
	total_deduction: number;
	remediation: string;
}

export interface ComplianceReportNonAgile {
	fingerprint: string;
	subject_cn: string;
	issuer_cn: string;
	validity_days: number;
	key_algorithm: string;
	source: string;
}

export interface ComplianceReportWildcard {
	fingerprint: string;
	subject_cn: string;
	san_count: number;
	grade: string;
	not_after: string;
	issuer_cn: string;
}

export interface ComplianceReport {
	compliance_score: number;
	total_certs: number;
	compliant: number;
	non_compliant: number;
	critical_issues: ComplianceReportIssue[];
	remediation_priorities: ComplianceReportPriority[];
	non_agile: ComplianceReportNonAgile[];
	wildcards: ComplianceReportWildcard[];
	by_category: Record<string, number>;
}

export interface ExpiryReportCert {
	fingerprint: string;
	subject_cn: string;
	issuer_cn: string;
	grade: string;
	days_remaining: number;
	subject_org: string;
	subject_ou: string;
	key_algorithm: string;
	source: string;
	first_seen: string;
	last_seen: string;
}

export interface ExpiryReportByIssuer {
	issuer_org: string;
	count: number;
	worst_grade: string;
}

export interface ExpiryReportByOwner {
	subject_org: string;
	subject_ou: string;
	count: number;
}

export interface ExpiryReportGhost {
	fingerprint: string;
	subject_cn: string;
	issuer_cn: string;
	expired_days_ago: number;
	last_observed: string;
	server_name: string;
	server_ip: string;
}

export interface ExpiryReportDeployment {
	server_name: string;
	server_ip: string;
	server_port: number;
	cert_cn: string;
	days_remaining: number;
}

export interface ExpiryReport {
	days: number;
	total_expiring: number;
	certificates: ExpiryReportCert[];
	by_issuer: ExpiryReportByIssuer[];
	by_owner: ExpiryReportByOwner[];
	already_expired: ExpiryReportGhost[];
	deployments_at_risk: ExpiryReportDeployment[];
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
	getCiphers: () => fetchJSON<CipherStats>('/stats/ciphers'),
	getCryptoPosture: () => fetchJSON<CryptoPostureResponse>('/stats/crypto-posture'),
	getExpiryForecast: () => fetchJSON<ExpiryForecastResponse>('/stats/expiry-forecast'),
	getSourceLineage: () => fetchJSON<SourceLineageResponse>('/stats/source-lineage'),
	globalSearch: (q: string, limit = 20) => fetchJSON<GlobalSearchResult>(`/search?q=${encodeURIComponent(q)}&limit=${limit}`),
	getDomainReport: (domain: string) => fetchJSON<DomainReport>(`/reports/domain?q=${encodeURIComponent(domain)}`),
	getCAReport: (params: string) => fetchJSON<CAReport>(`/reports/ca?${params}`),
	getComplianceReport: () => fetchJSON<ComplianceReport>('/reports/compliance'),
	getExpiryReport: (days: number) => fetchJSON<ExpiryReport>(`/reports/expiry?days=${days}`),
	getVenafiStatus: () => fetchJSON<any>('/venafi/status'),
};
