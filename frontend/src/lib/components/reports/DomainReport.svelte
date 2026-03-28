<script lang="ts">
	import { onMount } from 'svelte';
	import { api } from '$lib/api';
	import type { DomainReport } from '$lib/api';
	import ReportToolbar from './ReportToolbar.svelte';
	import { gradeColor, severityColor, exportCSV } from './report-types';

	interface Props {
		domain: string;
	}

	let { domain }: Props = $props();

	let report = $state<DomainReport | null>(null);
	let loading = $state(true);
	let error = $state<string | null>(null);

	onMount(async () => {
		try {
			report = await api.getDomainReport(domain);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load domain report';
		}
		loading = false;
	});

	let sortedCerts = $derived(
		report?.certificates
			? [...report.certificates].sort((a, b) => a.days_remaining - b.days_remaining)
			: []
	);

	let sortedFindings = $derived(
		report?.findings
			? [...report.findings].sort((a, b) => {
					const order: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
					return (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
				})
			: []
	);

	function daysColor(days: number): string {
		if (days < 30) return '#ef4444';
		if (days < 90) return '#eab308';
		return 'var(--cf-text-primary)';
	}

	function handleExportCSV() {
		if (!report) return;
		const headers = ['Grade', 'CN', 'Issuer', 'Key Algo', 'Not After', 'Days Remaining', 'Match Type', 'Source', 'First Seen', 'Last Seen'];
		const rows = sortedCerts.map(c => [
			c.grade, c.subject_cn, c.issuer_cn, c.key_algorithm,
			c.not_after, String(c.days_remaining), c.match_type, c.source,
			c.first_seen, c.last_seen
		]);
		exportCSV(headers, rows, `domain-report-${domain}.csv`);
	}

	function handlePrint() {
		window.print();
	}
</script>

{#if loading}
	<div class="report-loading">Loading domain report...</div>
{:else if error}
	<div class="report-error">{error}</div>
{:else if report}
	<ReportToolbar title="Domain Report: {domain}" onPrint={handlePrint} onExportCSV={handleExportCSV} />

	<div class="report-content">
		<!-- 1. Summary Header -->
		<section class="report-section">
			<div class="stat-cards">
				<div class="stat-card">
					<span class="stat-label">Domain</span>
					<span class="stat-value mono">{report.summary.domain}</span>
				</div>
				<div class="stat-card">
					<span class="stat-label">Total Certificates</span>
					<span class="stat-value">{report.summary.total_certs}</span>
				</div>
				<div class="stat-card">
					<span class="stat-label">Worst Grade</span>
					<span class="stat-value" style:color={gradeColor(report.summary.worst_grade)}>{report.summary.worst_grade}</span>
				</div>
				<div class="stat-card">
					<span class="stat-label">Expired</span>
					<span class="stat-value" style:color={report.summary.expired > 0 ? '#ef4444' : 'var(--cf-text-primary)'}>{report.summary.expired}</span>
				</div>
				<div class="stat-card">
					<span class="stat-label">Expiring &lt;30d</span>
					<span class="stat-value" style:color={report.summary.expiring_30d > 0 ? '#eab308' : 'var(--cf-text-primary)'}>{report.summary.expiring_30d}</span>
				</div>
				<div class="stat-card">
					<span class="stat-label">Wildcards</span>
					<span class="stat-value">{report.summary.wildcard_count}</span>
				</div>
			</div>
		</section>

		<!-- 2. Certificates Table -->
		<section class="report-section">
			<h3>Certificates</h3>
			<div class="table-wrap">
				<table>
					<thead>
						<tr>
							<th>Grade</th>
							<th>CN</th>
							<th>Issuer</th>
							<th>Key Algo</th>
							<th>Not After</th>
							<th>Days Remaining</th>
							<th>Match Type</th>
							<th>Source</th>
							<th>First Seen</th>
							<th>Last Seen</th>
						</tr>
					</thead>
					<tbody>
						{#each sortedCerts as cert}
							<tr>
								<td><span class="grade-badge" style:color={gradeColor(cert.grade)}>{cert.grade}</span></td>
								<td class="mono"><a href="/certificates/{cert.fingerprint}" class="cert-link">{cert.subject_cn}</a></td>
								<td>{cert.issuer_cn}</td>
								<td class="mono">{cert.key_algorithm}</td>
								<td>{new Date(cert.not_after).toLocaleDateString()}</td>
								<td style:color={daysColor(cert.days_remaining)} style:font-weight="600">{cert.days_remaining}d</td>
								<td><span class="badge">{cert.match_type}</span></td>
								<td>{cert.source}</td>
								<td>{new Date(cert.first_seen).toLocaleDateString()}</td>
								<td>{new Date(cert.last_seen).toLocaleDateString()}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		</section>

		<!-- 3. Deployments -->
		<section class="report-section">
			<h3>Deployments</h3>
			{#if report.deployments.length === 0}
				<p class="empty-note">No deployment data — certificates discovered via passive scanning will show endpoint details.</p>
			{:else}
				<div class="table-wrap">
					<table>
						<thead>
							<tr>
								<th>Server Name</th>
								<th>Server IP</th>
								<th>Port</th>
								<th>TLS Version</th>
								<th>Cipher</th>
								<th>Last Observed</th>
							</tr>
						</thead>
						<tbody>
							{#each report.deployments as dep}
								<tr>
									<td>{dep.server_name}</td>
									<td class="mono">{dep.server_ip}</td>
									<td>{dep.server_port}</td>
									<td class="mono">{dep.tls_version}</td>
									<td class="mono">{dep.cipher}</td>
									<td>{new Date(dep.last_observed).toLocaleDateString()}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</section>

		<!-- 4. Health Findings -->
		{#if sortedFindings.length > 0}
			<section class="report-section">
				<h3>Health Findings</h3>
				<div class="table-wrap">
					<table>
						<thead>
							<tr>
								<th>Severity</th>
								<th>Title</th>
								<th>Category</th>
								<th>Affected Certs</th>
								<th>Total Deduction</th>
							</tr>
						</thead>
						<tbody>
							{#each sortedFindings as finding}
								<tr>
									<td><span style:color={severityColor(finding.severity)} style:font-weight="600">{finding.severity}</span></td>
									<td>{finding.title}</td>
									<td>{finding.category}</td>
									<td>{finding.affected_count}</td>
									<td>-{finding.total_deduction}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</section>
		{/if}

		<!-- 5. Wildcards -->
		{#if report.wildcards.length > 0}
			<section class="report-section">
				<h3>Wildcard Certificates</h3>
				<div class="table-wrap">
					<table>
						<thead>
							<tr>
								<th>CN</th>
								<th>Grade</th>
								<th>Expiry</th>
								<th>SANs</th>
							</tr>
						</thead>
						<tbody>
							{#each report.wildcards as wc}
								<tr>
									<td class="mono"><a href="/certificates/{wc.fingerprint}" class="cert-link">{wc.subject_cn}</a></td>
									<td><span style:color={gradeColor(wc.grade)}>{wc.grade}</span></td>
									<td>{new Date(wc.not_after).toLocaleDateString()}</td>
									<td class="mono san-list">{wc.sans.join(', ')}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</section>
		{/if}
	</div>
{/if}

<style>
	.report-loading, .report-error {
		display: flex;
		align-items: center;
		justify-content: center;
		height: 50vh;
		color: var(--cf-text-muted);
		font-size: 0.9rem;
	}

	.report-error { color: var(--cf-risk-critical); }

	.report-content {
		padding: 1.5rem;
		overflow-y: auto;
		height: calc(100vh - 48px - 53px);
	}

	.report-section {
		margin-bottom: 2rem;
	}

	.report-section h3 {
		font-size: 0.95rem;
		font-weight: 700;
		color: var(--cf-text-primary);
		margin: 0 0 0.75rem 0;
	}

	.stat-cards {
		display: flex;
		gap: 1rem;
		flex-wrap: wrap;
	}

	.stat-card {
		flex: 1;
		min-width: 140px;
		background: var(--cf-bg-secondary);
		border: 1px solid var(--cf-border);
		border-radius: 8px;
		padding: 1rem;
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}

	.stat-label {
		font-size: 0.75rem;
		color: var(--cf-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}

	.stat-value {
		font-size: 1.25rem;
		font-weight: 700;
		color: var(--cf-text-primary);
	}

	.table-wrap {
		overflow-x: auto;
	}

	table {
		width: 100%;
		border-collapse: collapse;
		font-size: 0.8rem;
	}

	th {
		text-align: left;
		padding: 0.5rem 0.75rem;
		color: var(--cf-text-muted);
		font-weight: 600;
		font-size: 0.7rem;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		border-bottom: 1px solid var(--cf-border);
	}

	td {
		padding: 0.5rem 0.75rem;
		color: var(--cf-text-secondary);
		border-bottom: 1px solid var(--cf-border);
		white-space: nowrap;
	}

	tr:hover td { background: rgba(56, 189, 248, 0.03); }

	.mono { font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; }

	.grade-badge { font-weight: 700; }

	.badge {
		display: inline-block;
		padding: 0.125rem 0.5rem;
		font-size: 0.7rem;
		font-weight: 500;
		background: rgba(56, 189, 248, 0.1);
		border: 1px solid rgba(56, 189, 248, 0.2);
		border-radius: 4px;
		color: var(--cf-accent);
	}

	.cert-link {
		color: var(--cf-accent);
		text-decoration: none;
	}

	.cert-link:hover { text-decoration: underline; }

	.empty-note {
		color: var(--cf-text-muted);
		font-size: 0.85rem;
		font-style: italic;
		padding: 1rem;
		background: var(--cf-bg-secondary);
		border: 1px solid var(--cf-border);
		border-radius: 8px;
	}

	.san-list {
		white-space: normal;
		word-break: break-all;
		max-width: 400px;
	}

	@media print {
		:global(.top-bar) { display: none !important; }
		.report-content {
			height: auto;
			overflow: visible;
			padding: 0;
		}
		.report-section { page-break-inside: avoid; }
		.stat-card { border: 1px solid #ccc; }
		td, th { font-size: 9pt; }
	}
</style>
