<script lang="ts">
	import { onMount } from 'svelte';
	import { api } from '$lib/api';
	import type { CAReport } from '$lib/api';
	import ReportToolbar from './ReportToolbar.svelte';
	import { gradeColor, severityColor, exportCSV } from './report-types';

	interface Props {
		fingerprint?: string;
		issuerCN?: string;
	}

	let { fingerprint, issuerCN }: Props = $props();

	let report = $state<CAReport | null>(null);
	let loading = $state(true);
	let error = $state<string | null>(null);

	onMount(async () => {
		try {
			const parts: string[] = [];
			if (fingerprint) parts.push(`fingerprint=${encodeURIComponent(fingerprint)}`);
			if (issuerCN) parts.push(`issuer_cn=${encodeURIComponent(issuerCN)}`);
			report = await api.getCAReport(parts.join('&'));
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load CA report';
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

	let reportTitle = $derived(
		report?.ca ? `CA Report: ${report.ca.subject_cn}` : 'CA Report'
	);

	function daysColor(days: number): string {
		if (days < 30) return '#ef4444';
		if (days < 90) return '#eab308';
		return 'var(--cf-text-primary)';
	}

	function handleExportCSV() {
		if (!report) return;
		const headers = ['CN', 'Grade', 'Key Algo', 'Key Size', 'Not After', 'Days Remaining', 'Source', 'Wildcard'];
		const rows = sortedCerts.map(c => [
			c.subject_cn, c.grade, c.key_algorithm, String(c.key_size_bits),
			c.not_after, String(c.days_remaining), c.source, c.is_wildcard ? 'Yes' : 'No'
		]);
		exportCSV(headers, rows, `ca-report-${report.ca.subject_cn.replace(/[^a-zA-Z0-9]/g, '_')}.csv`);
	}

	function handlePrint() {
		window.print();
	}
</script>

{#if loading}
	<div class="report-loading">Loading CA report...</div>
{:else if error}
	<div class="report-error">{error}</div>
{:else if report}
	<ReportToolbar title={reportTitle} onPrint={handlePrint} onExportCSV={handleExportCSV} />

	<div class="report-content">
		<!-- 1. CA Identity Card -->
		<section class="report-section">
			<div class="ca-identity-card">
				<div class="ca-identity-header">
					<div class="ca-grade" style:color={gradeColor(report.ca.grade)}>{report.ca.grade}</div>
					<div class="ca-identity-info">
						<h2>{report.ca.subject_cn}</h2>
						{#if report.ca.organization}
							<span class="ca-org">{report.ca.organization}</span>
						{/if}
					</div>
					<div class="ca-badges">
						{#if report.ca.is_self_signed}
							<span class="badge badge-self-signed">Self-Signed</span>
						{/if}
						<span class="badge badge-position">{report.ca.chain_position}</span>
					</div>
				</div>
				<div class="ca-identity-details">
					<div class="detail-pair">
						<span class="detail-label">Key Algorithm</span>
						<span class="detail-value mono">{report.ca.key_algorithm} {report.ca.key_size_bits}-bit</span>
					</div>
					<div class="detail-pair">
						<span class="detail-label">Valid From</span>
						<span class="detail-value">{new Date(report.ca.not_before).toLocaleDateString()}</span>
					</div>
					<div class="detail-pair">
						<span class="detail-label">Valid Until</span>
						<span class="detail-value">{new Date(report.ca.not_after).toLocaleDateString()}</span>
					</div>
					<div class="detail-pair">
						<span class="detail-label">Fingerprint</span>
						<span class="detail-value mono fp">{report.ca.fingerprint}</span>
					</div>
				</div>
			</div>
		</section>

		<!-- 2. Summary Stats -->
		<section class="report-section">
			<h3>Issued Certificate Summary</h3>
			<div class="stat-cards">
				<div class="stat-card">
					<span class="stat-label">Total Issued</span>
					<span class="stat-value">{report.summary.total_issued}</span>
				</div>
				<div class="stat-card">
					<span class="stat-label">Grade Distribution</span>
					<div class="grade-pills">
						{#each Object.entries(report.summary.grade_distribution) as [grade, count]}
							<span class="grade-pill" style:background="{gradeColor(grade)}22" style:color={gradeColor(grade)}>{grade}: {count}</span>
						{/each}
					</div>
				</div>
				<div class="stat-card">
					<span class="stat-label">Expired</span>
					<span class="stat-value" style:color={report.summary.expired > 0 ? '#ef4444' : 'var(--cf-text-primary)'}>{report.summary.expired}</span>
				</div>
				<div class="stat-card">
					<span class="stat-label">Expiring &lt;30d</span>
					<span class="stat-value" style:color={report.summary.expiring_30d > 0 ? '#ef4444' : 'var(--cf-text-primary)'}>{report.summary.expiring_30d}</span>
				</div>
				<div class="stat-card">
					<span class="stat-label">Expiring &lt;90d</span>
					<span class="stat-value" style:color={report.summary.expiring_90d > 0 ? '#eab308' : 'var(--cf-text-primary)'}>{report.summary.expiring_90d}</span>
				</div>
				<div class="stat-card">
					<span class="stat-label">Wildcards</span>
					<span class="stat-value">{report.summary.wildcard_count}</span>
				</div>
			</div>
		</section>

		<!-- 3. Certificates Table -->
		<section class="report-section">
			<h3>Certificates</h3>
			<div class="table-wrap">
				<table>
					<thead>
						<tr>
							<th>CN</th>
							<th>Grade</th>
							<th>Key Algo</th>
							<th>Key Size</th>
							<th>Not After</th>
							<th>Days Remaining</th>
							<th>Source</th>
							<th>Wildcard</th>
						</tr>
					</thead>
					<tbody>
						{#each sortedCerts as cert}
							<tr>
								<td class="mono"><a href="/certificates/{cert.fingerprint}" class="cert-link">{cert.subject_cn}</a></td>
								<td><span style:color={gradeColor(cert.grade)} style:font-weight="700">{cert.grade}</span></td>
								<td class="mono">{cert.key_algorithm}</td>
								<td class="mono">{cert.key_size_bits}</td>
								<td>{new Date(cert.not_after).toLocaleDateString()}</td>
								<td style:color={daysColor(cert.days_remaining)} style:font-weight="600">{cert.days_remaining}d</td>
								<td>{cert.source}</td>
								<td>{#if cert.is_wildcard}<span class="badge">wildcard</span>{/if}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		</section>

		<!-- 4. Crypto Breakdown -->
		<section class="report-section">
			<h3>Cryptographic Breakdown</h3>
			<div class="crypto-grid">
				<div class="crypto-card">
					<h4>Key Algorithms</h4>
					<table>
						<thead><tr><th>Algorithm</th><th>Count</th></tr></thead>
						<tbody>
							{#each Object.entries(report.crypto.key_algorithms) as [algo, count]}
								<tr><td class="mono">{algo}</td><td>{count}</td></tr>
							{/each}
						</tbody>
					</table>
				</div>
				<div class="crypto-card">
					<h4>Signature Algorithms</h4>
					<table>
						<thead><tr><th>Algorithm</th><th>Count</th></tr></thead>
						<tbody>
							{#each Object.entries(report.crypto.signature_algorithms) as [algo, count]}
								<tr><td class="mono">{algo}</td><td>{count}</td></tr>
							{/each}
						</tbody>
					</table>
				</div>
				<div class="crypto-card">
					<h4>Key Sizes</h4>
					<table>
						<thead><tr><th>Size</th><th>Count</th></tr></thead>
						<tbody>
							{#each Object.entries(report.crypto.key_sizes) as [size, count]}
								<tr><td class="mono">{size}</td><td>{count}</td></tr>
							{/each}
						</tbody>
					</table>
				</div>
			</div>
		</section>

		<!-- 5. Chain Context -->
		<section class="report-section">
			<h3>Chain Context</h3>
			<div class="chain-context">
				{#if report.chain.issued_by}
					<div class="chain-entry">
						<span class="chain-label">Issued by:</span>
						<a href="/reports?type=ca&fp={report.chain.issued_by.fingerprint}" class="cert-link">{report.chain.issued_by.subject_cn}</a>
					</div>
				{/if}
				{#if report.chain.issues_to.length > 0}
					<div class="chain-entry">
						<span class="chain-label">Issues to:</span>
						<div class="chain-list">
							{#each report.chain.issues_to as child}
								<a href="/reports?type=ca&fp={child.fingerprint}" class="cert-link chain-child">{child.subject_cn}</a>
							{/each}
						</div>
					</div>
				{/if}
			</div>
		</section>

		<!-- 6. Health Findings -->
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

	/* CA Identity Card */
	.ca-identity-card {
		background: var(--cf-bg-secondary);
		border: 1px solid var(--cf-border);
		border-radius: 8px;
		padding: 1.25rem;
	}

	.ca-identity-header {
		display: flex;
		align-items: center;
		gap: 1rem;
		margin-bottom: 1rem;
	}

	.ca-grade {
		font-size: 2rem;
		font-weight: 800;
		line-height: 1;
	}

	.ca-identity-info h2 {
		margin: 0;
		font-size: 1.1rem;
		font-weight: 700;
		color: var(--cf-text-primary);
	}

	.ca-org {
		font-size: 0.8rem;
		color: var(--cf-text-secondary);
	}

	.ca-badges {
		margin-left: auto;
		display: flex;
		gap: 0.5rem;
	}

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

	.badge-self-signed {
		background: rgba(239, 68, 68, 0.1);
		border-color: rgba(239, 68, 68, 0.2);
		color: #ef4444;
	}

	.badge-position {
		background: rgba(168, 85, 247, 0.1);
		border-color: rgba(168, 85, 247, 0.2);
		color: #a855f7;
	}

	.ca-identity-details {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
		gap: 0.75rem;
	}

	.detail-pair {
		display: flex;
		flex-direction: column;
		gap: 0.125rem;
	}

	.detail-label {
		font-size: 0.7rem;
		color: var(--cf-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}

	.detail-value {
		font-size: 0.85rem;
		color: var(--cf-text-secondary);
	}

	.fp {
		font-size: 0.72rem;
		word-break: break-all;
	}

	/* Stats */
	.stat-cards {
		display: flex;
		gap: 1rem;
		flex-wrap: wrap;
	}

	.stat-card {
		flex: 1;
		min-width: 130px;
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

	.grade-pills {
		display: flex;
		flex-wrap: wrap;
		gap: 0.375rem;
		margin-top: 0.25rem;
	}

	.grade-pill {
		padding: 0.125rem 0.5rem;
		font-size: 0.7rem;
		font-weight: 600;
		border-radius: 4px;
	}

	/* Crypto Grid */
	.crypto-grid {
		display: grid;
		grid-template-columns: repeat(3, 1fr);
		gap: 1rem;
	}

	.crypto-card {
		background: var(--cf-bg-secondary);
		border: 1px solid var(--cf-border);
		border-radius: 8px;
		padding: 1rem;
	}

	.crypto-card h4 {
		margin: 0 0 0.5rem 0;
		font-size: 0.8rem;
		font-weight: 600;
		color: var(--cf-text-secondary);
	}

	/* Chain Context */
	.chain-context {
		background: var(--cf-bg-secondary);
		border: 1px solid var(--cf-border);
		border-radius: 8px;
		padding: 1rem;
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	.chain-entry {
		display: flex;
		align-items: flex-start;
		gap: 0.75rem;
	}

	.chain-label {
		font-size: 0.8rem;
		font-weight: 600;
		color: var(--cf-text-muted);
		white-space: nowrap;
	}

	.chain-list {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem;
	}

	.chain-child {
		font-size: 0.85rem;
	}

	/* Tables */
	.table-wrap { overflow-x: auto; }

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

	.cert-link {
		color: var(--cf-accent);
		text-decoration: none;
	}

	.cert-link:hover { text-decoration: underline; }

	@media (max-width: 900px) {
		.crypto-grid { grid-template-columns: 1fr; }
	}

	@media print {
		:global(.top-bar) { display: none !important; }
		.report-content {
			height: auto;
			overflow: visible;
			padding: 0;
		}
		.report-section { page-break-inside: avoid; }
		.ca-identity-card, .stat-card, .crypto-card, .chain-context { border: 1px solid #ccc; }
		td, th { font-size: 9pt; }
	}
</style>
