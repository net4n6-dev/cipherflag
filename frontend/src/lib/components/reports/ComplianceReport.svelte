<script lang="ts">
	import { onMount } from 'svelte';
	import { api } from '$lib/api';
	import type { ComplianceReport } from '$lib/api';
	import ReportToolbar from './ReportToolbar.svelte';
	import { gradeColor, severityColor, exportCSV } from './report-types';

	let report: ComplianceReport | null = $state(null);
	let loading = $state(true);
	let error: string | null = $state(null);

	onMount(async () => {
		try {
			report = await api.getComplianceReport();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load compliance report';
		}
		loading = false;
	});

	let scoreColor = $derived(() => {
		if (!report) return '#64748b';
		const s = report.compliance_score;
		if (s > 90) return '#22c55e';
		if (s > 70) return '#eab308';
		if (s > 50) return '#f97316';
		return '#ef4444';
	});

	let sortedPriorities = $derived(
		report ? [...report.remediation_priorities].sort((a, b) => {
			const order: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
			const sevDiff = (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
			if (sevDiff !== 0) return sevDiff;
			return b.affected_count - a.affected_count;
		}) : []
	);

	const CATEGORIES = ['key_strength', 'signature', 'wildcard', 'agility', 'chain', 'revocation', 'transparency'];

	function handleExportCSV() {
		if (!report) return;
		const headers = ['CN', 'Grade', 'Rule ID', 'Finding', 'Severity', 'Category', 'Remediation'];
		const rows = report.critical_issues.map(i => [
			i.subject_cn, i.grade, i.rule_id, i.title,
			i.severity, i.category, i.remediation
		]);
		exportCSV(headers, rows, 'compliance-report.csv');
	}

	function handlePrint() {
		window.print();
	}
</script>

{#if loading}
	<div class="report-loading">Loading compliance report...</div>
{:else if error}
	<div class="report-error">{error}</div>
{:else if report}
	<ReportToolbar title="Crypto Compliance Report" onPrint={handlePrint} onExportCSV={handleExportCSV} />

	<div class="report-content">
		<!-- 1. Compliance Score Banner -->
		<section class="report-section">
			<div class="score-banner" style:border-color={scoreColor()}>
				<div class="score-circle" style:color={scoreColor()}>
					{report.compliance_score}<span class="score-percent">%</span>
				</div>
				<div class="score-detail">
					<span class="score-title">Compliance Score</span>
					<span class="score-subtitle">{report.compliant} of {report.total_certs} certificates compliant</span>
					{#if report.non_compliant > 0}
						<span class="score-non-compliant">{report.non_compliant} non-compliant</span>
					{/if}
				</div>
			</div>
		</section>

		<!-- 2. Critical Issues Table -->
		{#if report.critical_issues.length > 0}
			<section class="report-section">
				<h3>Critical Issues</h3>
				<div class="table-wrap">
					<table>
						<thead>
							<tr>
								<th>CN</th>
								<th>Grade</th>
								<th>Rule ID</th>
								<th>Finding</th>
								<th>Severity</th>
								<th>Category</th>
								<th>Remediation</th>
							</tr>
						</thead>
						<tbody>
							{#each report.critical_issues as issue}
								<tr>
									<td class="mono"><a href="/certificates/{issue.fingerprint}" class="cert-link">{issue.subject_cn}</a></td>
									<td><span style:color={gradeColor(issue.grade)} style:font-weight="700">{issue.grade}</span></td>
									<td class="mono">{issue.rule_id}</td>
									<td>{issue.title}</td>
									<td><span style:color={severityColor(issue.severity)} style:font-weight="600">{issue.severity}</span></td>
									<td>{issue.category}</td>
									<td class="remediation-cell">{issue.remediation}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</section>
		{/if}

		<!-- 3. Remediation Priorities -->
		{#if sortedPriorities.length > 0}
			<section class="report-section">
				<h3>Remediation Priorities</h3>
				<div class="table-wrap">
					<table>
						<thead>
							<tr>
								<th>Rule ID</th>
								<th>Title</th>
								<th>Severity</th>
								<th>Affected Certs</th>
								<th>Total Deduction</th>
								<th>Remediation</th>
							</tr>
						</thead>
						<tbody>
							{#each sortedPriorities as p}
								<tr>
									<td class="mono">{p.rule_id}</td>
									<td>{p.title}</td>
									<td><span style:color={severityColor(p.severity)} style:font-weight="600">{p.severity}</span></td>
									<td>{p.affected_count}</td>
									<td>-{p.total_deduction}</td>
									<td class="remediation-cell">{p.remediation}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</section>
		{/if}

		<!-- 4. Non-agile Certificates -->
		{#if report.non_agile.length > 0}
			<section class="report-section">
				<h3>Non-Agile Certificates</h3>
				<div class="table-wrap">
					<table>
						<thead>
							<tr>
								<th>CN</th>
								<th>Issuer</th>
								<th>Validity Days</th>
								<th>Key Algo</th>
								<th>Source</th>
							</tr>
						</thead>
						<tbody>
							{#each report.non_agile as cert}
								<tr>
									<td class="mono"><a href="/certificates/{cert.fingerprint}" class="cert-link">{cert.subject_cn}</a></td>
									<td>{cert.issuer_cn}</td>
									<td>{cert.validity_days}</td>
									<td class="mono">{cert.key_algorithm}</td>
									<td>{cert.source}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</section>
		{/if}

		<!-- 5. Wildcard Inventory -->
		{#if report.wildcards.length > 0}
			<section class="report-section">
				<h3>Wildcard Inventory</h3>
				<div class="table-wrap">
					<table>
						<thead>
							<tr>
								<th>CN</th>
								<th>SAN Count</th>
								<th>Grade</th>
								<th>Expiry</th>
								<th>Issuer</th>
							</tr>
						</thead>
						<tbody>
							{#each report.wildcards as wc}
								<tr>
									<td class="mono"><a href="/certificates/{wc.fingerprint}" class="cert-link">{wc.subject_cn}</a></td>
									<td>{wc.san_count}</td>
									<td><span style:color={gradeColor(wc.grade)} style:font-weight="700">{wc.grade}</span></td>
									<td>{new Date(wc.not_after).toLocaleDateString()}</td>
									<td>{wc.issuer_cn}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</section>
		{/if}

		<!-- 6. Category Breakdown -->
		<section class="report-section">
			<h3>Category Breakdown</h3>
			<div class="table-wrap">
				<table>
					<thead>
						<tr>
							<th>Category</th>
							<th>Finding Count</th>
						</tr>
					</thead>
					<tbody>
						{#each CATEGORIES as cat}
							<tr>
								<td>{cat}</td>
								<td>{report.by_category[cat] ?? 0}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		</section>
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

	/* Score Banner */
	.score-banner {
		display: flex;
		align-items: center;
		gap: 1.5rem;
		background: var(--cf-bg-secondary);
		border: 2px solid var(--cf-border);
		border-radius: 8px;
		padding: 1.5rem 2rem;
	}

	.score-circle {
		font-size: 3rem;
		font-weight: 800;
		line-height: 1;
	}

	.score-percent {
		font-size: 1.5rem;
		font-weight: 600;
	}

	.score-detail {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}

	.score-title {
		font-size: 1rem;
		font-weight: 700;
		color: var(--cf-text-primary);
	}

	.score-subtitle {
		font-size: 0.85rem;
		color: var(--cf-text-secondary);
	}

	.score-non-compliant {
		font-size: 0.8rem;
		color: #ef4444;
		font-weight: 600;
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

	.remediation-cell {
		white-space: normal;
		max-width: 300px;
		font-size: 0.78rem;
	}

	@media print {
		:global(.top-bar) { display: none !important; }
		.report-content {
			height: auto;
			overflow: visible;
			padding: 0;
		}
		.report-section { page-break-inside: avoid; }
		.score-banner { border: 1px solid #ccc; }
		td, th { font-size: 9pt; }
	}
</style>
