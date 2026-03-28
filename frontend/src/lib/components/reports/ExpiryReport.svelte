<script lang="ts">
	import { onMount } from 'svelte';
	import { api } from '$lib/api';
	import type { ExpiryReport } from '$lib/api';
	import ReportToolbar from './ReportToolbar.svelte';
	import { gradeColor, exportCSV } from './report-types';

	interface Props {
		days?: number;
	}

	let { days = 30 }: Props = $props();

	let report: ExpiryReport | null = $state(null);
	let loading = $state(true);
	let error: string | null = $state(null);
	let activeDays = $state(days);

	async function loadReport(d: number) {
		loading = true;
		error = null;
		try {
			report = await api.getExpiryReport(d);
			activeDays = d;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load expiry report';
		}
		loading = false;
	}

	onMount(() => {
		loadReport(activeDays);
	});

	let sortedCerts = $derived(
		report ? [...report.certificates].sort((a, b) => a.days_remaining - b.days_remaining) : []
	);

	let sortedByIssuer = $derived(
		report ? [...report.by_issuer].sort((a, b) => b.count - a.count) : []
	);

	let sortedByOwner = $derived(
		report ? [...report.by_owner].sort((a, b) => b.count - a.count) : []
	);

	function daysColor(d: number): string {
		if (d < 30) return '#ef4444';
		if (d < 90) return '#eab308';
		return 'var(--cf-text-primary)';
	}

	function urgencyColor(count: number): string {
		if (count > 20) return '#ef4444';
		if (count > 10) return '#f97316';
		if (count > 0) return '#eab308';
		return '#22c55e';
	}

	function handleExportCSV() {
		if (!report) return;
		const headers = ['CN', 'Issuer', 'Grade', 'Days Remaining', 'Org', 'OU', 'Key Algo', 'Source', 'First Seen', 'Last Seen'];
		const rows = sortedCerts.map(c => [
			c.subject_cn, c.issuer_cn, c.grade, String(c.days_remaining),
			c.subject_org, c.subject_ou, c.key_algorithm, c.source,
			c.first_seen, c.last_seen
		]);
		exportCSV(headers, rows, `expiry-report-${activeDays}d.csv`);
	}

	function handlePrint() {
		window.print();
	}
</script>

<ReportToolbar title="Expiry Risk Report: Next {activeDays} Days" onPrint={handlePrint} onExportCSV={handleExportCSV} />

<div class="day-selector">
	{#each [30, 60, 90] as d}
		<button
			class="day-btn"
			class:active={activeDays === d}
			onclick={() => loadReport(d)}
		>
			{d} days
		</button>
	{/each}
</div>

{#if loading}
	<div class="report-loading">Loading expiry report...</div>
{:else if error}
	<div class="report-error">{error}</div>
{:else if report}
	<div class="report-content">
		<!-- 1. Urgency Banner -->
		<section class="report-section">
			<div class="urgency-banner" style:border-color={urgencyColor(report.total_expiring)}>
				<span class="urgency-count" style:color={urgencyColor(report.total_expiring)}>{report.total_expiring}</span>
				<span class="urgency-text">certificate{report.total_expiring !== 1 ? 's' : ''} expiring in the next <strong>{report.days}</strong> days</span>
			</div>
		</section>

		<!-- 2. Expiry Table -->
		<section class="report-section">
			<h3>Expiring Certificates</h3>
			<div class="table-wrap">
				<table>
					<thead>
						<tr>
							<th>CN</th>
							<th>Issuer</th>
							<th>Grade</th>
							<th>Days Remaining</th>
							<th>Org</th>
							<th>OU</th>
							<th>Key Algo</th>
							<th>Source</th>
							<th>First Seen</th>
							<th>Last Seen</th>
						</tr>
					</thead>
					<tbody>
						{#each sortedCerts as cert}
							<tr>
								<td class="mono"><a href="/certificates/{cert.fingerprint}" class="cert-link">{cert.subject_cn}</a></td>
								<td>{cert.issuer_cn}</td>
								<td><span style:color={gradeColor(cert.grade)} style:font-weight="700">{cert.grade}</span></td>
								<td style:color={daysColor(cert.days_remaining)} style:font-weight="700">{cert.days_remaining}d</td>
								<td>{cert.subject_org}</td>
								<td>{cert.subject_ou}</td>
								<td class="mono">{cert.key_algorithm}</td>
								<td>{cert.source}</td>
								<td>{new Date(cert.first_seen).toLocaleDateString()}</td>
								<td>{new Date(cert.last_seen).toLocaleDateString()}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		</section>

		<!-- 3. By Issuer -->
		{#if sortedByIssuer.length > 0}
			<section class="report-section">
				<h3>By Issuer</h3>
				<div class="table-wrap">
					<table>
						<thead>
							<tr>
								<th>Issuer Org</th>
								<th>Count</th>
								<th>Worst Grade</th>
							</tr>
						</thead>
						<tbody>
							{#each sortedByIssuer as row}
								<tr>
									<td>{row.issuer_org}</td>
									<td>{row.count}</td>
									<td><span style:color={gradeColor(row.worst_grade)} style:font-weight="700">{row.worst_grade}</span></td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</section>
		{/if}

		<!-- 4. By Owner -->
		{#if sortedByOwner.length > 0}
			<section class="report-section">
				<h3>By Owner</h3>
				<div class="table-wrap">
					<table>
						<thead>
							<tr>
								<th>Subject Org</th>
								<th>Subject OU</th>
								<th>Count</th>
							</tr>
						</thead>
						<tbody>
							{#each sortedByOwner as row}
								<tr>
									<td>{row.subject_org}</td>
									<td>{row.subject_ou}</td>
									<td>{row.count}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</section>
		{/if}

		<!-- 5. Already Expired (Ghost Certs) -->
		{#if report.already_expired.length > 0}
			<section class="report-section">
				<h3>Already Expired (Ghost Certs)</h3>
				<p class="section-note">Expired certificates still observed on the network.</p>
				<div class="table-wrap">
					<table>
						<thead>
							<tr>
								<th>CN</th>
								<th>Issuer</th>
								<th>Expired Days Ago</th>
								<th>Last Observed</th>
								<th>Server Name</th>
								<th>Server IP</th>
							</tr>
						</thead>
						<tbody>
							{#each report.already_expired as ghost}
								<tr>
									<td class="mono"><a href="/certificates/{ghost.fingerprint}" class="cert-link">{ghost.subject_cn}</a></td>
									<td>{ghost.issuer_cn}</td>
									<td style:color="#ef4444" style:font-weight="600">{ghost.expired_days_ago}d ago</td>
									<td>{new Date(ghost.last_observed).toLocaleDateString()}</td>
									<td>{ghost.server_name}</td>
									<td class="mono">{ghost.server_ip}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</section>
		{/if}

		<!-- 6. Deployments at Risk -->
		{#if report.deployments_at_risk.length > 0}
			<section class="report-section">
				<h3>Deployments at Risk</h3>
				<div class="table-wrap">
					<table>
						<thead>
							<tr>
								<th>Server Name</th>
								<th>Server IP</th>
								<th>Port</th>
								<th>Cert CN</th>
								<th>Days Remaining</th>
							</tr>
						</thead>
						<tbody>
							{#each report.deployments_at_risk as dep}
								<tr>
									<td>{dep.server_name}</td>
									<td class="mono">{dep.server_ip}</td>
									<td>{dep.server_port}</td>
									<td class="mono">{dep.cert_cn}</td>
									<td style:color={daysColor(dep.days_remaining)} style:font-weight="700">{dep.days_remaining}d</td>
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

	.day-selector {
		display: flex;
		gap: 0.5rem;
		padding: 0.75rem 1.5rem;
		border-bottom: 1px solid var(--cf-border);
		background: var(--cf-bg-secondary);
	}

	.day-btn {
		padding: 0.375rem 1rem;
		font-size: 0.8rem;
		font-weight: 500;
		background: transparent;
		border: 1px solid var(--cf-border);
		border-radius: 6px;
		color: var(--cf-text-secondary);
		cursor: pointer;
		transition: all 0.15s;
	}

	.day-btn:hover {
		color: var(--cf-text-primary);
		border-color: var(--cf-border-hover);
	}

	.day-btn.active {
		background: rgba(56, 189, 248, 0.1);
		border-color: rgba(56, 189, 248, 0.3);
		color: var(--cf-accent);
	}

	.report-content {
		padding: 1.5rem;
		overflow-y: auto;
		height: calc(100vh - 48px - 53px - 49px);
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

	.section-note {
		color: var(--cf-text-muted);
		font-size: 0.8rem;
		font-style: italic;
		margin: -0.5rem 0 0.75rem 0;
	}

	/* Urgency Banner */
	.urgency-banner {
		display: flex;
		align-items: center;
		gap: 1rem;
		background: var(--cf-bg-secondary);
		border: 2px solid var(--cf-border);
		border-radius: 8px;
		padding: 1.25rem 1.5rem;
	}

	.urgency-count {
		font-size: 2.5rem;
		font-weight: 800;
		line-height: 1;
	}

	.urgency-text {
		font-size: 1rem;
		color: var(--cf-text-secondary);
	}

	.urgency-text strong {
		color: var(--cf-text-primary);
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

	@media print {
		:global(.top-bar) { display: none !important; }
		.day-selector { display: none; }
		.report-content {
			height: auto;
			overflow: visible;
			padding: 0;
		}
		.report-section { page-break-inside: avoid; }
		.urgency-banner { border: 1px solid #ccc; }
		td, th { font-size: 9pt; }
	}
</style>
