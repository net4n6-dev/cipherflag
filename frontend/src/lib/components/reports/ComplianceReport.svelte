<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { api } from '$lib/api';
	import type { ComplianceReport } from '$lib/api';
	import ReportToolbar from './ReportToolbar.svelte';
	import { gradeColor, severityColor, exportCSV } from './report-types';

	let report = $state<ComplianceReport | null>(null);
	let loading = $state(true);
	let error = $state<string | null>(null);
	let expandedSection = $state<string | null>(null);

	onMount(async () => {
		try {
			report = await api.getComplianceReport();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load compliance report';
		}
		loading = false;
	});

	function getScoreColor(score: number): string {
		if (score > 90) return '#22c55e';
		if (score > 70) return '#84cc16';
		if (score > 50) return '#eab308';
		return '#ef4444';
	}

	let scoreColor = $derived(report ? getScoreColor(report.compliance_score) : '#64748b');

	let sortedPriorities = $derived(
		report?.remediation_priorities
			? [...report.remediation_priorities].sort((a, b) => {
					const order: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
					const sevDiff = (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
					if (sevDiff !== 0) return sevDiff;
					return b.affected_count - a.affected_count;
				})
			: []
	);

	// Severity counts from priorities
	let severityCounts = $derived.by(() => {
		const counts: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
		for (const p of report?.remediation_priorities ?? []) {
			counts[p.severity] = (counts[p.severity] ?? 0) + p.affected_count;
		}
		return counts;
	});

	let totalFindings = $derived(Object.values(severityCounts).reduce((a, b) => a + b, 0) || 1);

	let categorySorted = $derived(
		Object.entries(report?.by_category ?? {}).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1])
	);
	let categoryTotal = $derived(categorySorted.reduce((s, [, v]) => s + v, 0) || 1);

	const CATEGORY_LABELS: Record<string, string> = {
		key_strength: 'Key Strength', signature: 'Signature', expiration: 'Expiration',
		chain: 'Chain Trust', revocation: 'Revocation', transparency: 'CT/SCT',
		wildcard: 'Wildcards', agility: 'Crypto Agility',
	};
	const CATEGORY_COLORS: Record<string, string> = {
		key_strength: '#38bdf8', signature: '#ef4444', expiration: '#f97316',
		chain: '#a78bfa', revocation: '#fb923c', transparency: '#eab308',
		wildcard: '#f472b6', agility: '#34d399',
	};
	const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low'];

	function gaugeArc(pct: number, r: number, cx: number, cy: number): string {
		const startAngle = -Math.PI * 0.75;
		const endAngle = startAngle + (pct / 100) * Math.PI * 1.5;
		const x1 = cx + r * Math.cos(startAngle);
		const y1 = cy + r * Math.sin(startAngle);
		const x2 = cx + r * Math.cos(endAngle);
		const y2 = cy + r * Math.sin(endAngle);
		const large = (endAngle - startAngle) > Math.PI ? 1 : 0;
		return `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`;
	}

	function donutArc(startAngle: number, endAngle: number, r: number, cx: number, cy: number): string {
		const x1 = cx + r * Math.cos(startAngle - Math.PI / 2);
		const y1 = cy + r * Math.sin(startAngle - Math.PI / 2);
		const x2 = cx + r * Math.cos(endAngle - Math.PI / 2);
		const y2 = cy + r * Math.sin(endAngle - Math.PI / 2);
		const large = endAngle - startAngle > Math.PI ? 1 : 0;
		return `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`;
	}

	function toggleSection(section: string) {
		expandedSection = expandedSection === section ? null : section;
	}

	function handleExportCSV() {
		if (!report) return;
		const headers = ['CN', 'Grade', 'Rule ID', 'Finding', 'Severity', 'Category', 'Remediation'];
		const rows = report.critical_issues.map(i => [
			i.subject_cn, i.grade, i.rule_id, i.title, i.severity, i.category, i.remediation
		]);
		exportCSV(headers, rows, 'compliance-report.csv');
	}

	function handlePrint() { window.print(); }
</script>

{#if loading}
	<div class="report-loading">Loading compliance report...</div>
{:else if error}
	<div class="report-error">{error}</div>
{:else if report}
	<ReportToolbar title="Crypto Compliance Report" onPrint={handlePrint} onExportCSV={handleExportCSV} />

	<div class="report-content">
		<!-- Visual Analysis Layer -->
		<div class="analysis-grid">
			<!-- Compliance Gauge -->
			<div class="analysis-panel gauge-panel">
				<svg viewBox="0 0 180 130" class="gauge-svg">
					<path d={gaugeArc(100, 60, 90, 85)} fill="none" stroke="rgba(100,116,139,0.15)" stroke-width="14" stroke-linecap="round" />
					<path d={gaugeArc(report.compliance_score, 60, 90, 85)} fill="none" stroke={scoreColor} stroke-width="14" stroke-linecap="round" />
					<text x="90" y="78" text-anchor="middle" fill="#e2e8f0" font-size="28" font-weight="700">{report.compliance_score.toFixed(0)}%</text>
					<text x="90" y="96" text-anchor="middle" fill="#64748b" font-size="9">compliant</text>
				</svg>
				<div class="gauge-details">
					<div class="gd-row">
						<span class="gd-val" style="color: #22c55e">{report.compliant}</span>
						<span class="gd-label">Compliant</span>
					</div>
					<div class="gd-row">
						<span class="gd-val" style="color: #ef4444">{report.non_compliant}</span>
						<span class="gd-label">Non-Compliant</span>
					</div>
					<div class="gd-row">
						<span class="gd-val">{report.total_certs}</span>
						<span class="gd-label">Total</span>
					</div>
				</div>
				<!-- Compliant ratio bar -->
				<div class="ratio-bar">
					<div class="ratio-fill compliant" style="width: {(report.compliant / report.total_certs) * 100}%"></div>
					<div class="ratio-fill non-compliant" style="width: {(report.non_compliant / report.total_certs) * 100}%"></div>
				</div>
			</div>

			<!-- Category Donut -->
			<div class="analysis-panel">
				<h3>Findings by Category</h3>
				<div class="cat-donut-row">
					<svg viewBox="0 0 120 120" class="cat-donut-svg">
						{#each categorySorted as [cat, count], i}
							{@const startAngle = categorySorted.slice(0, i).reduce((s, [, v]) => s + (v / categoryTotal) * Math.PI * 2, 0)}
							{@const endAngle = startAngle + (count / categoryTotal) * Math.PI * 2}
							<path
								d={donutArc(startAngle, Math.min(endAngle, startAngle + Math.PI * 2 - 0.01), 45, 60, 60)}
								fill="none"
								stroke={CATEGORY_COLORS[cat] ?? '#64748b'}
								stroke-width="12"
								stroke-linecap="round"
							/>
						{/each}
						<text x="60" y="57" text-anchor="middle" fill="#e2e8f0" font-size="13" font-weight="700">{categoryTotal}</text>
						<text x="60" y="70" text-anchor="middle" fill="#64748b" font-size="7">findings</text>
					</svg>
					<div class="cat-legend">
						{#each Object.entries(report.by_category).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]) as [cat, count]}
							<div class="cl-row">
								<span class="cl-dot" style="background: {CATEGORY_COLORS[cat] ?? '#64748b'}"></span>
								<span class="cl-name">{CATEGORY_LABELS[cat] ?? cat}</span>
								<span class="cl-count">{count}</span>
							</div>
						{/each}
					</div>
				</div>
			</div>

			<!-- Severity Breakdown -->
			<div class="analysis-panel">
				<h3>Severity Distribution</h3>
				<div class="severity-stack">
					{#each SEVERITY_ORDER as sev}
						{@const count = severityCounts[sev] ?? 0}
						{#if count > 0}
							<div class="sev-bar" style="flex: {count}; background: {severityColor(sev)}; opacity: 0.7"></div>
						{/if}
					{/each}
				</div>
				<div class="severity-legend">
					{#each SEVERITY_ORDER as sev}
						{@const count = severityCounts[sev] ?? 0}
						{#if count > 0}
							<div class="sl-row">
								<span class="sl-dot" style="background: {severityColor(sev)}"></span>
								<span class="sl-name">{sev}</span>
								<span class="sl-count">{count}</span>
								<span class="sl-pct">{(count / totalFindings * 100).toFixed(0)}%</span>
							</div>
						{/if}
					{/each}
				</div>

				<h3 style="margin-top: 1rem;">Top Remediations</h3>
				<div class="top-remediations">
					{#each sortedPriorities.slice(0, 4) as p}
						<div class="tr-item">
							<span class="tr-sev" style="color: {severityColor(p.severity)}">{p.severity.charAt(0)}</span>
							<span class="tr-title">{p.title}</span>
							<span class="tr-count">{p.affected_count}</span>
						</div>
					{/each}
				</div>
			</div>
		</div>

		<!-- Category Drill Cards -->
		<div class="category-cards">
			{#each Object.entries(report.by_category).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]) as [cat, count]}
				<button class="cat-card" style="border-left-color: {CATEGORY_COLORS[cat] ?? '#64748b'}"
					onclick={() => toggleSection(cat)}>
					<span class="cc-name">{CATEGORY_LABELS[cat] ?? cat}</span>
					<span class="cc-count">{count} findings</span>
					<span class="cc-arrow">{expandedSection === cat ? '▼' : '▶'}</span>
				</button>
			{/each}
		</div>

		<!-- Expanded Detail Sections -->
		{#if expandedSection}
			<section class="detail-section">
				<div class="detail-header">
					<h3>{CATEGORY_LABELS[expandedSection] ?? expandedSection} Issues</h3>
					<button class="detail-close" onclick={() => expandedSection = null}>&times;</button>
				</div>
				<div class="table-wrap">
					<table>
						<thead>
							<tr>
								<th>CN</th><th>Grade</th><th>Rule</th><th>Finding</th><th>Severity</th><th>Remediation</th>
							</tr>
						</thead>
						<tbody>
							{#each report.critical_issues.filter(i => i.category === expandedSection) as issue}
								<tr>
									<td class="mono"><a href="/certificates/{issue.fingerprint}" class="cert-link">{issue.subject_cn}</a></td>
									<td><span style:color={gradeColor(issue.grade)} style:font-weight="700">{issue.grade}</span></td>
									<td class="mono">{issue.rule_id}</td>
									<td>{issue.title}</td>
									<td><span style:color={severityColor(issue.severity)} style:font-weight="600">{issue.severity}</span></td>
									<td class="remediation-cell">{issue.remediation}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</section>
		{/if}

		<!-- Collapsible Full Sections -->
		<div class="full-sections">
			{#if report.wildcards.length > 0}
				<button class="section-toggle" onclick={() => toggleSection('wildcards')}>
					Wildcard Inventory ({report.wildcards.length})
					<span>{expandedSection === 'wildcards' ? '▼' : '▶'}</span>
				</button>
				{#if expandedSection === 'wildcards'}
					<div class="table-wrap">
						<table>
							<thead><tr><th>CN</th><th>SANs</th><th>Grade</th><th>Expiry</th><th>Issuer</th></tr></thead>
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
				{/if}
			{/if}

			{#if report.non_agile.length > 0}
				<button class="section-toggle" onclick={() => toggleSection('non_agile')}>
					Non-Agile Certificates ({report.non_agile.length})
					<span>{expandedSection === 'non_agile' ? '▼' : '▶'}</span>
				</button>
				{#if expandedSection === 'non_agile'}
					<div class="table-wrap">
						<table>
							<thead><tr><th>CN</th><th>Issuer</th><th>Validity Days</th><th>Key Algo</th><th>Source</th></tr></thead>
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
				{/if}
			{/if}

			<button class="section-toggle" onclick={() => toggleSection('all_priorities')}>
				All Remediation Priorities ({sortedPriorities.length})
				<span>{expandedSection === 'all_priorities' ? '▼' : '▶'}</span>
			</button>
			{#if expandedSection === 'all_priorities'}
				<div class="table-wrap">
					<table>
						<thead><tr><th>Rule</th><th>Finding</th><th>Severity</th><th>Affected</th><th>Deduction</th><th>Remediation</th></tr></thead>
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
			{/if}
		</div>
	</div>
{/if}

<style>
	.report-loading, .report-error { display: flex; align-items: center; justify-content: center; height: 50vh; color: var(--cf-text-muted); font-size: 0.9rem; }
	.report-error { color: var(--cf-risk-critical); }
	.report-content { padding: 1.5rem; overflow-y: auto; height: calc(100vh - 48px - 53px); }

	/* Analysis Grid */
	.analysis-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1rem; margin-bottom: 1.25rem; }
	.analysis-panel { background: var(--cf-bg-secondary); border: 1px solid var(--cf-border); border-radius: 8px; padding: 1rem; }
	.analysis-panel h3 { margin: 0 0 0.75rem; font-size: 0.7rem; font-weight: 600; color: var(--cf-text-muted); text-transform: uppercase; letter-spacing: 0.04em; }

	/* Gauge */
	.gauge-panel { display: flex; flex-direction: column; align-items: center; }
	.gauge-svg { width: 180px; height: 130px; }
	.gauge-details { display: flex; gap: 1.5rem; margin: 0.5rem 0; }
	.gd-row { text-align: center; }
	.gd-val { display: block; font-size: 1.2rem; font-weight: 700; font-variant-numeric: tabular-nums; }
	.gd-label { font-size: 0.6rem; color: var(--cf-text-muted); text-transform: uppercase; }
	.ratio-bar { display: flex; height: 6px; border-radius: 3px; overflow: hidden; width: 100%; gap: 1px; }
	.ratio-fill.compliant { background: #22c55e; opacity: 0.6; }
	.ratio-fill.non-compliant { background: #ef4444; opacity: 0.6; }

	/* Category donut */
	.cat-donut-row { display: flex; align-items: center; gap: 1rem; }
	.cat-donut-svg { width: 110px; height: 110px; flex-shrink: 0; }
	.cat-legend { display: flex; flex-direction: column; gap: 0.25rem; flex: 1; }
	.cl-row { display: flex; align-items: center; gap: 0.375rem; }
	.cl-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
	.cl-name { font-size: 0.75rem; color: var(--cf-text-secondary); flex: 1; }
	.cl-count { font-size: 0.75rem; color: var(--cf-text-muted); font-variant-numeric: tabular-nums; }

	/* Severity */
	.severity-stack { display: flex; height: 12px; border-radius: 6px; overflow: hidden; gap: 1px; margin-bottom: 0.5rem; }
	.sev-bar { border-radius: 2px; }
	.severity-legend { display: flex; flex-direction: column; gap: 0.2rem; }
	.sl-row { display: flex; align-items: center; gap: 0.375rem; }
	.sl-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
	.sl-name { font-size: 0.75rem; color: var(--cf-text-secondary); flex: 1; }
	.sl-count { font-size: 0.75rem; color: var(--cf-text-muted); font-variant-numeric: tabular-nums; }
	.sl-pct { font-size: 0.65rem; color: var(--cf-text-muted); font-variant-numeric: tabular-nums; width: 28px; text-align: right; }

	/* Top remediations */
	.top-remediations { display: flex; flex-direction: column; gap: 0.3rem; }
	.tr-item { display: flex; align-items: center; gap: 0.375rem; }
	.tr-sev { font-size: 0.65rem; font-weight: 700; width: 14px; text-align: center; }
	.tr-title { font-size: 0.7rem; color: var(--cf-text-primary); flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.tr-count { font-size: 0.7rem; color: var(--cf-text-muted); font-variant-numeric: tabular-nums; }

	/* Category drill cards */
	.category-cards { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 1rem; }
	.cat-card {
		display: flex; align-items: center; gap: 0.5rem;
		padding: 0.5rem 0.75rem; background: var(--cf-bg-secondary);
		border: 1px solid var(--cf-border); border-left: 3px solid;
		border-radius: 6px; cursor: pointer; transition: all 0.15s;
		color: inherit;
	}
	.cat-card:hover { background: rgba(56, 189, 248, 0.05); border-color: var(--cf-border-hover); }
	.cc-name { font-size: 0.8rem; font-weight: 600; color: var(--cf-text-primary); }
	.cc-count { font-size: 0.7rem; color: var(--cf-text-muted); }
	.cc-arrow { font-size: 0.55rem; color: var(--cf-text-muted); }

	/* Detail sections */
	.detail-section { background: var(--cf-bg-secondary); border: 1px solid var(--cf-border); border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
	.detail-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.75rem; }
	.detail-header h3 { margin: 0; font-size: 0.9rem; font-weight: 700; color: var(--cf-text-primary); }
	.detail-close { background: none; border: none; color: var(--cf-text-muted); font-size: 1.25rem; cursor: pointer; }

	/* Collapsible sections */
	.full-sections { display: flex; flex-direction: column; gap: 0.5rem; }
	.section-toggle {
		display: flex; align-items: center; justify-content: space-between;
		padding: 0.625rem 1rem; background: var(--cf-bg-secondary);
		border: 1px solid var(--cf-border); border-radius: 6px;
		color: var(--cf-text-primary); font-size: 0.85rem; font-weight: 600;
		cursor: pointer; transition: all 0.15s; width: 100%; text-align: left;
	}
	.section-toggle:hover { border-color: var(--cf-border-hover); }
	.section-toggle span { font-size: 0.55rem; color: var(--cf-text-muted); }

	/* Tables */
	.table-wrap { overflow-x: auto; margin-bottom: 0.5rem; }
	table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
	th { text-align: left; padding: 0.5rem 0.75rem; color: var(--cf-text-muted); font-weight: 600; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.04em; border-bottom: 1px solid var(--cf-border); }
	td { padding: 0.5rem 0.75rem; color: var(--cf-text-secondary); border-bottom: 1px solid var(--cf-border); white-space: nowrap; }
	tr:hover td { background: rgba(56, 189, 248, 0.03); }
	.mono { font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; }
	.cert-link { color: var(--cf-accent); text-decoration: none; }
	.cert-link:hover { text-decoration: underline; }
	.remediation-cell { white-space: normal; max-width: 300px; font-size: 0.78rem; }

	@media print {
		:global(.top-bar) { display: none !important; }
		.report-content { height: auto; overflow: visible; padding: 0; }
		.detail-section, .full-sections { page-break-inside: avoid; }
	}
</style>
