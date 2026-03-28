<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { api, type DeploymentGroup, type IssuerStat } from '$lib/api';
	import { hierarchy, treemap, treemapSquarify } from 'd3-hierarchy';
	import DomainReport from '$lib/components/reports/DomainReport.svelte';
	import CAReport from '$lib/components/reports/CAReport.svelte';
	import ComplianceReport from '$lib/components/reports/ComplianceReport.svelte';
	import ExpiryReport from '$lib/components/reports/ExpiryReport.svelte';

	let reportType = $derived(page.url.searchParams.get('type'));
	let q = $derived(page.url.searchParams.get('q') ?? '');
	let fp = $derived(page.url.searchParams.get('fp') ?? '');
	let issuerCN = $derived(page.url.searchParams.get('issuer_cn') ?? '');
	let daysParam = $derived(Number(page.url.searchParams.get('days')) || 30);

	// Landing data
	let domains = $state<DeploymentGroup[]>([]);
	let issuers = $state<IssuerStat[]>([]);
	let complianceScore = $state(0);
	let totalCerts = $state(0);
	let expired = $state(0);
	let expiring30d = $state(0);
	let wildcardCount = $state(0);
	let expiryBuckets = $state<{month: string; count: number}[]>([]);
	let landingLoading = $state(true);

	const GRADE_COLORS: Record<string, string> = {
		'A+': '#22c55e', 'A': '#22c55e', 'B': '#84cc16',
		'C': '#eab308', 'D': '#f97316', 'F': '#ef4444', '?': '#64748b',
	};

	function gradeColor(g: string): string { return GRADE_COLORS[g] ?? '#64748b'; }

	onMount(async () => {
		if (!reportType) {
			try {
				const [dep, iss, summary, compliance] = await Promise.all([
					api.getDeployment(),
					api.getIssuers(),
					api.getSummary(),
					api.getComplianceReport(),
				]);
				domains = dep.groups;
				issuers = (iss as any).issuers ?? [];
				totalCerts = summary.total_certs;
				expired = summary.expired;
				expiring30d = summary.expiring_in_30_days;
				complianceScore = compliance.compliance_score;
				wildcardCount = compliance.wildcards?.length ?? 0;

				// Build monthly expiry buckets from expiry forecast
				try {
					const forecast = await api.getExpiryForecast();
					const monthMap: Record<string, number> = {};
					for (const b of forecast.buckets) {
						const d = new Date(b.week_start + 'T00:00:00');
						const key = d.toLocaleDateString('en-US', { month: 'short', year: '2-digit' });
						monthMap[key] = (monthMap[key] ?? 0) + b.total_count;
					}
					expiryBuckets = Object.entries(monthMap).map(([month, count]) => ({ month, count }));
				} catch {}
			} catch {}
			computeTreemap();
			landingLoading = false;
		}
	});

	// Treemap layout for domain overview
	interface DomainRect {
		x: number; y: number; w: number; h: number;
		domain: string; count: number; grade: string;
		ips: number; expired: number; score: number;
		showLabel: boolean;
	}

	let domainRects = $state<DomainRect[]>([]);
	let treemapWidth = 800;
	let treemapHeight = 280;

	function computeTreemap() {
		if (domains.length === 0) { domainRects = []; return; }

		const root = hierarchy({ children: domains.map(d => ({ ...d, value: d.cert_count })) })
			.sum((d: any) => d.value ?? 0)
			.sort((a, b) => (b.value ?? 0) - (a.value ?? 0));

		treemap<any>()
			.size([treemapWidth, treemapHeight])
			.paddingOuter(3)
			.paddingInner(2)
			.tile(treemapSquarify)
			(root);

		const totalArea = treemapWidth * treemapHeight;
		domainRects = root.leaves().map((leaf: any) => {
			const d = leaf.data;
			const w = (leaf.x1 ?? 0) - (leaf.x0 ?? 0);
			const h = (leaf.y1 ?? 0) - (leaf.y0 ?? 0);
			return {
				x: leaf.x0 ?? 0, y: leaf.y0 ?? 0, w, h,
				domain: d.domain ?? '',
				count: d.cert_count ?? 0,
				grade: d.worst_grade ?? '?',
				ips: d.unique_ips ?? 0,
				expired: d.expired_count ?? 0,
				score: d.avg_score ?? 0,
				showLabel: (w * h) / totalArea > 0.015 && w > 50 && h > 24,
			};
		});
	}

	let hoveredDomain = $state<DomainRect | null>(null);
	let tooltipX = $state(0);
	let tooltipY = $state(0);

	function scoreColor(score: number): string {
		if (score >= 90) return '#22c55e';
		if (score >= 70) return '#84cc16';
		if (score >= 50) return '#eab308';
		return '#ef4444';
	}

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
</script>

<svelte:head>
	<title>Reports - CipherFlag</title>
</svelte:head>

{#if !reportType}
	<div class="reports-landing">
		{#if landingLoading}
			<div class="landing-loading">Loading report dashboard...</div>
		{:else}
			<div class="landing-header">
				<h1>Reports</h1>
				<p>Click any chart element to drill into a detailed report</p>
			</div>

			<div class="dashboard-grid">
				<!-- Domain Overview Treemap -->
				<div class="dash-panel treemap-panel">
					<h2>Domain Overview <span class="panel-hint">click any domain for report</span></h2>
					<svg class="treemap-svg" viewBox="0 0 {treemapWidth} {treemapHeight}">
						{#each domainRects as rect}
							<g
								class="tm-group"
								onclick={() => goto(`/reports?type=domain&q=${encodeURIComponent(rect.domain)}`)}
								onpointerenter={(e) => { hoveredDomain = rect; tooltipX = e.clientX; tooltipY = e.clientY; }}
								onpointermove={(e) => { tooltipX = e.clientX; tooltipY = e.clientY; }}
								onpointerleave={() => hoveredDomain = null}
								role="button"
								tabindex="-1"
							>
								<rect
									x={rect.x} y={rect.y} width={rect.w} height={rect.h}
									fill={gradeColor(rect.grade)}
									fill-opacity={hoveredDomain === rect ? 0.35 : 0.2}
									stroke={gradeColor(rect.grade)}
									stroke-opacity={hoveredDomain === rect ? 0.8 : 0.5}
									stroke-width={hoveredDomain === rect ? 2 : 1}
									rx="3"
								/>
								{#if rect.showLabel}
									<text x={rect.x + 5} y={rect.y + 14} fill="#e2e8f0" font-size="9" font-weight="600">
										{rect.domain.length > rect.w / 6.5 ? rect.domain.slice(0, Math.floor(rect.w / 6.5)) + '...' : rect.domain}
									</text>
									{#if rect.h > 36}
										<text x={rect.x + 5} y={rect.y + 26} fill={gradeColor(rect.grade)} font-size="8">
											{rect.count} certs · {rect.grade}
										</text>
									{/if}
									{#if rect.h > 50 && rect.expired > 0}
										<text x={rect.x + 5} y={rect.y + 38} fill="#ef4444" font-size="7">
											{rect.expired} expired
										</text>
									{/if}
								{/if}
							</g>
						{/each}
					</svg>

					{#if hoveredDomain}
						<div class="tm-tooltip" style="left:{tooltipX + 12}px; top:{tooltipY - 8}px">
							<div class="tt-domain">{hoveredDomain.domain}</div>
							<div class="tt-stats">
								<span>{hoveredDomain.count} certs</span>
								<span>{hoveredDomain.ips} IPs</span>
								<span style="color: {gradeColor(hoveredDomain.grade)}">Grade {hoveredDomain.grade}</span>
								<span>Score: {hoveredDomain.score.toFixed(0)}</span>
								{#if hoveredDomain.expired > 0}<span class="tt-expired">{hoveredDomain.expired} expired</span>{/if}
							</div>
							<div class="tt-hint">Click for full report</div>
						</div>
					{/if}
				</div>

				<!-- CA Concentration -->
				<div class="dash-panel">
					<h2>CA Concentration</h2>
					<div class="ca-bars">
						{#each issuers.slice(0, 8) as issuer}
							{@const maxCount = Math.max(...issuers.map(i => i.cert_count), 1)}
							<button class="ca-bar-row" onclick={() => goto(`/reports?type=ca&issuer_cn=${encodeURIComponent(issuer.issuer_cn)}`)}>
								<span class="cb-name">{issuer.issuer_cn.length > 28 ? issuer.issuer_cn.slice(0, 26) + '...' : issuer.issuer_cn}</span>
								<div class="cb-track">
									<div class="cb-fill" style="width: {(issuer.cert_count / maxCount) * 100}%; background: {gradeColor(issuer.min_grade)}"></div>
								</div>
								<span class="cb-count">{issuer.cert_count}</span>
								<span class="cb-grade" style="color: {gradeColor(issuer.min_grade)}">{issuer.min_grade}</span>
							</button>
						{/each}
					</div>
				</div>

				<!-- Compliance Gauge -->
				<div class="dash-panel">
					<h2>Compliance Posture</h2>
					<div class="gauge-layout">
						<svg viewBox="0 0 160 120" class="gauge-svg">
							<!-- Background arc -->
							<path d={gaugeArc(100, 55, 80, 75)} fill="none" stroke="rgba(100,116,139,0.2)" stroke-width="12" stroke-linecap="round" />
							<!-- Score arc -->
							<path d={gaugeArc(complianceScore, 55, 80, 75)} fill="none" stroke={scoreColor(complianceScore)} stroke-width="12" stroke-linecap="round" />
							<text x="80" y="72" text-anchor="middle" fill="#e2e8f0" font-size="22" font-weight="700">{complianceScore.toFixed(0)}%</text>
							<text x="80" y="88" text-anchor="middle" fill="#64748b" font-size="8">compliant</text>
						</svg>
						<div class="gauge-stats">
							<div class="gs-row">
								<span class="gs-val">{totalCerts.toLocaleString()}</span>
								<span class="gs-label">Total Certs</span>
							</div>
							<div class="gs-row">
								<span class="gs-val" style="color: #ef4444">{expired}</span>
								<span class="gs-label">Expired</span>
							</div>
							<div class="gs-row">
								<span class="gs-val" style="color: #eab308">{expiring30d}</span>
								<span class="gs-label">Expiring &lt;30d</span>
							</div>
							<div class="gs-row">
								<span class="gs-val">{wildcardCount}</span>
								<span class="gs-label">Wildcards</span>
							</div>
						</div>
					</div>
					<button class="panel-action" onclick={() => goto('/reports?type=compliance')}>
						View Compliance Report →
					</button>
				</div>

				<!-- Expiry Heatmap -->
				<div class="dash-panel">
					<h2>Expiry Timeline</h2>
					{#if expiryBuckets.length > 0}
						{@const maxExp = Math.max(...expiryBuckets.map(b => b.count), 1)}
						<div class="expiry-months">
							{#each expiryBuckets as bucket}
								<div class="em-col">
									<div class="em-bar-wrap">
										<div
											class="em-bar"
											style="height: {(bucket.count / maxExp) * 100}%; background: {bucket.count > maxExp * 0.7 ? '#ef4444' : bucket.count > maxExp * 0.4 ? '#eab308' : '#38bdf8'}"
										></div>
									</div>
									<span class="em-count">{bucket.count}</span>
									<span class="em-label">{bucket.month}</span>
								</div>
							{/each}
						</div>
					{:else}
						<div class="panel-empty">No expiry data available</div>
					{/if}
					<div class="expiry-actions">
						<button class="panel-action" onclick={() => goto('/reports?type=expiry&days=30')}>30 Day Report</button>
						<button class="panel-action" onclick={() => goto('/reports?type=expiry&days=90')}>90 Day Report</button>
					</div>
				</div>
			</div>
		{/if}
	</div>
{:else if reportType === 'domain'}
	<DomainReport domain={q} />
{:else if reportType === 'ca'}
	<CAReport fingerprint={fp || undefined} issuerCN={issuerCN || undefined} />
{:else if reportType === 'compliance'}
	<ComplianceReport />
{:else if reportType === 'expiry'}
	<ExpiryReport days={daysParam} />
{:else}
	<div class="report-error">Unknown report type: {reportType}</div>
{/if}

<style>
	.reports-landing { padding: 1.5rem; overflow-y: auto; height: 100%; }
	.landing-loading { display: flex; align-items: center; justify-content: center; height: 50vh; color: var(--cf-text-muted); }

	.landing-header { margin-bottom: 1.25rem; }
	.landing-header h1 { margin: 0; font-size: 1.4rem; font-weight: 700; color: var(--cf-text-primary); }
	.landing-header p { margin: 0.25rem 0 0; font-size: 0.8rem; color: var(--cf-text-muted); }

	.dashboard-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }

	.dash-panel {
		background: var(--cf-bg-secondary); border: 1px solid var(--cf-border);
		border-radius: 8px; padding: 1rem;
	}

	.dash-panel h2 {
		margin: 0 0 0.75rem; font-size: 0.75rem; font-weight: 600;
		color: var(--cf-text-muted); text-transform: uppercase; letter-spacing: 0.04em;
	}

	.treemap-panel { grid-column: 1 / -1; position: relative; }

	.panel-hint { font-size: 0.6rem; font-weight: 400; text-transform: none; letter-spacing: normal; color: var(--cf-accent); opacity: 0.6; }

	/* Treemap */
	.treemap-svg { width: 100%; display: block; }
	.tm-group { cursor: pointer; }
	.tm-group text { pointer-events: none; user-select: none; }

	.tm-tooltip {
		position: fixed; background: rgba(15, 23, 42, 0.97);
		border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 8px;
		padding: 0.5rem 0.75rem; z-index: 50; pointer-events: none;
		box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
	}
	.tt-domain { font-size: 0.8rem; font-weight: 600; color: #e2e8f0; margin-bottom: 0.25rem; }
	.tt-stats { display: flex; gap: 0.75rem; font-size: 0.7rem; color: #94a3b8; }
	.tt-expired { color: #ef4444; }
	.tt-hint { font-size: 0.6rem; color: var(--cf-accent); margin-top: 0.25rem; }

	/* CA bars */
	.ca-bars { display: flex; flex-direction: column; gap: 0.3rem; }

	.ca-bar-row {
		display: flex; align-items: center; gap: 0.5rem;
		padding: 0.3rem 0.375rem; background: none; border: 1px solid transparent;
		border-radius: 4px; color: inherit; text-align: left;
		cursor: pointer; transition: all 0.15s; width: 100%;
	}
	.ca-bar-row:hover { background: rgba(56, 189, 248, 0.06); border-color: rgba(56, 189, 248, 0.2); }

	.cb-name { width: 170px; font-size: 0.75rem; color: var(--cf-text-primary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex-shrink: 0; }
	.cb-track { flex: 1; height: 14px; background: var(--cf-bg-tertiary); border-radius: 3px; overflow: hidden; pointer-events: none; }
	.cb-fill { height: 100%; border-radius: 3px; opacity: 0.6; pointer-events: none; }
	.cb-count { width: 30px; text-align: right; font-size: 0.8rem; font-weight: 600; color: var(--cf-text-secondary); font-variant-numeric: tabular-nums; flex-shrink: 0; }
	.cb-grade { width: 20px; font-size: 0.75rem; font-weight: 700; text-align: center; flex-shrink: 0; }

	/* Gauge */
	.gauge-layout { display: flex; align-items: center; gap: 1rem; }
	.gauge-svg { width: 160px; height: 120px; flex-shrink: 0; }
	.gauge-stats { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; flex: 1; }
	.gs-row { display: flex; flex-direction: column; align-items: center; padding: 0.375rem; background: rgba(56, 189, 248, 0.03); border-radius: 6px; }
	.gs-val { font-size: 1.1rem; font-weight: 700; color: var(--cf-text-primary); font-variant-numeric: tabular-nums; }
	.gs-label { font-size: 0.6rem; color: var(--cf-text-muted); text-transform: uppercase; letter-spacing: 0.04em; }

	.panel-action {
		display: block; width: 100%; margin-top: 0.75rem;
		padding: 0.5rem; font-size: 0.75rem; font-weight: 500;
		background: rgba(56, 189, 248, 0.06); border: 1px solid rgba(56, 189, 248, 0.15);
		border-radius: 6px; color: var(--cf-accent); cursor: pointer;
		text-align: center; transition: all 0.15s;
	}
	.panel-action:hover { background: rgba(56, 189, 248, 0.12); }

	/* Expiry months */
	.expiry-months { display: flex; gap: 3px; height: 140px; align-items: flex-end; }

	.em-col {
		flex: 1; display: flex; flex-direction: column; align-items: center;
		height: 100%; justify-content: flex-end;
	}

	.em-bar-wrap { flex: 1; width: 100%; display: flex; align-items: flex-end; }
	.em-bar { width: 100%; border-radius: 2px 2px 0 0; min-height: 2px; opacity: 0.7; transition: height 0.3s; }
	.em-count { font-size: 0.6rem; color: var(--cf-text-secondary); font-variant-numeric: tabular-nums; margin-top: 2px; }
	.em-label { font-size: 0.55rem; color: var(--cf-text-muted); white-space: nowrap; }

	.expiry-actions { display: flex; gap: 0.5rem; margin-top: 0.75rem; }
	.expiry-actions .panel-action { flex: 1; margin-top: 0; }

	.panel-empty { padding: 2rem; text-align: center; color: var(--cf-text-muted); font-size: 0.8rem; }

	.report-error { display: flex; align-items: center; justify-content: center; height: 50vh; color: var(--cf-risk-critical); font-size: 0.9rem; }
</style>
