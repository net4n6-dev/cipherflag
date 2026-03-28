<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { api, type Certificate } from '$lib/api';
	import type { ExpiryForecastResponse, ExpiryForecastBucket } from '$lib/api';

	let data = $state<ExpiryForecastResponse | null>(null);
	let loading = $state(true);
	let error = $state<string | null>(null);
	let hoveredBucket = $state<ExpiryForecastBucket | null>(null);
	let tooltipX = $state(0);
	let tooltipY = $state(0);

	// Expanded state
	let expandedWeek = $state<string | null>(null);
	let expandedCerts = $state<Certificate[]>([]);
	let expandedLoading = $state(false);

	const ISSUER_PALETTE = [
		'#38bdf8', '#f472b6', '#a78bfa', '#fb923c',
		'#34d399', '#facc15', '#f87171', '#60a5fa',
	];

	let issuerColorMap: Map<string, string> = $state(new Map());
	let otherColor = '#64748b';

	onMount(async () => {
		try {
			data = await api.getExpiryForecast();
			const map = new Map<string, string>();
			(data.top_issuers ?? []).forEach((org, i) => {
				map.set(org, ISSUER_PALETTE[i % ISSUER_PALETTE.length]);
			});
			issuerColorMap = map;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load expiry forecast';
		}
		loading = false;
	});

	function issuerColor(org: string): string {
		return issuerColorMap.get(org) ?? otherColor;
	}

	let maxBucketCount = $derived(
		data ? Math.max(...data.buckets.map((b: ExpiryForecastBucket) => b.total_count), 1) : 1
	);

	function formatWeek(d: string): string {
		const date = new Date(d + 'T00:00:00');
		return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
	}

	function formatWeekFull(d: string): string {
		const date = new Date(d + 'T00:00:00');
		return date.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });
	}

	function stackSegments(bucket: ExpiryForecastBucket): { org: string; count: number; color: string; offset: number }[] {
		const segments: { org: string; count: number; color: string; offset: number }[] = [];
		let offset = 0;

		for (const issuer of data?.top_issuers ?? []) {
			const match = bucket.by_issuer.find(i => i.issuer_org === issuer);
			if (match && match.count > 0) {
				segments.push({ org: issuer, count: match.count, color: issuerColor(issuer), offset });
				offset += match.count;
			}
		}

		const topSet = new Set(data?.top_issuers ?? []);
		const otherCount = bucket.by_issuer
			.filter(i => !topSet.has(i.issuer_org))
			.reduce((s, i) => s + i.count, 0);
		if (otherCount > 0) {
			segments.push({ org: 'Other', count: otherCount, color: otherColor, offset });
		}

		return segments;
	}

	function showLabel(index: number, total: number): boolean {
		const step = Math.max(Math.floor(total / 8), 1);
		return index % step === 0;
	}

	async function toggleWeek(bucket: ExpiryForecastBucket) {
		if (bucket.total_count === 0) return;

		if (expandedWeek === bucket.week_start) {
			expandedWeek = null;
			expandedCerts = [];
			return;
		}

		expandedWeek = bucket.week_start;
		expandedLoading = true;
		expandedCerts = [];

		// Calculate the end of the week (7 days after week_start)
		const start = new Date(bucket.week_start + 'T00:00:00');
		const end = new Date(start);
		end.setDate(end.getDate() + 7);

		requestAnimationFrame(() => {
			document.getElementById('expiry-drilldown')?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
		});

		try {
			// Use expiring_within_days from now, but we need certs expiring in this specific week
			// Fetch certs expiring within the broader window, then filter client-side to this week
			const daysToEnd = Math.ceil((end.getTime() - Date.now()) / 86400000);
			const daysToStart = Math.max(Math.floor((start.getTime() - Date.now()) / 86400000), 0);

			if (daysToEnd <= 0) {
				// This week is in the past — fetch expired certs
				const params = new URLSearchParams({ expired: 'true', page_size: '50' });
				const result = await api.searchCerts(params.toString());
				expandedCerts = (result.certificates ?? []).filter(c => {
					const expiry = new Date(c.not_after);
					return expiry >= start && expiry < end;
				});
			} else {
				const params = new URLSearchParams({ expiring_within_days: String(daysToEnd), page_size: '100' });
				const result = await api.searchCerts(params.toString());
				expandedCerts = (result.certificates ?? []).filter(c => {
					const expiry = new Date(c.not_after);
					return expiry >= start && expiry < end;
				});
			}
		} catch {
			expandedCerts = [];
		}
		expandedLoading = false;
	}

	function daysUntil(d: string): number {
		return Math.floor((new Date(d).getTime() - Date.now()) / 86400000);
	}

	function viewCert(fp: string) { goto(`/certificates/${fp}`); }
	function viewExpiryReport() { goto('/reports?type=expiry&days=90'); }
</script>

<div class="expiry-tab">
	{#if loading}
		<div class="tab-loading">Loading expiry forecast...</div>
	{:else if error}
		<div class="tab-error">{error}</div>
	{:else if data}
		<div class="tab-header">
			<h2>Expiry Forecast</h2>
			<span class="tab-meta">
				{data.total_expiring.toLocaleString()} expiring in next 52 weeks
			</span>
			<button class="report-btn" onclick={viewExpiryReport}>Expiry Report →</button>
		</div>

		{#if data.already_expired > 0}
			<div class="expired-banner">
				<span class="expired-count">{data.already_expired}</span>
				certificate{data.already_expired > 1 ? 's' : ''} already expired
			</div>
		{/if}

		<!-- Stacked bar chart -->
		<div class="chart-container">
			<div class="chart-hint">click any bar to see certificates</div>
			<div class="chart-bars">
				{#each data.buckets as bucket, i}
					{@const segments = stackSegments(bucket)}
					<button
						class="bar-col"
						class:active={expandedWeek === bucket.week_start}
						class:has-data={bucket.total_count > 0}
						onclick={() => toggleWeek(bucket)}
						onpointerenter={(e) => { hoveredBucket = bucket; tooltipX = e.clientX; tooltipY = e.clientY; }}
						onpointermove={(e) => { tooltipX = e.clientX; tooltipY = e.clientY; }}
						onpointerleave={() => hoveredBucket = null}
					>
						<div class="bar-stack" style="height: {(bucket.total_count / maxBucketCount) * 100}%">
							{#each segments as seg}
								<div
									class="bar-segment"
									style="flex: {seg.count}; background: {seg.color}; opacity: 0.75"
								></div>
							{/each}
						</div>
						{#if bucket.total_count > 0 && (bucket.total_count / maxBucketCount) > 0.15}
							<span class="bar-count-label">{bucket.total_count}</span>
						{/if}
					</button>
				{/each}
			</div>
			<div class="chart-labels">
				{#each data.buckets as bucket, i}
					{#if showLabel(i, data.buckets.length)}
						<span style="left: {(i / data.buckets.length) * 100}%">{formatWeek(bucket.week_start)}</span>
					{/if}
				{/each}
			</div>
		</div>

		<!-- Drilldown panel -->
		{#if expandedWeek}
			{@const bucket = data.buckets.find(b => b.week_start === expandedWeek)}
			<div class="drilldown-panel" id="expiry-drilldown">
				<div class="drilldown-header">
					<div class="drilldown-title">
						<h3>Week of {formatWeekFull(expandedWeek)}</h3>
						<span class="drilldown-meta">{bucket?.total_count ?? 0} certificates expiring</span>
					</div>
					<div class="drilldown-actions">
						<button class="report-btn-sm" onclick={viewExpiryReport}>Expiry Report →</button>
						<button class="close-btn" onclick={() => { expandedWeek = null; expandedCerts = []; }}>&times;</button>
					</div>
				</div>

				{#if bucket && bucket.by_issuer.length > 0}
					<div class="drilldown-issuers">
						{#each [...bucket.by_issuer].sort((a, b) => b.count - a.count) as item}
							<span class="issuer-chip">
								<span class="chip-dot" style="background: {issuerColor(item.issuer_org)}"></span>
								{item.issuer_org}: {item.count}
							</span>
						{/each}
					</div>
				{/if}

				{#if expandedLoading}
					<div class="drilldown-loading">Loading certificates...</div>
				{:else if expandedCerts.length === 0}
					<div class="drilldown-empty">No certificates found for this week.</div>
				{:else}
					<table class="cert-table">
						<thead>
							<tr>
								<th>CN</th>
								<th>Issuer</th>
								<th>Org</th>
								<th>Algorithm</th>
								<th>Expires</th>
								<th>Days</th>
								<th>Source</th>
							</tr>
						</thead>
						<tbody>
							{#each expandedCerts as cert}
								{@const days = daysUntil(cert.not_after)}
								<tr onclick={() => viewCert(cert.fingerprint_sha256)}>
									<td class="cell-cn">{cert.subject.common_name || cert.fingerprint_sha256.slice(0, 16)}</td>
									<td class="cell-issuer">{cert.issuer.common_name}</td>
									<td class="cell-org">{cert.subject.organization}</td>
									<td class="cell-algo">{cert.key_algorithm} {cert.key_size_bits}</td>
									<td class="cell-date">{new Date(cert.not_after).toLocaleDateString()}</td>
									<td class="cell-days" class:expired={days < 0} class:warning={days >= 0 && days < 30}>
										{days < 0 ? 'Expired' : days + 'd'}
									</td>
									<td class="cell-source">{cert.source_discovery}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				{/if}
			</div>
		{/if}

		<!-- Legend -->
		<div class="issuer-legend">
			{#each data.top_issuers as issuer}
				<div class="legend-item">
					<span class="legend-dot" style="background: {issuerColor(issuer)}"></span>
					<span class="legend-label">{issuer}</span>
				</div>
			{/each}
			<div class="legend-item">
				<span class="legend-dot" style="background: {otherColor}"></span>
				<span class="legend-label">Other</span>
			</div>
		</div>

		<!-- Tooltip -->
		{#if hoveredBucket}
			<div class="forecast-tooltip" style="left:{tooltipX + 12}px; top:{tooltipY - 8}px">
				<div class="tt-week">Week of {formatWeekFull(hoveredBucket.week_start)}</div>
				<div class="tt-total">{hoveredBucket.total_count} certificates expiring</div>
				{#if hoveredBucket.by_issuer.length > 0}
					<div class="tt-breakdown">
						{#each [...hoveredBucket.by_issuer].sort((a, b) => b.count - a.count).slice(0, 6) as item}
							<div class="tt-issuer-row">
								<span class="tt-dot" style="background: {issuerColor(item.issuer_org)}"></span>
								<span class="tt-issuer-name">{item.issuer_org}</span>
								<span class="tt-issuer-count">{item.count}</span>
							</div>
						{/each}
					</div>
				{/if}
				{#if Object.keys(hoveredBucket.by_grade).length > 0}
					<div class="tt-grades">
						{#each Object.entries(hoveredBucket.by_grade).sort((a, b) => b[1] - a[1]) as [grade, count]}
							<span class="tt-grade-pill">Grade {grade}: {count}</span>
						{/each}
					</div>
				{/if}
				<div class="tt-click-hint">Click to drill down</div>
			</div>
		{/if}
	{/if}
</div>

<style>
	.expiry-tab { padding: 1.5rem; height: 100%; overflow-y: auto; }

	.tab-header { display: flex; align-items: baseline; gap: 1rem; margin-bottom: 1rem; }
	.tab-header h2 { margin: 0; font-size: 1.1rem; font-weight: 700; color: var(--cf-text-primary); }
	.tab-meta { font-size: 0.8rem; color: var(--cf-text-muted); flex: 1; }

	.report-btn {
		font-size: 0.75rem; color: var(--cf-accent, #38bdf8);
		background: none; border: 1px solid rgba(56, 189, 248, 0.2);
		border-radius: 4px; padding: 0.25rem 0.625rem; cursor: pointer;
	}
	.report-btn:hover { background: rgba(56, 189, 248, 0.1); }

	.expired-banner {
		padding: 0.625rem 1rem; background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.25); border-radius: 8px;
		font-size: 0.85rem; color: #fca5a5; margin-bottom: 1.25rem;
	}
	.expired-count { font-weight: 700; font-size: 1.1rem; color: #ef4444; margin-right: 0.25rem; }

	.chart-container {
		background: var(--cf-bg-secondary, rgba(15, 23, 42, 0.5));
		border: 1px solid var(--cf-border, rgba(56, 189, 248, 0.1));
		border-radius: 8px; padding: 1.25rem 1rem 0.5rem; margin-bottom: 0.5rem;
		position: relative;
	}

	.chart-hint {
		position: absolute; top: 0.5rem; right: 0.75rem;
		font-size: 0.6rem; color: var(--cf-accent, #38bdf8); opacity: 0.6;
	}

	.chart-bars { display: flex; gap: 2px; height: 280px; align-items: flex-end; }

	.bar-col {
		flex: 1; height: 100%; display: flex; flex-direction: column;
		justify-content: flex-end; align-items: center;
		cursor: default; position: relative;
		background: none; border: 1px solid transparent; border-radius: 2px;
		padding: 0; transition: border-color 0.15s;
	}
	.bar-col.has-data { cursor: pointer; }
	.bar-col.has-data:hover { border-color: rgba(56, 189, 248, 0.3); }
	.bar-col.active { border-color: var(--cf-accent, #38bdf8); background: rgba(56, 189, 248, 0.05); }

	.bar-stack {
		width: 100%; display: flex; flex-direction: column;
		border-radius: 2px 2px 0 0; overflow: hidden;
		min-height: 2px; transition: height 0.3s ease;
		pointer-events: none;
	}

	.bar-segment { transition: opacity 0.15s; pointer-events: none; }
	.bar-col:hover .bar-segment { opacity: 1 !important; }

	.bar-count-label {
		position: absolute; top: -2px; transform: translateY(-100%);
		font-size: 0.6rem; color: #64748b; font-variant-numeric: tabular-nums;
		pointer-events: none;
	}

	.chart-labels { position: relative; height: 20px; margin-top: 0.375rem; }
	.chart-labels span { position: absolute; font-size: 0.65rem; color: #64748b; transform: translateX(-50%); }

	/* Drilldown panel */
	.drilldown-panel {
		background: var(--cf-bg-secondary, rgba(15, 23, 42, 0.5));
		border: 1px solid var(--cf-border, rgba(56, 189, 248, 0.15));
		border-radius: 8px; padding: 1rem; margin-bottom: 0.75rem;
	}

	.drilldown-header { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 0.75rem; }
	.drilldown-title h3 { margin: 0; font-size: 0.9rem; font-weight: 700; color: var(--cf-text-primary, #e2e8f0); }
	.drilldown-meta { font-size: 0.75rem; color: var(--cf-text-muted, #64748b); }
	.drilldown-actions { display: flex; align-items: center; gap: 0.5rem; }

	.report-btn-sm {
		font-size: 0.7rem; color: var(--cf-accent, #38bdf8);
		background: none; border: 1px solid rgba(56, 189, 248, 0.2);
		border-radius: 4px; padding: 0.2rem 0.5rem; cursor: pointer;
	}
	.report-btn-sm:hover { background: rgba(56, 189, 248, 0.1); }

	.close-btn { background: none; border: none; color: var(--cf-text-muted); font-size: 1.25rem; cursor: pointer; padding: 0; line-height: 1; }
	.close-btn:hover { color: var(--cf-text-primary); }

	.drilldown-issuers {
		display: flex; flex-wrap: wrap; gap: 0.375rem; margin-bottom: 0.75rem;
	}

	.issuer-chip {
		display: flex; align-items: center; gap: 0.25rem;
		font-size: 0.7rem; color: var(--cf-text-secondary, #94a3b8);
		padding: 0.15rem 0.5rem; background: rgba(56, 189, 248, 0.05);
		border-radius: 4px; border: 1px solid rgba(56, 189, 248, 0.1);
	}

	.chip-dot { width: 6px; height: 6px; border-radius: 2px; flex-shrink: 0; }

	.drilldown-loading, .drilldown-empty { padding: 1rem; text-align: center; font-size: 0.8rem; color: var(--cf-text-muted); }

	.cert-table { width: 100%; border-collapse: collapse; font-size: 0.75rem; }
	.cert-table th { text-align: left; padding: 0.375rem 0.5rem; color: var(--cf-text-muted, #64748b);
		font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.04em; font-weight: 600;
		border-bottom: 1px solid var(--cf-border, rgba(56, 189, 248, 0.1)); }
	.cert-table td { padding: 0.375rem 0.5rem; border-bottom: 1px solid rgba(56, 189, 248, 0.05);
		color: var(--cf-text-secondary, #94a3b8); }
	.cert-table tr { cursor: pointer; transition: background 0.1s; }
	.cert-table tbody tr:hover { background: rgba(56, 189, 248, 0.05); }

	.cell-cn { color: var(--cf-text-primary, #e2e8f0); font-weight: 500; max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.cell-issuer, .cell-org { max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.cell-algo { font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; }
	.cell-date { font-variant-numeric: tabular-nums; }
	.cell-days { font-weight: 600; font-variant-numeric: tabular-nums; }
	.cell-days.expired { color: #ef4444; }
	.cell-days.warning { color: #eab308; }
	.cell-source { font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; }

	/* Legend */
	.issuer-legend { display: flex; flex-wrap: wrap; gap: 0.5rem 1.25rem; padding: 0.5rem 0; }
	.legend-item { display: flex; align-items: center; gap: 0.375rem; }
	.legend-dot { width: 10px; height: 10px; border-radius: 2px; flex-shrink: 0; }
	.legend-label { font-size: 0.75rem; color: #cbd5e1; }

	/* Tooltip */
	.forecast-tooltip {
		position: fixed; background: rgba(15, 23, 42, 0.97);
		border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 8px;
		padding: 0.75rem; min-width: 220px; z-index: 50;
		pointer-events: none; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
	}

	.tt-week { font-size: 0.8rem; font-weight: 600; color: #e2e8f0; margin-bottom: 0.125rem; }
	.tt-total { font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.5rem; }
	.tt-breakdown { display: flex; flex-direction: column; gap: 0.2rem; margin-bottom: 0.375rem; }
	.tt-issuer-row { display: flex; align-items: center; gap: 0.375rem; font-size: 0.75rem; }
	.tt-dot { width: 6px; height: 6px; border-radius: 2px; flex-shrink: 0; }
	.tt-issuer-name { flex: 1; color: #cbd5e1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.tt-issuer-count { color: #94a3b8; font-variant-numeric: tabular-nums; }
	.tt-grades { display: flex; flex-wrap: wrap; gap: 0.375rem; }
	.tt-grade-pill { font-size: 0.65rem; color: #64748b; padding: 0.1rem 0.375rem; background: rgba(56, 189, 248, 0.08); border-radius: 3px; }
	.tt-click-hint { margin-top: 0.375rem; font-size: 0.6rem; color: var(--cf-accent, #38bdf8); opacity: 0.7; }

	.tab-loading, .tab-error { display: flex; align-items: center; justify-content: center; height: 50vh; color: var(--cf-text-muted); font-size: 0.9rem; }
	.tab-error { color: var(--cf-risk-critical); }
</style>
