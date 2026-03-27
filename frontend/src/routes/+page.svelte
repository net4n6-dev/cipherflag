<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type SummaryStats, type IssuerStat, type ExpiryBucket } from '$lib/api';

	let stats: SummaryStats | null = $state(null);
	let issuers: IssuerStat[] = $state([]);
	let expiryBuckets: ExpiryBucket[] = $state([]);
	let alreadyExpired = $state(0);
	let loading = $state(true);
	let error: string | null = $state(null);

	const GRADE_COLORS: Record<string, string> = {
		'A+': '#22c55e', 'A': '#22c55e', 'B': '#84cc16',
		'C': '#eab308', 'D': '#f97316', 'F': '#ef4444'
	};

	const GRADE_ORDER = ['A+', 'A', 'B', 'C', 'D', 'F'];

	onMount(() => {
		(async () => {
			try {
				const [s, iss, exp] = await Promise.all([
					api.getSummary(),
					api.getIssuers(),
					api.getExpiryTimeline()
				]);
				stats = s;
				issuers = iss.issuers ?? [];
				expiryBuckets = exp.buckets ?? [];
				alreadyExpired = exp.already_expired;
			} catch (e) {
				error = e instanceof Error ? e.message : 'Failed to load dashboard';
			}
			loading = false;
		})();
	});

	function gradeTotal(): number {
		if (!stats) return 1;
		return Object.values(stats.grade_distribution).reduce((a, b) => a + b, 0) || 1;
	}

	function gradePct(grade: string): number {
		if (!stats) return 0;
		return ((stats.grade_distribution[grade] ?? 0) / gradeTotal()) * 100;
	}

	function maxBucketCount(): number {
		return Math.max(...expiryBuckets.map(b => b.count), 1);
	}

	function bucketColor(b: ExpiryBucket): string {
		if (b.critical > 0) return 'var(--cf-risk-critical)';
		if (b.count >= 10) return 'var(--cf-risk-high)';
		if (b.count >= 5) return 'var(--cf-risk-medium)';
		return 'var(--cf-accent)';
	}

	function formatWeek(d: string): string {
		const date = new Date(d + 'T00:00:00');
		return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
	}

	// Treemap: top 12 issuers, rest grouped as "Other"
	function treemapData(): { label: string; count: number; score: number; pct: number }[] {
		const top = issuers.slice(0, 12);
		const otherCount = issuers.slice(12).reduce((s, i) => s + i.cert_count, 0);
		const total = issuers.reduce((s, i) => s + i.cert_count, 0) || 1;
		const items = top.map(i => ({
			label: i.issuer_cn.length > 28 ? i.issuer_cn.slice(0, 26) + '...' : i.issuer_cn,
			count: i.cert_count,
			score: i.avg_score,
			pct: (i.cert_count / total) * 100
		}));
		if (otherCount > 0) {
			items.push({ label: 'Other', count: otherCount, score: 0, pct: (otherCount / total) * 100 });
		}
		return items;
	}

	function scoreColor(score: number): string {
		if (score >= 85) return '#22c55e';
		if (score >= 70) return '#84cc16';
		if (score >= 50) return '#eab308';
		if (score >= 20) return '#f97316';
		return '#ef4444';
	}
</script>

<div class="dashboard">
	{#if loading}
		<div class="loading">Loading dashboard...</div>
	{:else if error}
		<div class="error">{error}</div>
	{:else if stats}
		<div class="dash-header">
			<h1>Certificate Landscape</h1>
			<div class="header-meta">
				<span class="meta-item">{stats.total_certs.toLocaleString()} certificates</span>
				<span class="meta-sep">|</span>
				<span class="meta-item">{stats.total_observations.toLocaleString()} observations</span>
			</div>
		</div>

		<!-- Risk Signal Cards -->
		<div class="risk-row">
			<a href="/certificates?expired=true" class="risk-card critical">
				<div class="risk-num">{stats.expired}</div>
				<div class="risk-label">Expired</div>
			</a>
			<a href="/certificates?expiring_within_days=30" class="risk-card high">
				<div class="risk-num">{stats.expiring_in_30_days}</div>
				<div class="risk-label">Expiring &lt;30d</div>
			</a>
			<a href="/certificates?expiring_within_days=90" class="risk-card medium">
				<div class="risk-num">{stats.expiring_in_90_days}</div>
				<div class="risk-label">Expiring &lt;90d</div>
			</a>
			<a href="/certificates?grade=F" class="risk-card critical">
				<div class="risk-num">{stats.critical_findings}</div>
				<div class="risk-label">Grade F</div>
			</a>
			<div class="risk-card info">
				<div class="risk-num">{stats.total_findings}</div>
				<div class="risk-label">With Findings</div>
			</div>
		</div>

		<div class="panels-grid">
			<!-- Grade Distribution -->
			<div class="panel">
				<h2>Grade Distribution</h2>
				<div class="grade-donut-row">
					<div class="donut-wrapper">
						<svg viewBox="0 0 36 36" class="donut">
							{#each GRADE_ORDER as grade, i}
								{@const pct = gradePct(grade)}
								{@const offset = GRADE_ORDER.slice(0, i).reduce((s, g) => s + gradePct(g), 0)}
								{#if pct > 0}
									<circle cx="18" cy="18" r="15.9155"
										fill="none"
										stroke={GRADE_COLORS[grade]}
										stroke-width="3.5"
										stroke-dasharray="{pct} {100 - pct}"
										stroke-dashoffset={-offset}
										transform="rotate(-90 18 18)" />
								{/if}
							{/each}
							<text x="18" y="17" text-anchor="middle" class="donut-total">{stats.total_certs}</text>
							<text x="18" y="22" text-anchor="middle" class="donut-label">total</text>
						</svg>
					</div>
					<div class="grade-legend">
						{#each GRADE_ORDER as grade}
							{@const count = stats.grade_distribution[grade] ?? 0}
							{#if count > 0}
								<a href="/certificates?grade={grade}" class="grade-row">
									<span class="grade-dot" style="background: {GRADE_COLORS[grade]}"></span>
									<span class="grade-name">{grade}</span>
									<span class="grade-count">{count}</span>
									<span class="grade-pct">{gradePct(grade).toFixed(0)}%</span>
								</a>
							{/if}
						{/each}
					</div>
				</div>
			</div>

			<!-- Expiry Timeline -->
			<div class="panel">
				<h2>Expiry Timeline (52 weeks)</h2>
				{#if alreadyExpired > 0}
					<div class="expired-banner">
						{alreadyExpired} certificate{alreadyExpired > 1 ? 's' : ''} already expired
					</div>
				{/if}
				<div class="timeline-bars">
					{#each expiryBuckets as bucket}
						<div class="tl-bar-col" title="{formatWeek(bucket.week_start)}: {bucket.count} expiring">
							<div class="tl-bar"
								style="height: {(bucket.count / maxBucketCount()) * 100}%; background: {bucketColor(bucket)}">
							</div>
						</div>
					{/each}
				</div>
				<div class="timeline-labels">
					{#each expiryBuckets.filter((_, i) => i % Math.max(Math.floor(expiryBuckets.length / 6), 1) === 0) as bucket}
						<span>{formatWeek(bucket.week_start)}</span>
					{/each}
				</div>
			</div>

			<!-- Issuer Treemap -->
			<div class="panel panel-wide">
				<h2>Certificates by Issuer</h2>
				<div class="treemap">
					{#each treemapData() as item}
						<div class="treemap-cell"
							style="flex: {Math.max(item.pct, 3)}; background: {item.score ? scoreColor(item.score) : 'var(--cf-bg-tertiary)'}22; border-color: {item.score ? scoreColor(item.score) : 'var(--cf-border)'}">
							<span class="tm-label">{item.label}</span>
							<span class="tm-count">{item.count}</span>
						</div>
					{/each}
				</div>
			</div>

			<!-- Discovery Sources -->
			<div class="panel">
				<h2>Discovery Sources</h2>
				<div class="source-list">
					{#each Object.entries(stats.source_stats).sort((a, b) => b[1] - a[1]) as [source, count]}
						<div class="source-row">
							<span class="source-name">{source}</span>
							<span class="source-count">{count}</span>
						</div>
					{/each}
				</div>
			</div>
		</div>
	{/if}
</div>

<style>
	.dashboard {
		padding: 1.5rem;
		max-width: 1400px;
		margin: 0 auto;
		overflow-y: auto;
		height: 100%;
	}

	.dash-header {
		display: flex;
		align-items: baseline;
		gap: 1rem;
		margin-bottom: 1.25rem;
	}

	h1 {
		font-size: 1.4rem;
		font-weight: 700;
		margin: 0;
		color: var(--cf-text-primary);
	}

	.header-meta {
		display: flex;
		gap: 0.5rem;
		font-size: 0.8rem;
		color: var(--cf-text-muted);
	}

	.meta-sep { opacity: 0.4; }

	h2 {
		font-size: 0.8rem;
		font-weight: 600;
		color: var(--cf-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		margin: 0 0 0.75rem;
	}

	/* Risk cards */
	.risk-row {
		display: grid;
		grid-template-columns: repeat(5, 1fr);
		gap: 0.75rem;
		margin-bottom: 1.25rem;
	}

	.risk-card {
		background: var(--cf-bg-secondary);
		border: 1px solid var(--cf-border);
		border-radius: 8px;
		padding: 0.875rem;
		text-align: center;
		text-decoration: none;
		transition: border-color 0.15s;
	}

	.risk-card:hover { border-color: var(--cf-border-hover); }
	.risk-card.critical .risk-num { color: var(--cf-risk-critical); }
	.risk-card.high .risk-num { color: var(--cf-risk-high); }
	.risk-card.medium .risk-num { color: var(--cf-risk-medium); }
	.risk-card.info .risk-num { color: var(--cf-accent); }

	.risk-num {
		font-size: 1.75rem;
		font-weight: 700;
		font-variant-numeric: tabular-nums;
	}

	.risk-label {
		font-size: 0.75rem;
		color: var(--cf-text-muted);
		margin-top: 0.125rem;
	}

	/* Panels */
	.panels-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 1rem;
	}

	.panel {
		background: var(--cf-bg-secondary);
		border: 1px solid var(--cf-border);
		border-radius: 8px;
		padding: 1.25rem;
	}

	.panel-wide {
		grid-column: 1 / -1;
	}

	/* Grade donut */
	.grade-donut-row {
		display: flex;
		align-items: center;
		gap: 1.5rem;
	}

	.donut-wrapper {
		width: 120px;
		height: 120px;
		flex-shrink: 0;
	}

	.donut { width: 100%; height: 100%; }

	.donut-total {
		font-size: 7px;
		font-weight: 700;
		fill: var(--cf-text-primary);
	}

	.donut-label {
		font-size: 3.5px;
		fill: var(--cf-text-muted);
	}

	.grade-legend {
		display: flex;
		flex-direction: column;
		gap: 0.375rem;
		flex: 1;
	}

	.grade-row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		text-decoration: none;
		padding: 0.25rem 0.5rem;
		border-radius: 4px;
		transition: background 0.15s;
	}

	.grade-row:hover { background: var(--cf-bg-tertiary); }

	.grade-dot {
		width: 8px;
		height: 8px;
		border-radius: 50%;
		flex-shrink: 0;
	}

	.grade-name {
		font-weight: 600;
		font-size: 0.85rem;
		color: var(--cf-text-primary);
		width: 20px;
	}

	.grade-count {
		font-variant-numeric: tabular-nums;
		font-size: 0.85rem;
		color: var(--cf-text-secondary);
		flex: 1;
	}

	.grade-pct {
		font-size: 0.75rem;
		color: var(--cf-text-muted);
		font-variant-numeric: tabular-nums;
	}

	/* Expiry timeline */
	.expired-banner {
		padding: 0.375rem 0.625rem;
		background: rgba(239, 68, 68, 0.12);
		border: 1px solid rgba(239, 68, 68, 0.25);
		border-radius: 6px;
		font-size: 0.8rem;
		color: var(--cf-risk-critical);
		margin-bottom: 0.75rem;
	}

	.timeline-bars {
		display: flex;
		gap: 2px;
		height: 80px;
		align-items: flex-end;
	}

	.tl-bar-col {
		flex: 1;
		height: 100%;
		display: flex;
		align-items: flex-end;
		cursor: default;
	}

	.tl-bar {
		width: 100%;
		min-height: 2px;
		border-radius: 2px 2px 0 0;
		transition: height 0.3s ease;
	}

	.timeline-labels {
		display: flex;
		justify-content: space-between;
		font-size: 0.65rem;
		color: var(--cf-text-muted);
		margin-top: 0.375rem;
		padding: 0 2px;
	}

	/* Treemap */
	.treemap {
		display: flex;
		flex-wrap: wrap;
		gap: 4px;
		min-height: 60px;
	}

	.treemap-cell {
		display: flex;
		flex-direction: column;
		justify-content: center;
		align-items: center;
		padding: 0.5rem;
		border-radius: 6px;
		border: 1px solid;
		min-width: 80px;
		min-height: 48px;
		text-align: center;
		gap: 0.125rem;
	}

	.tm-label {
		font-size: 0.7rem;
		color: var(--cf-text-secondary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		max-width: 100%;
	}

	.tm-count {
		font-size: 0.85rem;
		font-weight: 700;
		color: var(--cf-text-primary);
		font-variant-numeric: tabular-nums;
	}

	/* Sources */
	.source-list {
		display: flex;
		flex-direction: column;
		gap: 0.375rem;
	}

	.source-row {
		display: flex;
		justify-content: space-between;
		padding: 0.375rem 0.625rem;
		background: var(--cf-bg-tertiary);
		border-radius: 6px;
	}

	.source-name {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.8rem;
		color: var(--cf-text-primary);
	}

	.source-count {
		font-weight: 600;
		color: var(--cf-accent);
		font-variant-numeric: tabular-nums;
	}

	.loading, .error {
		display: flex;
		align-items: center;
		justify-content: center;
		height: 50vh;
		color: var(--cf-text-muted);
	}

	.error { color: var(--cf-risk-critical); }
</style>
