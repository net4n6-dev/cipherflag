<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type SummaryStats } from '$lib/api';

	let stats: SummaryStats | null = $state(null);
	let loading = $state(true);
	let error: string | null = $state(null);

	const GRADE_COLORS: Record<string, string> = {
		'A+': '#22c55e', 'A': '#22c55e', 'B': '#84cc16',
		'C': '#eab308', 'D': '#f97316', 'F': '#ef4444'
	};

	onMount(() => {
		(async () => {
			try {
				stats = await api.getSummary();
				loading = false;
			} catch (e) {
				error = e instanceof Error ? e.message : 'Failed to load stats';
				loading = false;
			}
		})();
	});

	function gradeEntries(dist: Record<string, number>): [string, number][] {
		const order = ['A+', 'A', 'B', 'C', 'D', 'F'];
		return order
			.filter(g => (dist[g] ?? 0) > 0)
			.map(g => [g, dist[g]]);
	}

	function maxGradeCount(dist: Record<string, number>): number {
		return Math.max(...Object.values(dist), 1);
	}
</script>

<div class="stats-page">
	<h1>Analytics</h1>

	{#if loading}
		<div class="loading">Loading analytics...</div>
	{:else if error}
		<div class="error">{error}</div>
	{:else if stats}
		<!-- Summary cards -->
		<div class="card-grid">
			<div class="stat-card">
				<div class="stat-value">{stats.total_certs}</div>
				<div class="stat-label">Certificates</div>
			</div>
			<div class="stat-card">
				<div class="stat-value">{stats.total_observations}</div>
				<div class="stat-label">Observations</div>
			</div>
			<div class="stat-card warn">
				<div class="stat-value">{stats.expired}</div>
				<div class="stat-label">Expired</div>
			</div>
			<div class="stat-card warn">
				<div class="stat-value">{stats.expiring_in_30_days}</div>
				<div class="stat-label">Expiring &lt;30d</div>
			</div>
			<div class="stat-card">
				<div class="stat-value">{stats.expiring_in_90_days}</div>
				<div class="stat-label">Expiring &lt;90d</div>
			</div>
			<div class="stat-card critical">
				<div class="stat-value">{stats.critical_findings}</div>
				<div class="stat-label">Critical (F)</div>
			</div>
		</div>

		<div class="panels">
			<!-- Grade distribution -->
			<div class="panel">
				<h2>Grade Distribution</h2>
				<div class="grade-bars">
					{#each gradeEntries(stats.grade_distribution) as [grade, count]}
						<div class="bar-row">
							<span class="bar-label" style="color: {GRADE_COLORS[grade]}">{grade}</span>
							<div class="bar-track">
								<div
									class="bar-fill"
									style="width: {(count / maxGradeCount(stats.grade_distribution)) * 100}%; background: {GRADE_COLORS[grade]}"
								></div>
							</div>
							<span class="bar-count">{count}</span>
						</div>
					{/each}
				</div>
			</div>

			<!-- Source distribution -->
			<div class="panel">
				<h2>Discovery Sources</h2>
				<div class="source-list">
					{#each Object.entries(stats.source_stats) as [source, count]}
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
	.stats-page {
		padding: 1.5rem;
		max-width: 1200px;
		margin: 0 auto;
		overflow-y: auto;
		height: 100%;
	}

	h1 {
		font-size: 1.4rem;
		font-weight: 700;
		margin: 0 0 1.25rem;
		color: var(--cf-text-primary);
	}

	h2 {
		font-size: 0.85rem;
		font-weight: 600;
		color: var(--cf-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		margin: 0 0 1rem;
	}

	.card-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
		gap: 0.75rem;
		margin-bottom: 1.5rem;
	}

	.stat-card {
		background: var(--cf-bg-secondary);
		border: 1px solid var(--cf-border);
		border-radius: 8px;
		padding: 1rem;
		text-align: center;
	}

	.stat-value {
		font-size: 2rem;
		font-weight: 700;
		color: var(--cf-text-primary);
		font-variant-numeric: tabular-nums;
	}

	.stat-card.warn .stat-value { color: var(--cf-risk-high); }
	.stat-card.critical .stat-value { color: var(--cf-risk-critical); }

	.stat-label {
		font-size: 0.8rem;
		color: var(--cf-text-muted);
		margin-top: 0.25rem;
	}

	.panels {
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

	.grade-bars {
		display: flex;
		flex-direction: column;
		gap: 0.625rem;
	}

	.bar-row {
		display: flex;
		align-items: center;
		gap: 0.75rem;
	}

	.bar-label {
		width: 24px;
		font-weight: 700;
		font-size: 0.9rem;
		text-align: right;
	}

	.bar-track {
		flex: 1;
		height: 24px;
		background: var(--cf-bg-tertiary);
		border-radius: 4px;
		overflow: hidden;
	}

	.bar-fill {
		height: 100%;
		border-radius: 4px;
		transition: width 0.5s ease;
	}

	.bar-count {
		width: 30px;
		text-align: right;
		font-size: 0.85rem;
		color: var(--cf-text-secondary);
		font-variant-numeric: tabular-nums;
	}

	.source-list {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.source-row {
		display: flex;
		justify-content: space-between;
		padding: 0.5rem 0.75rem;
		background: var(--cf-bg-tertiary);
		border-radius: 6px;
	}

	.source-name {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.85rem;
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
