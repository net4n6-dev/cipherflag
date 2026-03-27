<script lang="ts">
	import { onMount } from 'svelte';
	import { api } from '$lib/api';
	import type { SourceLineageResponse, SourceLineageGroup } from '$lib/api';
	import { gradeColor } from './analytics-types';

	let data: SourceLineageResponse | null = $state(null);
	let loading = $state(true);
	let error: string | null = $state(null);

	onMount(async () => {
		try {
			data = await api.getSourceLineage();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load source lineage';
		}
		loading = false;
	});

	// Source metadata: category, label, description, icon
	interface SourceMeta {
		label: string;
		category: string;
		description: string;
		color: string;
	}

	const SOURCE_META: Record<string, SourceMeta> = {
		'zeek_passive': {
			label: 'Zeek Passive',
			category: 'network',
			description: 'Certificates observed via passive network monitoring',
			color: '#38bdf8',
		},
		'zeek_active': {
			label: 'Zeek Active',
			category: 'network',
			description: 'Certificates discovered via active Zeek scanning',
			color: '#60a5fa',
		},
		'corelight': {
			label: 'Corelight',
			category: 'network',
			description: 'Certificates from Corelight appliance',
			color: '#818cf8',
		},
		'manual_upload': {
			label: 'Manual Upload',
			category: 'upload',
			description: 'Certificates uploaded via file or paste',
			color: '#a78bfa',
		},
		'active_scan': {
			label: 'Active Scan',
			category: 'scan',
			description: 'Certificates discovered via active reconnaissance',
			color: '#f472b6',
		},
		'pcap_import': {
			label: 'PCAP Import',
			category: 'network',
			description: 'Certificates extracted from packet captures',
			color: '#22d3ee',
		},
		'git_repository': {
			label: 'Git Repository',
			category: 'repo',
			description: 'Certificates discovered in code repositories',
			color: '#fb923c',
		},
		'aws': {
			label: 'AWS',
			category: 'cloud',
			description: 'Certificates from AWS Certificate Manager',
			color: '#facc15',
		},
		'azure': {
			label: 'Azure',
			category: 'cloud',
			description: 'Certificates from Azure Key Vault',
			color: '#34d399',
		},
		'venafi': {
			label: 'Venafi',
			category: 'platform',
			description: 'Certificates imported from Venafi',
			color: '#f87171',
		},
	};

	function getMeta(source: string): SourceMeta {
		return SOURCE_META[source] ?? {
			label: source.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
			category: 'unknown',
			description: 'Certificate discovery source',
			color: '#94a3b8',
		};
	}

	const GRADE_ORDER = ['A+', 'A', 'B', 'C', 'D', 'F'];

	function gradeTotal(dist: Record<string, number>): number {
		return Object.values(dist).reduce((s, c) => s + c, 0) || 1;
	}

	function formatDate(d: string): string {
		if (!d) return '—';
		return new Date(d + 'T00:00:00').toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
	}
</script>

<div class="source-tab">
	{#if loading}
		<div class="tab-loading">Loading source lineage...</div>
	{:else if error}
		<div class="tab-error">{error}</div>
	{:else if data}
		<div class="tab-header">
			<h2>Discovery Sources</h2>
			<span class="tab-meta">{data.sources.length} sources · {data.total_certs.toLocaleString()} certificates</span>
		</div>

		<div class="source-grid">
			{#each data.sources as source}
				{@const meta = getMeta(source.source)}
				<div class="source-card" style="border-left-color: {meta.color}">
					<div class="card-header">
						<div class="card-icon" style="color: {meta.color}">
							{#if meta.category === 'network'}
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
									<path d="M2 20h20"/><path d="M12 4v8"/><path d="M8 8l4-4 4 4"/><circle cx="12" cy="16" r="2"/><path d="M6 12c0-3.3 2.7-6 6-6s6 2.7 6 6"/>
								</svg>
							{:else if meta.category === 'upload'}
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
									<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
								</svg>
							{:else if meta.category === 'scan'}
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
									<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/>
								</svg>
							{:else if meta.category === 'cloud'}
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
									<path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/>
								</svg>
							{:else if meta.category === 'repo'}
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
									<line x1="6" y1="3" x2="6" y2="15"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M18 9a9 9 0 0 1-9 9"/>
								</svg>
							{:else if meta.category === 'platform'}
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
									<rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
								</svg>
							{:else}
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
									<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>
								</svg>
							{/if}
						</div>
						<div class="card-title">
							<h3>{meta.label}</h3>
							<span class="card-desc">{meta.description}</span>
						</div>
						<div class="card-count">{source.cert_count.toLocaleString()}</div>
					</div>

					<div class="card-stats">
						<div class="stat">
							<span class="stat-val" class:danger={source.expired_count > 0}>{source.expired_count}</span>
							<span class="stat-label">Expired</span>
						</div>
						<div class="stat">
							<span class="stat-val" class:warning={source.expiring_30d_count > 0}>{source.expiring_30d_count}</span>
							<span class="stat-label">&lt;30d</span>
						</div>
						<div class="stat">
							<span class="stat-val">{source.avg_score.toFixed(0)}</span>
							<span class="stat-label">Avg Score</span>
						</div>
					</div>

					<!-- Grade distribution mini-bar -->
					<div class="grade-bar">
						{#each GRADE_ORDER as grade}
							{@const count = source.grade_distribution[grade] ?? 0}
							{#if count > 0}
								<div
									class="grade-segment"
									style="flex: {count}; background: {gradeColor(grade)}"
									title="Grade {grade}: {count}"
								></div>
							{/if}
						{/each}
					</div>

					<!-- Key algorithms -->
					<div class="card-algos">
						{#each Object.entries(source.key_algorithms).sort((a, b) => b[1] - a[1]) as [algo, count]}
							<span class="algo-pill">{algo} <span class="algo-count">{count}</span></span>
						{/each}
					</div>

					<!-- Date range -->
					<div class="card-dates">
						<span>First: {formatDate(source.first_seen)}</span>
						<span>Last: {formatDate(source.last_seen)}</span>
					</div>
				</div>
			{/each}
		</div>

		{#if data.sources.length === 0}
			<div class="tab-empty">No discovery source data available.</div>
		{/if}
	{/if}
</div>

<style>
	.source-tab { padding: 1.5rem; height: 100%; overflow-y: auto; }

	.tab-header { display: flex; align-items: baseline; gap: 1rem; margin-bottom: 1.25rem; }
	.tab-header h2 { margin: 0; font-size: 1.1rem; font-weight: 700; color: var(--cf-text-primary); }
	.tab-meta { font-size: 0.8rem; color: var(--cf-text-muted); }

	.source-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(380px, 1fr));
		gap: 1rem;
	}

	.source-card {
		background: var(--cf-bg-secondary, rgba(15, 23, 42, 0.5));
		border: 1px solid var(--cf-border, rgba(56, 189, 248, 0.1));
		border-left: 3px solid;
		border-radius: 8px;
		padding: 1rem;
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	.card-header {
		display: flex;
		align-items: flex-start;
		gap: 0.75rem;
	}

	.card-icon {
		width: 32px;
		height: 32px;
		flex-shrink: 0;
		opacity: 0.9;
	}

	.card-icon svg {
		width: 100%;
		height: 100%;
	}

	.card-title {
		flex: 1;
		min-width: 0;
	}

	.card-title h3 {
		margin: 0;
		font-size: 0.95rem;
		font-weight: 600;
		color: var(--cf-text-primary, #e2e8f0);
	}

	.card-desc {
		font-size: 0.7rem;
		color: var(--cf-text-muted, #64748b);
	}

	.card-count {
		font-size: 1.5rem;
		font-weight: 700;
		color: var(--cf-text-primary, #e2e8f0);
		font-variant-numeric: tabular-nums;
		flex-shrink: 0;
	}

	.card-stats {
		display: flex;
		gap: 1rem;
	}

	.stat {
		display: flex;
		flex-direction: column;
		align-items: center;
		padding: 0.375rem 0.75rem;
		background: rgba(56, 189, 248, 0.05);
		border-radius: 6px;
		flex: 1;
	}

	.stat-val {
		font-size: 1rem;
		font-weight: 700;
		color: var(--cf-text-primary, #e2e8f0);
		font-variant-numeric: tabular-nums;
	}

	.stat-val.danger { color: #ef4444; }
	.stat-val.warning { color: #eab308; }

	.stat-label {
		font-size: 0.6rem;
		color: var(--cf-text-muted, #64748b);
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}

	.grade-bar {
		display: flex;
		height: 6px;
		border-radius: 3px;
		overflow: hidden;
		gap: 1px;
	}

	.grade-segment {
		opacity: 0.75;
		border-radius: 1px;
		min-width: 2px;
		transition: opacity 0.15s;
	}

	.grade-segment:hover { opacity: 1; }

	.card-algos {
		display: flex;
		flex-wrap: wrap;
		gap: 0.375rem;
	}

	.algo-pill {
		font-size: 0.7rem;
		padding: 0.15rem 0.5rem;
		background: rgba(56, 189, 248, 0.08);
		border: 1px solid rgba(56, 189, 248, 0.15);
		border-radius: 4px;
		color: var(--cf-text-secondary, #94a3b8);
		font-family: 'JetBrains Mono', monospace;
	}

	.algo-count {
		font-weight: 600;
		color: var(--cf-text-primary, #e2e8f0);
		margin-left: 0.25rem;
	}

	.card-dates {
		display: flex;
		justify-content: space-between;
		font-size: 0.7rem;
		color: var(--cf-text-muted, #64748b);
	}

	.tab-loading, .tab-error, .tab-empty {
		display: flex; align-items: center; justify-content: center;
		height: 50vh; color: var(--cf-text-muted); font-size: 0.9rem;
	}
	.tab-error { color: var(--cf-risk-critical); }
</style>
