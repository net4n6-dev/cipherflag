<script lang="ts">
	import { onMount } from 'svelte';
	import { api } from '$lib/api';
	import type { LibraryDistItem } from '$lib/api';
	import LibraryDistTreemap from './LibraryDistTreemap.svelte';

	let items = $state<LibraryDistItem[]>([]);
	let loading = $state(true);
	let error: string | null = $state(null);

	onMount(async () => {
		try {
			const resp = await api.getLibraryDistribution();
			items = resp?.items ?? [];
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load library data';
		}
		loading = false;
	});
</script>

<div class="library-dist-tab">
	{#if loading}
		<div class="tab-loading">Loading library distribution...</div>
	{:else if error}
		<div class="tab-error">{error}</div>
	{:else if items.length === 0}
		<div class="tab-empty">No crypto-library data yet — configure a host-based source (osquery or EDR) to populate this view.</div>
	{:else}
		<div class="tab-header">
			<h2>Library Distribution</h2>
			<span class="tab-meta">{items.length} libraries · sized by host count · red = has CVEs</span>
		</div>
		<div class="chart-wrap">
			<LibraryDistTreemap {items} />
		</div>
	{/if}
</div>

<style>
	.library-dist-tab { padding: 1.5rem; height: 100%; overflow-y: auto; }
	.tab-header { display: flex; align-items: baseline; gap: 1rem; margin-bottom: 1rem; }
	.tab-header h2 { margin: 0; font-size: 1.1rem; font-weight: 700; color: var(--cf-text-primary); }
	.tab-meta { font-size: 0.8rem; color: var(--cf-text-muted); }
	.chart-wrap { height: calc(100% - 60px); min-height: 400px; }
	.tab-loading, .tab-error, .tab-empty { display: flex; align-items: center; justify-content: center; height: 50vh; color: var(--cf-text-muted); font-size: 0.9rem; text-align: center; padding: 0 2rem; }
	.tab-error { color: var(--cf-severity-critical); }
</style>
