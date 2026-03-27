<script lang="ts">
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import ChainFlowTab from '$lib/components/analytics/ChainFlowTab.svelte';
	import OwnershipTab from '$lib/components/analytics/OwnershipTab.svelte';

	const TABS = [
		{ id: 'chain-flow', label: 'Chain Flow' },
		{ id: 'ownership', label: 'Ownership' },
	] as const;

	type TabId = typeof TABS[number]['id'];

	let activeTab: TabId = $derived(
		(page.url.searchParams.get('tab') as TabId) || 'chain-flow'
	);

	function switchTab(tab: TabId) {
		const url = new URL(page.url);
		url.searchParams.set('tab', tab);
		goto(url.toString(), { replaceState: true, noScroll: true });
	}
</script>

<div class="analytics-page">
	<nav class="tab-bar">
		{#each TABS as tab}
			<button
				class="tab"
				class:active={activeTab === tab.id}
				onclick={() => switchTab(tab.id)}
			>
				{tab.label}
			</button>
		{/each}
	</nav>

	<div class="tab-content">
		{#if activeTab === 'chain-flow'}
			<ChainFlowTab />
		{:else if activeTab === 'ownership'}
			<OwnershipTab />
		{/if}
	</div>
</div>

<style>
	.analytics-page { display: flex; flex-direction: column; height: 100%; overflow: hidden; }
	.tab-bar { display: flex; gap: 0; border-bottom: 1px solid var(--cf-border); background: var(--cf-bg-secondary); flex-shrink: 0; padding: 0 1.5rem; }
	.tab { padding: 0.75rem 1.25rem; font-size: 0.85rem; font-weight: 500; color: var(--cf-text-secondary); background: none; border: none; border-bottom: 2px solid transparent; cursor: pointer; transition: all 0.15s; }
	.tab:hover { color: var(--cf-text-primary); }
	.tab.active { color: var(--cf-accent); border-bottom-color: var(--cf-accent); }
	.tab-content { flex: 1; overflow: hidden; }
</style>
