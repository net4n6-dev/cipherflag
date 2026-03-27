<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { api } from '$lib/api';
	import type { ChainFlowNode, ChainFlowLink } from '$lib/api';
	import SankeyChart from './SankeyChart.svelte';

	let nodes: ChainFlowNode[] = $state([]);
	let links: ChainFlowLink[] = $state([]);
	let loading = $state(true);
	let error: string | null = $state(null);

	onMount(async () => {
		try {
			const resp = await api.getChainFlow();
			nodes = resp.nodes;
			links = resp.links;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load chain flow';
		}
		loading = false;
	});

	function handleNodeClick(nodeId: string, nodeType: string) {
		if (nodeType === 'leaf-aggregate') {
			const intermediateId = nodeId.replace('leaves-fp-', 'fp-');
			const intermediateNode = nodes.find(n => n.id === intermediateId);
			if (intermediateNode) {
				goto(`/certificates?issuer_cn=${encodeURIComponent(intermediateNode.label)}`);
			}
		} else {
			const fp = nodeId.replace('fp-', '');
			goto(`/pki?select=${fp}`);
		}
	}
</script>

<div class="chain-flow-tab">
	{#if loading}
		<div class="tab-loading">Loading chain flow...</div>
	{:else if error}
		<div class="tab-error">{error}</div>
	{:else if nodes.length === 0}
		<div class="tab-empty">No certificate chain data available.</div>
	{:else}
		<div class="tab-header">
			<h2>Certificate Chain Flow</h2>
			<span class="tab-meta">
				{nodes.filter(n => n.type === 'root').length} roots ·
				{nodes.filter(n => n.type === 'intermediate').length} intermediates ·
				{nodes.filter(n => n.type === 'leaf-aggregate').reduce((s, n) => s + n.cert_count, 0).toLocaleString()} leaf certs
			</span>
		</div>
		<SankeyChart {nodes} {links} onNodeClick={handleNodeClick} />
	{/if}
</div>

<style>
	.chain-flow-tab { padding: 1.5rem; height: 100%; overflow-y: auto; }
	.tab-header { display: flex; align-items: baseline; gap: 1rem; margin-bottom: 1rem; }
	.tab-header h2 { margin: 0; font-size: 1.1rem; font-weight: 700; color: var(--cf-text-primary); }
	.tab-meta { font-size: 0.8rem; color: var(--cf-text-muted); }
	.tab-loading, .tab-error, .tab-empty { display: flex; align-items: center; justify-content: center; height: 50vh; color: var(--cf-text-muted); font-size: 0.9rem; }
	.tab-error { color: var(--cf-risk-critical); }
</style>
