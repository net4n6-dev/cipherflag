<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { api, type BlastRadiusResponse } from '$lib/api';
	import ForceGraph from '$lib/components/graph/ForceGraph.svelte';
	import GraphTooltip from '$lib/components/graph/GraphTooltip.svelte';
	import GraphToolbar from '$lib/components/graph/GraphToolbar.svelte';
	import GraphLegend from '$lib/components/graph/GraphLegend.svelte';
	import type { ForceNode, ForceEdge, GraphMode } from '$lib/components/graph/graph-types';
	import { apiNodeToForceNode, apiEdgeToForceEdge } from '$lib/components/graph/graph-simulation';

	let nodes: ForceNode[] = $state([]);
	let edges: ForceEdge[] = $state([]);
	let expandedCAs: Set<string> = $state(new Set());
	let mode: GraphMode = $state('explore');
	let searchQuery = $state('');
	let blastRadiusTarget: string | null = $state(null);
	let blastRadiusNodes: Set<string> = $state(new Set());
	let blastRadiusSummary: BlastRadiusResponse['summary'] | null = $state(null);
	let hoveredNode: ForceNode | null = $state(null);
	let tooltipX = $state(0);
	let tooltipY = $state(0);
	let selectedGrades: Set<string> = $state(new Set());
	let showExpiredOnly = $state(false);
	let loading = $state(true);
	let error: string | null = $state(null);
	let totalCerts = $state(0);
	let zoomScale = $state(1);

	let graphComponent: ForceGraph;

	let dimmedNodes: Set<string> = $derived.by(() => {
		const dimmed = new Set<string>();

		if (mode === 'blast-radius' && blastRadiusTarget) {
			for (const n of nodes) {
				if (n.id !== blastRadiusTarget && !blastRadiusNodes.has(n.id)) {
					dimmed.add(n.id);
				}
			}
			return dimmed;
		}

		if (searchQuery) {
			const q = searchQuery.toLowerCase();
			for (const n of nodes) {
				if (!n.label.toLowerCase().includes(q) &&
					!n.organization.toLowerCase().includes(q) &&
					!n.id.toLowerCase().startsWith(q)) {
					dimmed.add(n.id);
				}
			}
			return dimmed;
		}

		if (selectedGrades.size > 0) {
			for (const n of nodes) {
				if (!selectedGrades.has(n.grade)) {
					dimmed.add(n.id);
				}
			}
		}

		if (showExpiredOnly) {
			for (const n of nodes) {
				if (n.expiredCount === 0) {
					dimmed.add(n.id);
				}
			}
		}

		return dimmed;
	});

	onMount(async () => {
		try {
			const resp = await api.getAggregatedLandscape();
			nodes = resp.nodes.map(apiNodeToForceNode);
			edges = resp.edges.map((e, i) => apiEdgeToForceEdge(e, i));
			totalCerts = resp.nodes.reduce((sum, n) => sum + n.cert_count, 0);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load landscape';
		}
		loading = false;
	});

	async function handleNodeClick(node: ForceNode) {
		if (mode === 'blast-radius') {
			if (node.type !== 'leaf') {
				await activateBlastRadius(node.id);
			}
			return;
		}

		if (node.type === 'leaf') {
			goto(`/certificates/${node.id}`);
			return;
		}

		if (expandedCAs.has(node.id)) {
			collapseCA(node.id);
		} else {
			await expandCA(node.id);
		}
	}

	async function expandCA(fingerprint: string) {
		try {
			const resp = await api.getCAChildren(fingerprint);
			const newNodes = resp.nodes.map(apiNodeToForceNode);
			const edgeOffset = edges.length;
			const newEdges = resp.edges.map((e, i) => apiEdgeToForceEdge(e, edgeOffset + i));

			const parent = nodes.find(n => n.id === fingerprint);
			if (parent) {
				for (const n of newNodes) {
					n.x = (parent.x ?? 0) + (Math.random() - 0.5) * 40;
					n.y = (parent.y ?? 0) + (Math.random() - 0.5) * 40;
				}
			}

			nodes = [...nodes, ...newNodes];
			edges = [...edges, ...newEdges];

			const next = new Set(expandedCAs);
			next.add(fingerprint);
			expandedCAs = next;

			const parentNode = nodes.find(n => n.id === fingerprint);
			if (parentNode) parentNode.isExpanded = true;
		} catch (e) {
			console.error('Failed to expand CA:', e);
		}
	}

	function collapseCA(fingerprint: string) {
		const childIds = new Set<string>();
		const collectChildren = (parentId: string) => {
			for (const edge of edges) {
				const srcId = edge.sourceId;
				const tgtId = edge.targetId;
				if (srcId === parentId && !childIds.has(tgtId)) {
					const childNode = nodes.find(n => n.id === tgtId);
					if (childNode && childNode.type === 'leaf') {
						childIds.add(tgtId);
					} else if (childNode && expandedCAs.has(tgtId)) {
						collapseCA(tgtId);
						childIds.add(tgtId);
					} else if (childNode && !childNode.isExpanded) {
						childIds.add(tgtId);
					}
				}
			}
		};
		collectChildren(fingerprint);

		nodes = nodes.filter(n => !childIds.has(n.id));
		edges = edges.filter(e => {
			return !childIds.has(e.sourceId) && !childIds.has(e.targetId);
		});

		const next = new Set(expandedCAs);
		next.delete(fingerprint);
		expandedCAs = next;

		const parentNode = nodes.find(n => n.id === fingerprint);
		if (parentNode) parentNode.isExpanded = false;
	}

	async function activateBlastRadius(fingerprint: string) {
		try {
			const resp = await api.getBlastRadius(fingerprint);
			blastRadiusTarget = fingerprint;
			blastRadiusNodes = new Set(resp.nodes.map(n => n.fingerprint));
			blastRadiusSummary = resp.summary;

			const existingIds = new Set(nodes.map(n => n.id));
			const newNodes = resp.nodes
				.filter(n => !existingIds.has(n.fingerprint))
				.map(apiNodeToForceNode);
			const edgeOffset = edges.length;
			const newEdges = resp.edges
				.filter(e => !edges.some(existing => {
					return existing.sourceId === e.source && existing.targetId === e.target;
				}))
				.map((e, i) => apiEdgeToForceEdge(e, edgeOffset + i));

			if (newNodes.length > 0 || newEdges.length > 0) {
				const target = nodes.find(n => n.id === fingerprint);
				if (target) {
					for (const n of newNodes) {
						n.x = (target.x ?? 0) + (Math.random() - 0.5) * 80;
						n.y = (target.y ?? 0) + (Math.random() - 0.5) * 80;
					}
				}
				nodes = [...nodes, ...newNodes];
				edges = [...edges, ...newEdges];
			}
		} catch (e) {
			console.error('Failed to load blast radius:', e);
		}
	}

	function deactivateBlastRadius() {
		blastRadiusTarget = null;
		blastRadiusNodes = new Set();
		blastRadiusSummary = null;
		mode = 'explore';
	}

	function handleBackgroundClick() {
		if (mode === 'blast-radius') {
			deactivateBlastRadius();
		}
		hoveredNode = null;
	}

	function handleNodeHover(node: ForceNode | null, x: number, y: number) {
		hoveredNode = node;
		tooltipX = x;
		tooltipY = y;
	}

	function handleNodeRightClick(node: ForceNode, _x: number, _y: number) {
		if (node.type !== 'leaf') {
			mode = 'blast-radius';
			activateBlastRadius(node.id);
		}
	}

	function handleSearchChange(q: string) {
		searchQuery = q;
		mode = q ? 'search' : 'explore';
	}

	function handleGradeToggle(grade: string) {
		const next = new Set(selectedGrades);
		if (next.has(grade)) next.delete(grade);
		else next.add(grade);
		selectedGrades = next;
	}

	function handleExpiredToggle() {
		showExpiredOnly = !showExpiredOnly;
	}

	function handleBlastRadiusToggle() {
		if (mode === 'blast-radius') {
			deactivateBlastRadius();
		} else {
			mode = 'blast-radius';
		}
	}

	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'Escape') {
			if (mode === 'blast-radius') deactivateBlastRadius();
			else if (searchQuery) handleSearchChange('');
		}
	}
</script>

<svelte:window onkeydown={handleKeydown} />

<div class="pki-graph-page">
	{#if loading}
		<div class="loading-overlay">Loading PKI landscape...</div>
	{:else if error}
		<div class="error-overlay">{error}</div>
	{:else}
		<ForceGraph
			bind:this={graphComponent}
			bind:nodes
			bind:edges
			{hoveredNode}
			{dimmedNodes}
			onNodeClick={handleNodeClick}
			onNodeHover={handleNodeHover}
			onNodeRightClick={handleNodeRightClick}
			onBackgroundClick={handleBackgroundClick}
			onZoomChange={(s) => zoomScale = s}
		/>

		<GraphToolbar
			{searchQuery}
			{mode}
			{selectedGrades}
			{showExpiredOnly}
			nodeCount={nodes.filter(n => n.type !== 'leaf').length}
			edgeCount={edges.length}
			expandedCount={expandedCAs.size}
			onSearchChange={handleSearchChange}
			onGradeToggle={handleGradeToggle}
			onExpiredToggle={handleExpiredToggle}
			onBlastRadiusToggle={handleBlastRadiusToggle}
			onZoomIn={() => graphComponent.zoomIn()}
			onZoomOut={() => graphComponent.zoomOut()}
			onZoomReset={() => graphComponent.zoomReset()}
		/>

		<GraphTooltip node={hoveredNode} x={tooltipX} y={tooltipY} />

		<GraphLegend
			nodeCount={nodes.filter(n => n.type !== 'leaf').length}
			{totalCerts}
			expandedCount={expandedCAs.size}
		/>

		{#if mode === 'blast-radius' && blastRadiusSummary}
			<div class="blast-badge">
				<strong>Blast Radius</strong>
				<span>{blastRadiusSummary.total_certs} certs</span>
				{#if blastRadiusSummary.expired > 0}
					<span class="blast-expired">{blastRadiusSummary.expired} expired</span>
				{/if}
				{#if blastRadiusSummary.grade_f > 0}
					<span class="blast-gradef">{blastRadiusSummary.grade_f} grade F</span>
				{/if}
				<button class="blast-close" onclick={deactivateBlastRadius}>Esc to close</button>
			</div>
		{/if}
	{/if}
</div>

<style>
	.pki-graph-page {
		position: relative;
		width: 100%;
		height: 100%;
		background: #0a0e17;
		overflow: hidden;
	}

	.loading-overlay,
	.error-overlay {
		display: flex;
		align-items: center;
		justify-content: center;
		height: 100%;
		color: var(--cf-text-muted);
		font-size: 0.9rem;
	}

	.error-overlay {
		color: var(--cf-risk-critical);
	}

	.blast-badge {
		position: absolute;
		top: 56px;
		left: 50%;
		transform: translateX(-50%);
		background: rgba(15, 23, 42, 0.95);
		border: 1px solid rgba(249, 115, 22, 0.3);
		border-radius: 8px;
		padding: 0.5rem 1rem;
		display: flex;
		align-items: center;
		gap: 0.75rem;
		font-size: 0.8rem;
		color: #e2e8f0;
		z-index: 15;
	}

	.blast-badge strong {
		color: #f97316;
	}

	.blast-expired {
		color: #ef4444;
	}

	.blast-gradef {
		color: #ef4444;
	}

	.blast-close {
		background: rgba(249, 115, 22, 0.15);
		border: 1px solid rgba(249, 115, 22, 0.3);
		border-radius: 4px;
		padding: 0.15rem 0.5rem;
		font-size: 0.7rem;
		color: #f97316;
		cursor: pointer;
	}
</style>
