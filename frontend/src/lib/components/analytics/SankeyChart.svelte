<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { sankey, sankeyLinkHorizontal, type SankeyNode, type SankeyLink } from 'd3-sankey';
	import type { ChainFlowNode, ChainFlowLink } from '$lib/api';
	import { gradeColor } from './analytics-types';

	interface Props {
		nodes: ChainFlowNode[];
		links: ChainFlowLink[];
		onNodeClick: (nodeId: string, nodeType: string) => void;
	}

	let { nodes, links, onNodeClick }: Props = $props();

	let containerEl: HTMLDivElement;
	let width = $state(900);
	let height = $state(500);
	let resizeObserver: ResizeObserver;

	type SNode = SankeyNode<ChainFlowNode, ChainFlowLink>;
	type SLink = SankeyLink<ChainFlowNode, ChainFlowLink>;

	let sankeyNodes: SNode[] = $state([]);
	let sankeyLinks: SLink[] = $state([]);

	let hoveredLink: SLink | null = $state(null);
	let hoveredNode: SNode | null = $state(null);
	let tooltipX = $state(0);
	let tooltipY = $state(0);

	// Categorical palette — 16 distinct colors for root CA families
	const ORG_PALETTE = [
		'#38bdf8', '#f472b6', '#a78bfa', '#fb923c',
		'#34d399', '#facc15', '#f87171', '#60a5fa',
		'#c084fc', '#4ade80', '#fbbf24', '#e879f9',
		'#22d3ee', '#a3e635', '#f97316', '#94a3b8',
	];

	// Map each root CA to a color; intermediates/leaves inherit from their root
	let rootColorMap: Map<string, string> = $state(new Map());

	interface LegendEntry {
		label: string;
		color: string;
		certCount: number;
	}
	let legendEntries: LegendEntry[] = $state([]);

	function buildColorMap() {
		const roots = nodes.filter(n => n.type === 'root');
		const map = new Map<string, string>();

		// Assign colors to roots
		roots.forEach((r, i) => {
			map.set(r.id, ORG_PALETTE[i % ORG_PALETTE.length]);
		});

		// Walk links to propagate root color to intermediates and leaf-aggregates
		// Build a parent map: target → source for root-to-intermediate links
		const parentOf = new Map<string, string>();
		for (const link of links) {
			const srcNode = nodes.find(n => n.id === link.source);
			if (srcNode && (srcNode.type === 'root' || srcNode.type === 'intermediate')) {
				parentOf.set(link.target, link.source);
			}
		}

		// Trace each node back to its root
		function findRoot(nodeId: string): string | undefined {
			const visited = new Set<string>();
			let current = nodeId;
			while (parentOf.has(current) && !visited.has(current)) {
				visited.add(current);
				current = parentOf.get(current)!;
			}
			return map.has(current) ? current : undefined;
		}

		for (const n of nodes) {
			if (!map.has(n.id)) {
				const rootId = findRoot(n.id);
				if (rootId) {
					map.set(n.id, map.get(rootId)!);
				} else {
					map.set(n.id, '#64748b');
				}
			}
		}

		rootColorMap = map;

		// Build legend from roots, sorted by cert count
		legendEntries = roots
			.map(r => ({
				label: r.label.length > 32 ? r.label.slice(0, 30) + '...' : r.label,
				color: map.get(r.id) ?? '#64748b',
				certCount: r.cert_count,
			}))
			.sort((a, b) => b.certCount - a.certCount);
	}

	function nodeColor(nodeId: string): string {
		return rootColorMap.get(nodeId) ?? '#64748b';
	}

	function linkColor(link: SLink): string {
		const srcId = typeof link.source === 'object' ? (link.source as unknown as ChainFlowNode).id : String(link.source);
		return rootColorMap.get(srcId) ?? '#64748b';
	}

	function computeLayout() {
		if (nodes.length === 0) return;

		buildColorMap();

		const nodeMap = new Map(nodes.map((n, i) => [n.id, i]));
		const validLinks = links.filter(l => nodeMap.has(l.source) && nodeMap.has(l.target) && l.value > 0);

		const layout = sankey<ChainFlowNode, ChainFlowLink>()
			.nodeId(d => d.id)
			.nodeWidth(16)
			.nodePadding(8)
			.extent([[60, 20], [width - 60, height - 20]]);

		const graph = layout({
			nodes: nodes.map(n => ({ ...n })),
			links: validLinks.map(l => ({ ...l })),
		});

		sankeyNodes = graph.nodes as SNode[];
		sankeyLinks = graph.links as SLink[];
	}

	onMount(() => {
		const rect = containerEl.getBoundingClientRect();
		width = rect.width;
		height = Math.max(400, Math.min(700, nodes.length * 12 + 100));

		resizeObserver = new ResizeObserver((entries) => {
			const entry = entries[0];
			if (entry) {
				width = entry.contentRect.width;
				computeLayout();
			}
		});
		resizeObserver.observe(containerEl);

		computeLayout();
	});

	onDestroy(() => {
		if (resizeObserver) resizeObserver.disconnect();
	});

	$effect(() => {
		if (nodes && links && width > 0) {
			computeLayout();
		}
	});

	function linkPath(link: SLink): string {
		return sankeyLinkHorizontal()(link as any) ?? '';
	}

	function nodeLabel(node: SNode): string {
		const d = node as unknown as ChainFlowNode;
		if (d.type === 'leaf-aggregate') return `${d.cert_count.toLocaleString()} leaves`;
		const label = d.label.length > 28 ? d.label.slice(0, 26) + '...' : d.label;
		return label;
	}

	function handleLinkHover(link: SLink | null, e?: PointerEvent) {
		hoveredLink = link;
		if (e) { tooltipX = e.clientX; tooltipY = e.clientY; }
	}

	function handleNodeHover(node: SNode | null, e?: PointerEvent) {
		hoveredNode = node;
		if (e) { tooltipX = e.clientX; tooltipY = e.clientY; }
	}
</script>

<div class="sankey-container" bind:this={containerEl}>
	<svg {width} {height}>
		{#each sankeyLinks as link, i (i)}
			<path
				class="sankey-link"
				d={linkPath(link)}
				fill="none"
				stroke={linkColor(link)}
				stroke-opacity={hoveredLink === link ? 0.85 : 0.45}
				stroke-width={Math.max(link.width ?? 1, 3)}
				onpointerenter={(e) => handleLinkHover(link, e)}
				onpointerleave={() => handleLinkHover(null)}
			/>
		{/each}

		{#each sankeyNodes as node, i (i)}
			{@const d = node as unknown as ChainFlowNode}
			{@const color = nodeColor(d.id)}
			<g
				class="sankey-node"
				transform="translate({node.x0 ?? 0},{node.y0 ?? 0})"
				onclick={() => onNodeClick(d.id, d.type)}
				onpointerenter={(e) => handleNodeHover(node, e)}
				onpointerleave={() => handleNodeHover(null)}
				role="button"
				tabindex="-1"
			>
				<rect
					width={(node.x1 ?? 0) - (node.x0 ?? 0)}
					height={(node.y1 ?? 0) - (node.y0 ?? 0)}
					fill={color}
					fill-opacity={0.3}
					stroke={color}
					stroke-width={1.5}
					rx={3}
				/>
				{#if ((node.y1 ?? 0) - (node.y0 ?? 0)) > 14}
					<text
						x={d.type === 'leaf-aggregate' ? -6 : ((node.x1 ?? 0) - (node.x0 ?? 0)) + 6}
						y={((node.y1 ?? 0) - (node.y0 ?? 0)) / 2}
						text-anchor={d.type === 'leaf-aggregate' ? 'end' : 'start'}
						dominant-baseline="middle"
						fill="#cbd5e1"
						font-size="11"
					>
						{nodeLabel(node)}
					</text>
				{/if}
			</g>
		{/each}
	</svg>

	<div class="column-labels">
		<span style="left: 60px">Root CAs</span>
		<span style="left: {width / 2}px; transform: translateX(-50%)">Intermediates</span>
		<span style="right: 60px">Leaf Certificates</span>
	</div>

	<!-- Legend: root CA color reference -->
	{#if legendEntries.length > 0}
		<div class="sankey-legend">
			{#each legendEntries as entry}
				<div class="legend-item">
					<span class="legend-dot" style="background: {entry.color}"></span>
					<span class="legend-label">{entry.label}</span>
					<span class="legend-count">{entry.certCount.toLocaleString()}</span>
				</div>
			{/each}
		</div>
	{/if}

	{#if hoveredLink}
		{@const src = hoveredLink.source as unknown as ChainFlowNode}
		{@const tgt = hoveredLink.target as unknown as ChainFlowNode}
		{@const ld = hoveredLink as unknown as ChainFlowLink}
		<div class="sankey-tooltip" style="left:{tooltipX + 12}px; top:{tooltipY - 8}px">
			<div class="tt-flow">{src.label} &rarr; {tgt.label}</div>
			<div class="tt-stats">
				<span>{ld.value.toLocaleString()} certs</span>
				{#if ld.expired_count > 0}<span class="tt-expired">{ld.expired_count} expired</span>{/if}
				<span class="tt-grade" style="color:{gradeColor(ld.worst_grade)}">Grade {ld.worst_grade}</span>
			</div>
		</div>
	{/if}

	{#if hoveredNode && !hoveredLink}
		{@const nd = hoveredNode as unknown as ChainFlowNode}
		<div class="sankey-tooltip" style="left:{tooltipX + 12}px; top:{tooltipY - 8}px">
			<div class="tt-flow">{nd.label}</div>
			<div class="tt-stats">
				<span>{nd.cert_count.toLocaleString()} certs</span>
				{#if nd.expired_count > 0}<span class="tt-expired">{nd.expired_count} expired</span>{/if}
				<span class="tt-grade" style="color:{gradeColor(nd.grade)}">Grade {nd.grade}</span>
			</div>
		</div>
	{/if}
</div>

<style>
	.sankey-container {
		position: relative;
		width: 100%;
	}

	svg { display: block; }

	.sankey-link { cursor: pointer; transition: stroke-opacity 0.15s; }
	.sankey-node { cursor: pointer; }

	.column-labels {
		position: absolute;
		top: 2px;
		left: 0;
		right: 0;
		display: flex;
		justify-content: space-between;
		pointer-events: none;
	}

	.column-labels span {
		position: absolute;
		font-size: 0.65rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: #64748b;
	}

	/* Legend */
	.sankey-legend {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem 1.25rem;
		padding: 0.75rem 60px;
		margin-top: 0.5rem;
		border-top: 1px solid rgba(56, 189, 248, 0.08);
	}

	.legend-item {
		display: flex;
		align-items: center;
		gap: 0.375rem;
	}

	.legend-dot {
		width: 10px;
		height: 10px;
		border-radius: 2px;
		flex-shrink: 0;
	}

	.legend-label {
		font-size: 0.75rem;
		color: #cbd5e1;
	}

	.legend-count {
		font-size: 0.7rem;
		color: #64748b;
		font-variant-numeric: tabular-nums;
	}

	.sankey-tooltip {
		position: fixed;
		background: rgba(15, 23, 42, 0.95);
		border: 1px solid rgba(56, 189, 248, 0.25);
		border-radius: 8px;
		padding: 0.5rem 0.75rem;
		z-index: 50;
		pointer-events: none;
		box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
	}

	.tt-flow { font-size: 0.8rem; font-weight: 600; color: #e2e8f0; margin-bottom: 0.25rem; }
	.tt-stats { display: flex; gap: 0.75rem; font-size: 0.75rem; color: #94a3b8; }
	.tt-expired { color: #ef4444; }
	.tt-grade { font-weight: 600; }
</style>
