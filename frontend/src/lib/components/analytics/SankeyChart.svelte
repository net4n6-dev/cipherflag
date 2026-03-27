<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { sankey, sankeyLinkHorizontal, type SankeyNode, type SankeyLink } from 'd3-sankey';
	import { select } from 'd3-selection';
	import type { ChainFlowNode, ChainFlowLink } from '$lib/api';
	import { gradeColor } from './analytics-types';
	import 'd3-transition';

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

	function computeLayout() {
		if (nodes.length === 0) return;

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
			{@const src = link.source as SNode}
			{@const tgt = link.target as SNode}
			<path
				class="sankey-link"
				d={linkPath(link)}
				fill="none"
				stroke={gradeColor((link as unknown as ChainFlowLink).worst_grade)}
				stroke-opacity={hoveredLink === link ? 0.8 : 0.4}
				stroke-width={Math.max(link.width ?? 1, 1)}
				onpointerenter={(e) => handleLinkHover(link, e)}
				onpointerleave={() => handleLinkHover(null)}
			/>
		{/each}

		{#each sankeyNodes as node, i (i)}
			{@const d = node as unknown as ChainFlowNode}
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
					fill={gradeColor(d.grade)}
					fill-opacity={0.25}
					stroke={gradeColor(d.grade)}
					stroke-width={1}
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
