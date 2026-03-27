<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { zoom, zoomIdentity, type ZoomBehavior } from 'd3-zoom';
	import { select } from 'd3-selection';
	import { drag } from 'd3-drag';
	import type { Simulation } from 'd3-force';
	import type { ForceNode, ForceEdge } from './graph-types';
	import { createSimulation, updateSimulation } from './graph-simulation';
	import 'd3-transition';

	interface Props {
		nodes: ForceNode[];
		edges: ForceEdge[];
		hoveredNode: ForceNode | null;
		dimmedNodes: Set<string>;
		onNodeClick: (node: ForceNode) => void;
		onNodeHover: (node: ForceNode | null, x: number, y: number) => void;
		onNodeRightClick: (node: ForceNode, x: number, y: number) => void;
		onBackgroundClick: () => void;
		onZoomChange: (scale: number) => void;
	}

	let {
		nodes = $bindable(),
		edges = $bindable(),
		hoveredNode,
		dimmedNodes,
		onNodeClick,
		onNodeHover,
		onNodeRightClick,
		onBackgroundClick,
		onZoomChange,
	}: Props = $props();

	let svgEl: SVGSVGElement;
	let width = $state(0);
	let height = $state(0);
	let transform = $state({ x: 0, y: 0, k: 1 });
	let sim: Simulation<ForceNode, ForceEdge>;
	let zoomBehavior: ZoomBehavior<SVGSVGElement, unknown>;
	let resizeObserver: ResizeObserver;
	let animFrame: number;

	onMount(() => {
		const rect = svgEl.parentElement!.getBoundingClientRect();
		width = rect.width;
		height = rect.height;

		sim = createSimulation(width, height, () => {
			if (animFrame) cancelAnimationFrame(animFrame);
			animFrame = requestAnimationFrame(() => {
				nodes = [...nodes];
				edges = [...edges];
			});
		});

		zoomBehavior = zoom<SVGSVGElement, unknown>()
			.scaleExtent([0.1, 8])
			.on('zoom', (event) => {
				transform = event.transform;
				onZoomChange(event.transform.k);
			});

		select(svgEl).call(zoomBehavior);

		select(svgEl).on('click', (event) => {
			if (event.target === svgEl) onBackgroundClick();
		});

		resizeObserver = new ResizeObserver((entries) => {
			const entry = entries[0];
			if (entry) {
				width = entry.contentRect.width;
				height = entry.contentRect.height;
			}
		});
		resizeObserver.observe(svgEl.parentElement!);

		updateSimulation(sim, nodes, edges);
		setupDrag();
	});

	onDestroy(() => {
		if (sim) sim.stop();
		if (resizeObserver) resizeObserver.disconnect();
		if (animFrame) cancelAnimationFrame(animFrame);
	});

	function setupDrag() {
		const dragBehavior = drag<SVGCircleElement, ForceNode>()
			.on('start', (event, d) => {
				if (!event.active) sim.alphaTarget(0.3).restart();
				d.fx = d.x;
				d.fy = d.y;
			})
			.on('drag', (event, d) => {
				d.fx = event.x;
				d.fy = event.y;
			})
			.on('end', (event, d) => {
				if (!event.active) sim.alphaTarget(0);
				d.fx = null;
				d.fy = null;
			});

		select(svgEl).selectAll<SVGCircleElement, ForceNode>('.graph-node').call(dragBehavior);
	}

	$effect(() => {
		if (sim && nodes && edges) {
			updateSimulation(sim, nodes, edges);
			requestAnimationFrame(setupDrag);
		}
	});

	export function zoomIn() {
		select(svgEl).transition().duration(300).call(zoomBehavior.scaleBy, 1.4);
	}

	export function zoomOut() {
		select(svgEl).transition().duration(300).call(zoomBehavior.scaleBy, 0.7);
	}

	export function zoomReset() {
		select(svgEl).transition().duration(500).call(zoomBehavior.transform, zoomIdentity);
	}

	function nodeOpacity(node: ForceNode): number {
		if (dimmedNodes.size === 0) return 1;
		return dimmedNodes.has(node.id) ? 0.1 : 1;
	}

	function edgeOpacity(edge: ForceEdge): number {
		if (dimmedNodes.size === 0) return 0.25;
		const src = typeof edge.source === 'object' ? String(edge.source.id) : String(edge.source);
		const tgt = typeof edge.target === 'object' ? String(edge.target.id) : String(edge.target);
		if (dimmedNodes.has(src) || dimmedNodes.has(tgt)) return 0.03;
		return 0.25;
	}

	function edgeX1(edge: ForceEdge): number {
		return typeof edge.source === 'object' ? (edge.source.x ?? 0) : 0;
	}
	function edgeY1(edge: ForceEdge): number {
		return typeof edge.source === 'object' ? (edge.source.y ?? 0) : 0;
	}
	function edgeX2(edge: ForceEdge): number {
		return typeof edge.target === 'object' ? (edge.target.x ?? 0) : 0;
	}
	function edgeY2(edge: ForceEdge): number {
		return typeof edge.target === 'object' ? (edge.target.y ?? 0) : 0;
	}
</script>

<svg bind:this={svgEl} class="force-graph-svg" {width} {height}>
	<g transform="translate({transform.x},{transform.y}) scale({transform.k})">
		{#each edges as edge (edge.id)}
			<line
				class="graph-edge"
				x1={edgeX1(edge)}
				y1={edgeY1(edge)}
				x2={edgeX2(edge)}
				y2={edgeY2(edge)}
				stroke={edge.color}
				stroke-opacity={edgeOpacity(edge)}
				stroke-width={1.5}
			/>
		{/each}

		{#each nodes as node (node.id)}
			<g
				class="graph-node-group"
				transform="translate({node.x ?? 0},{node.y ?? 0})"
				opacity={nodeOpacity(node)}
				role="button"
				tabindex="-1"
				onclick={() => onNodeClick(node)}
				oncontextmenu={(e) => { e.preventDefault(); onNodeRightClick(node, e.clientX, e.clientY); }}
				onpointerenter={(e) => onNodeHover(node, e.clientX, e.clientY)}
				onpointerleave={() => onNodeHover(null, 0, 0)}
			>
				<circle
					class="graph-node"
					r={node.radius}
					fill={node.color}
					fill-opacity={node.fillOpacity}
					stroke={node.color}
					stroke-width={node.type === 'root' ? 2 : node.type === 'intermediate' ? 1.5 : 1}
				>
					{#if node.pulseRate > 0}
						<animate
							attributeName="stroke-opacity"
							values="1;0.4;1"
							dur="{2 / node.pulseRate}s"
							repeatCount="indefinite"
						/>
					{/if}
				</circle>

				{#if node.type !== 'leaf'}
					<text
						class="node-label"
						y={-node.radius - 4}
						text-anchor="middle"
						fill="#e2e8f0"
						font-size={node.type === 'root' ? '9' : '7'}
						font-weight="600"
					>
						{node.label.length > 24 ? node.label.slice(0, 22) + '...' : node.label}
					</text>
					<text
						class="node-badge"
						y={4}
						text-anchor="middle"
						fill={node.color}
						font-size={node.type === 'root' ? '8' : '6.5'}
					>
						{node.grade} · {node.certCount.toLocaleString()}
					</text>
				{/if}

				{#if (node.type === 'root' || node.type === 'intermediate') && node.certCount > 0}
					<text
						class="expand-indicator"
						y={node.radius + 10}
						text-anchor="middle"
						fill="#64748b"
						font-size="6"
					>
						{node.isExpanded ? '−' : '+'}
					</text>
				{/if}
			</g>
		{/each}
	</g>
</svg>

<style>
	.force-graph-svg {
		width: 100%;
		height: 100%;
		display: block;
		cursor: grab;
	}

	.force-graph-svg:active {
		cursor: grabbing;
	}

	.graph-node-group {
		cursor: pointer;
		transition: opacity 0.2s;
	}

	.node-label, .node-badge, .expand-indicator {
		pointer-events: none;
		user-select: none;
	}

	.graph-edge {
		pointer-events: none;
	}
</style>
