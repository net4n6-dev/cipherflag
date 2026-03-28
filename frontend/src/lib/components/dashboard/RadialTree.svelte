<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { goto } from '$app/navigation';
	import { hierarchy, tree as d3tree } from 'd3-hierarchy';
	import type { PKITreeNode } from '$lib/api';

	interface Props {
		roots: PKITreeNode[];
		totalLeaves: number;
	}

	let { roots, totalLeaves }: Props = $props();

	let containerEl: HTMLDivElement;
	let width = $state(800);
	let height = $state(800);
	let resizeObserver: ResizeObserver;

	const GRADE_COLORS: Record<string, string> = {
		'A+': '#22c55e', 'A': '#22c55e', 'B': '#84cc16',
		'C': '#eab308', 'D': '#f97316', 'F': '#ef4444', '?': '#64748b',
	};

	function gradeColor(g: string): string { return GRADE_COLORS[g] ?? '#64748b'; }

	interface TreePoint {
		x: number; // angle
		y: number; // radius
		name: string;
		grade: string;
		leafCount: number;
		nodeType: string;
		fingerprint: string;
		children?: TreePoint[];
	}

	let treeNodes: TreePoint[] = $state([]);
	let treeLinks: {sx: number; sy: number; tx: number; ty: number; grade: string}[] = $state([]);

	let hoveredNode: TreePoint | null = $state(null);
	let tooltipX = $state(0);
	let tooltipY = $state(0);

	function computeTree() {
		if (roots.length === 0) return;

		const size = Math.min(width, height);
		const radius = size / 2 - 80;
		const cx = size / 2;
		const cy = size / 2;

		// Build hierarchy: virtual root → real roots → intermediates
		const rootData = {
			name: 'PKI',
			grade: '?',
			leaf_count: 0,
			fingerprint: '',
			node_type: 'virtual',
			children: roots.map(r => ({
				name: r.subject_cn,
				grade: r.grade,
				leaf_count: r.leaf_count,
				fingerprint: r.fingerprint,
				node_type: r.node_type,
				children: (r.children ?? []).map(c => ({
					name: c.subject_cn,
					grade: c.grade,
					leaf_count: c.leaf_count,
					fingerprint: c.fingerprint,
					node_type: c.node_type,
					children: (c.children ?? []).map(gc => ({
						name: gc.subject_cn,
						grade: gc.grade,
						leaf_count: gc.leaf_count,
						fingerprint: gc.fingerprint,
						node_type: gc.node_type,
					}))
				}))
			}))
		};

		const root = hierarchy(rootData);

		const treeLayout = d3tree<any>()
			.size([2 * Math.PI, radius])
			.separation((a, b) => (a.parent === b.parent ? 1 : 2) / a.depth);

		treeLayout(root);

		// Convert to points
		const nodes: TreePoint[] = [];
		const links: typeof treeLinks = [];

		root.descendants().forEach((d: any) => {
			if (d.data.node_type === 'virtual') return; // skip virtual root

			const angle = d.x;
			const r = d.y;
			const px = cx + r * Math.cos(angle - Math.PI / 2);
			const py = cy + r * Math.sin(angle - Math.PI / 2);

			nodes.push({
				x: px, y: py,
				name: d.data.name,
				grade: d.data.grade,
				leafCount: d.data.leaf_count,
				nodeType: d.data.node_type,
				fingerprint: d.data.fingerprint,
			});

			if (d.parent && d.parent.data.node_type !== 'virtual') {
				const pr = d.parent.y;
				const pa = d.parent.x;
				links.push({
					sx: cx + pr * Math.cos(pa - Math.PI / 2),
					sy: cy + pr * Math.sin(pa - Math.PI / 2),
					tx: px, ty: py,
					grade: d.data.grade,
				});
			} else if (d.parent && d.parent.data.node_type === 'virtual') {
				// Connect to center
				links.push({
					sx: cx, sy: cy,
					tx: px, ty: py,
					grade: d.data.grade,
				});
			}
		});

		treeNodes = nodes;
		treeLinks = links;
	}

	onMount(() => {
		const rect = containerEl.getBoundingClientRect();
		const size = Math.min(rect.width, 700);
		width = size;
		height = size;

		resizeObserver = new ResizeObserver((entries) => {
			const entry = entries[0];
			if (entry) {
				const s = Math.min(entry.contentRect.width, 700);
				width = s;
				height = s;
				computeTree();
			}
		});
		resizeObserver.observe(containerEl);
		computeTree();
	});

	onDestroy(() => {
		if (resizeObserver) resizeObserver.disconnect();
	});

	$effect(() => {
		if (roots.length > 0 && width > 0) computeTree();
	});

	function nodeRadius(node: TreePoint): number {
		if (node.nodeType === 'root') return 6 + Math.min(node.leafCount / 30, 6);
		if (node.nodeType === 'intermediate') return 4 + Math.min(node.leafCount / 50, 4);
		return 3;
	}

	function handleNodeClick(node: TreePoint) {
		if (node.fingerprint) {
			goto(`/reports?type=ca&issuer_cn=${encodeURIComponent(node.name)}`);
		}
	}
</script>

<div class="radial-tree" bind:this={containerEl}>
	<svg {width} {height}>
		<!-- Center label -->
		<text x={width/2} y={width/2 - 8} text-anchor="middle" fill="#64748b" font-size="8" letter-spacing="0.08em">PKI</text>
		<text x={width/2} y={width/2 + 6} text-anchor="middle" fill="#e2e8f0" font-size="11" font-weight="700">{roots.length} Roots</text>
		<text x={width/2} y={width/2 + 18} text-anchor="middle" fill="#64748b" font-size="8">{totalLeaves.toLocaleString()} certs</text>

		<!-- Links -->
		{#each treeLinks as link}
			<line
				x1={link.sx} y1={link.sy}
				x2={link.tx} y2={link.ty}
				stroke={gradeColor(link.grade)}
				stroke-opacity="0.2"
				stroke-width="1"
			/>
		{/each}

		<!-- Nodes -->
		{#each treeNodes as node}
			{@const r = nodeRadius(node)}
			<g
				class="tree-node"
				onclick={() => handleNodeClick(node)}
				onpointerenter={(e) => { hoveredNode = node; tooltipX = e.clientX; tooltipY = e.clientY; }}
				onpointerleave={() => hoveredNode = null}
				role="button"
				tabindex="-1"
			>
				<circle
					cx={node.x} cy={node.y} r={r}
					fill={gradeColor(node.grade)}
					fill-opacity={hoveredNode === node ? 0.6 : 0.25}
					stroke={gradeColor(node.grade)}
					stroke-width={hoveredNode === node ? 2 : 1}
				/>
				{#if r > 6}
					<text
						x={node.x} y={node.y + r + 10}
						text-anchor="middle" fill="#94a3b8" font-size="7"
					>
						{node.name.length > 18 ? node.name.slice(0, 16) + '...' : node.name}
					</text>
				{/if}
			</g>
		{/each}
	</svg>

	{#if hoveredNode}
		<div class="tree-tooltip" style="left:{tooltipX + 12}px; top:{tooltipY - 8}px">
			<div class="tt-name">{hoveredNode.name}</div>
			<div class="tt-meta">
				<span style="color: {gradeColor(hoveredNode.grade)}">{hoveredNode.grade}</span>
				<span>{hoveredNode.nodeType}</span>
				{#if hoveredNode.leafCount > 0}<span>{hoveredNode.leafCount} certs</span>{/if}
			</div>
			<div class="tt-hint">Click for CA report</div>
		</div>
	{/if}
</div>

<style>
	.radial-tree { width: 100%; display: flex; justify-content: center; }
	svg { display: block; }
	.tree-node { cursor: pointer; }
	.tree-node text { pointer-events: none; user-select: none; }

	.tree-tooltip {
		position: fixed; background: rgba(15, 23, 42, 0.97);
		border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 8px;
		padding: 0.5rem 0.75rem; z-index: 50; pointer-events: none;
		box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
	}
	.tt-name { font-size: 0.8rem; font-weight: 600; color: #e2e8f0; }
	.tt-meta { display: flex; gap: 0.5rem; font-size: 0.7rem; color: #94a3b8; margin-top: 0.125rem; }
	.tt-hint { font-size: 0.6rem; color: var(--cf-accent); margin-top: 0.25rem; }
</style>
