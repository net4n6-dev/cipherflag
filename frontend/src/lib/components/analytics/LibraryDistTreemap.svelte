<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { hierarchy, treemap, treemapSquarify } from 'd3-hierarchy';
	import type { LibraryDistItem } from '$lib/api';

	interface Props {
		items: LibraryDistItem[];
	}

	let { items }: Props = $props();

	let containerEl: HTMLDivElement;
	let width = $state(800);
	let height = $state(400);
	let resizeObserver: ResizeObserver;

	interface TreeRect {
		x: number; y: number; w: number; h: number;
		library: string; version: string;
		hostCount: number; hasCves: boolean; showLabel: boolean;
	}

	let rects: TreeRect[] = $state([]);
	let hoveredRect: TreeRect | null = $state(null);
	let tooltipX = $state(0);
	let tooltipY = $state(0);

	const CVE_COLOR = '#ef4444';
	const SAFE_COLOR = '#22c55e';

	function computeLayout() {
		if (items.length === 0) { rects = []; return; }

		const children = items.map((item) => ({
			name: `${item.library} ${item.version}`,
			value: item.host_count,
			library: item.library,
			version: item.version,
			hostCount: item.host_count,
			hasCves: item.has_cves,
		}));

		const root = hierarchy({ name: 'root', children })
			.sum(d => (d as any).value ?? 0)
			.sort((a, b) => (b.value ?? 0) - (a.value ?? 0));

		treemap<any>()
			.size([width, height])
			.paddingOuter(4)
			.paddingInner(2)
			.tile(treemapSquarify)
			(root);

		const totalArea = width * height;
		rects = (root.leaves() as any[]).map(leaf => {
			const d = leaf.data;
			const w = (leaf.x1 ?? 0) - (leaf.x0 ?? 0);
			const h = (leaf.y1 ?? 0) - (leaf.y0 ?? 0);
			return {
				x: leaf.x0 ?? 0, y: leaf.y0 ?? 0, w, h,
				library: d.library ?? '',
				version: d.version ?? '',
				hostCount: d.hostCount ?? 0,
				hasCves: d.hasCves ?? false,
				showLabel: totalArea > 0 && (w * h) / totalArea > 0.02 && w > 50 && h > 24,
			};
		});
	}

	onMount(() => {
		const rect = containerEl.getBoundingClientRect();
		width = rect.width || width;
		resizeObserver = new ResizeObserver((entries) => {
			const entry = entries[0];
			if (entry) { width = entry.contentRect.width; computeLayout(); }
		});
		resizeObserver.observe(containerEl);
		computeLayout();
	});

	onDestroy(() => { if (resizeObserver) resizeObserver.disconnect(); });

	$effect(() => { if (items && width > 0) computeLayout(); });
</script>

<div class="treemap-container" bind:this={containerEl}>
	<svg {width} {height}>
		{#each rects as r, i (i)}
			<g
				transform="translate({r.x},{r.y})"
				onpointerenter={(e) => { hoveredRect = r; tooltipX = e.clientX; tooltipY = e.clientY; }}
				onpointerleave={() => hoveredRect = null}
				role="img"
				aria-label={`${r.library} ${r.version}`}
			>
				<rect width={r.w} height={r.h} fill={r.hasCves ? CVE_COLOR : SAFE_COLOR} fill-opacity={0.25}
					stroke={r.hasCves ? CVE_COLOR : SAFE_COLOR} stroke-opacity={0.6} stroke-width={1} rx={3} />
				{#if r.showLabel}
					<text x={4} y={14} fill="#e2e8f0" font-size="10" font-weight="600">
						{r.library.length > r.w / 6 ? r.library.slice(0, Math.floor(r.w / 6)) + '...' : r.library}
					</text>
					{#if r.h > 30}
						<text x={4} y={26} fill="#94a3b8" font-size="9">{r.version}</text>
					{/if}
					<text x={4} y={r.h - 6} fill="#64748b" font-size="9">{r.hostCount.toLocaleString()}</text>
				{/if}
			</g>
		{/each}
	</svg>

	{#if hoveredRect}
		<div class="treemap-tooltip" style="left:{tooltipX + 12}px; top:{tooltipY - 8}px">
			<div class="tt-lib">{hoveredRect.library}</div>
			<div class="tt-ver">v{hoveredRect.version}</div>
			<div class="tt-stats">
				<span>{hoveredRect.hostCount.toLocaleString()} host{hoveredRect.hostCount === 1 ? '' : 's'}</span>
				{#if hoveredRect.hasCves}<span class="tt-cve">has CVEs</span>{/if}
			</div>
		</div>
	{/if}
</div>

<style>
	.treemap-container { position: relative; width: 100%; }
	svg { display: block; }
	g { cursor: default; }
	g rect { transition: fill-opacity 0.15s; }
	g:hover rect { fill-opacity: 0.4; }
	text { pointer-events: none; user-select: none; }
	.treemap-tooltip { position: fixed; background: rgba(15, 23, 42, 0.95); border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 8px; padding: 0.5rem 0.75rem; z-index: 50; pointer-events: none; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4); }
	.tt-lib { font-size: 0.8rem; font-weight: 600; color: #e2e8f0; }
	.tt-ver { font-size: 0.7rem; color: #64748b; margin-bottom: 0.25rem; }
	.tt-stats { display: flex; gap: 0.75rem; font-size: 0.75rem; color: #94a3b8; }
	.tt-cve { color: #ef4444; font-weight: 600; }
</style>
