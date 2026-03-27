<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { hierarchy, treemap, treemapSquarify } from 'd3-hierarchy';
	import type { OwnershipGroup } from '$lib/api';
	import { gradeColor } from './analytics-types';

	interface Props {
		groups: OwnershipGroup[];
		onGroupClick: (issuerOrg: string, subjectOU: string) => void;
	}

	let { groups, onGroupClick }: Props = $props();

	let containerEl: HTMLDivElement;
	let width = $state(800);
	let height = $state(400);
	let resizeObserver: ResizeObserver;

	interface TreeRect {
		x: number; y: number; w: number; h: number;
		issuerOrg: string; subjectOU: string;
		certCount: number; expiredCount: number;
		grade: string; avgScore: number; showLabel: boolean;
	}

	let rects: TreeRect[] = $state([]);
	let hoveredRect: TreeRect | null = $state(null);
	let tooltipX = $state(0);
	let tooltipY = $state(0);

	function computeLayout() {
		if (groups.length === 0) { rects = []; return; }

		const byIssuer = new Map<string, OwnershipGroup[]>();
		for (const g of groups) {
			const existing = byIssuer.get(g.issuer_org) ?? [];
			existing.push(g);
			byIssuer.set(g.issuer_org, existing);
		}

		const children = Array.from(byIssuer.entries()).map(([org, items]) => ({
			name: org,
			children: items.map(g => ({
				name: g.subject_ou || 'Unspecified',
				value: g.cert_count,
				issuerOrg: g.issuer_org,
				subjectOU: g.subject_ou,
				expiredCount: g.expired_count,
				grade: g.worst_grade,
				avgScore: g.avg_score,
			})),
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
				issuerOrg: d.issuerOrg ?? leaf.parent?.data.name ?? '',
				subjectOU: d.subjectOU ?? '',
				certCount: d.value ?? 0,
				expiredCount: d.expiredCount ?? 0,
				grade: d.grade ?? '?',
				avgScore: d.avgScore ?? 0,
				showLabel: (w * h) / totalArea > 0.03 && w > 60 && h > 30,
			};
		});
	}

	onMount(() => {
		const rect = containerEl.getBoundingClientRect();
		width = rect.width;
		resizeObserver = new ResizeObserver((entries) => {
			const entry = entries[0];
			if (entry) { width = entry.contentRect.width; computeLayout(); }
		});
		resizeObserver.observe(containerEl);
		computeLayout();
	});

	onDestroy(() => { if (resizeObserver) resizeObserver.disconnect(); });

	$effect(() => { if (groups && width > 0) computeLayout(); });
</script>

<div class="treemap-container" bind:this={containerEl}>
	<svg {width} {height}>
		{#each rects as r, i (i)}
			<g
				transform="translate({r.x},{r.y})"
				onclick={() => onGroupClick(r.issuerOrg, r.subjectOU)}
				onpointerenter={(e) => { hoveredRect = r; tooltipX = e.clientX; tooltipY = e.clientY; }}
				onpointerleave={() => hoveredRect = null}
				role="button"
				tabindex="-1"
			>
				<rect width={r.w} height={r.h} fill={gradeColor(r.grade)} fill-opacity={0.2}
					stroke={gradeColor(r.grade)} stroke-opacity={0.5} stroke-width={1} rx={3} />
				{#if r.showLabel}
					<text x={4} y={14} fill="#e2e8f0" font-size="10" font-weight="600">
						{r.issuerOrg.length > r.w / 6 ? r.issuerOrg.slice(0, Math.floor(r.w / 6)) + '...' : r.issuerOrg}
					</text>
					{#if r.subjectOU && r.h > 44}
						<text x={4} y={26} fill="#94a3b8" font-size="9">{r.subjectOU === '' ? 'Unspecified' : r.subjectOU}</text>
					{/if}
					<text x={4} y={r.h - 6} fill="#64748b" font-size="9">{r.certCount.toLocaleString()}</text>
				{/if}
			</g>
		{/each}
	</svg>

	{#if hoveredRect}
		<div class="treemap-tooltip" style="left:{tooltipX + 12}px; top:{tooltipY - 8}px">
			<div class="tt-org">{hoveredRect.issuerOrg}</div>
			<div class="tt-ou">OU: {hoveredRect.subjectOU || 'Unspecified'}</div>
			<div class="tt-stats">
				<span>{hoveredRect.certCount.toLocaleString()} certs</span>
				{#if hoveredRect.expiredCount > 0}<span class="tt-expired">{hoveredRect.expiredCount} expired</span>{/if}
				<span>Score: {hoveredRect.avgScore.toFixed(0)}</span>
				<span class="tt-grade" style="color:{gradeColor(hoveredRect.grade)}">Grade {hoveredRect.grade}</span>
			</div>
		</div>
	{/if}
</div>

<style>
	.treemap-container { position: relative; width: 100%; }
	svg { display: block; }
	g { cursor: pointer; }
	g rect { transition: fill-opacity 0.15s; }
	g:hover rect { fill-opacity: 0.35; }
	text { pointer-events: none; user-select: none; }
	.treemap-tooltip { position: fixed; background: rgba(15, 23, 42, 0.95); border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 8px; padding: 0.5rem 0.75rem; z-index: 50; pointer-events: none; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4); }
	.tt-org { font-size: 0.8rem; font-weight: 600; color: #e2e8f0; }
	.tt-ou { font-size: 0.7rem; color: #64748b; margin-bottom: 0.25rem; }
	.tt-stats { display: flex; gap: 0.75rem; font-size: 0.75rem; color: #94a3b8; }
	.tt-expired { color: #ef4444; }
	.tt-grade { font-weight: 600; }
</style>
