<script lang="ts">
	import type { ForceNode } from './graph-types';

	interface Props {
		node: ForceNode | null;
		x: number;
		y: number;
	}

	let { node, x, y }: Props = $props();
</script>

{#if node}
	<div class="graph-tooltip" style="left: {x + 12}px; top: {y - 8}px;">
		<div class="tt-name">{node.label}</div>
		{#if node.organization}
			<div class="tt-org">{node.organization}</div>
		{/if}
		<div class="tt-grid">
			<span class="tt-key">Grade</span>
			<span class="tt-val" style="color: {node.color}; font-weight: 600;">{node.grade}</span>
			{#if node.type !== 'leaf'}
				<span class="tt-key">Certificates</span>
				<span class="tt-val">{node.certCount.toLocaleString()}</span>
				<span class="tt-key">Expired</span>
				<span class="tt-val">{node.expiredCount}</span>
				<span class="tt-key">Avg Score</span>
				<span class="tt-val">{node.avgScore.toFixed(1)}</span>
			{/if}
			<span class="tt-key">Key</span>
			<span class="tt-val">{node.keyAlgorithm} {node.keySizeBits}</span>
		</div>
		<div class="tt-hint">
			{#if node.type === 'leaf'}
				Click to view certificate
			{:else if node.isExpanded}
				Click to collapse
			{:else}
				Click to expand · Right-click for actions
			{/if}
		</div>
	</div>
{/if}

<style>
	.graph-tooltip {
		position: fixed;
		background: rgba(15, 23, 42, 0.95);
		border: 1px solid rgba(56, 189, 248, 0.25);
		border-radius: 8px;
		padding: 0.75rem;
		min-width: 200px;
		max-width: 300px;
		z-index: 50;
		pointer-events: none;
		box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
	}

	.tt-name {
		font-size: 0.8rem;
		font-weight: 600;
		color: #e2e8f0;
		margin-bottom: 0.125rem;
		word-break: break-word;
	}

	.tt-org {
		font-size: 0.7rem;
		color: #64748b;
		margin-bottom: 0.5rem;
	}

	.tt-grid {
		display: grid;
		grid-template-columns: auto 1fr;
		gap: 0.2rem 0.75rem;
		font-size: 0.7rem;
	}

	.tt-key { color: #64748b; }
	.tt-val { color: #cbd5e1; }

	.tt-hint {
		margin-top: 0.5rem;
		font-size: 0.65rem;
		color: #64748b;
	}
</style>
