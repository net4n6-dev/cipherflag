<script lang="ts">
	interface Props {
		nodeCount: number;
		totalCerts: number;
		expandedCount: number;
	}

	let { nodeCount, totalCerts, expandedCount }: Props = $props();
</script>

<div class="graph-legend">
	<div class="legend-title">Legend</div>
	<div class="legend-items">
		<span class="legend-item">
			<span class="legend-dot root-dot"></span>Root CA
		</span>
		<span class="legend-item">
			<span class="legend-dot int-dot"></span>Intermediate
		</span>
		<span class="legend-item">
			<span class="legend-dot leaf-dot"></span>Leaf
		</span>
		<span class="legend-item">
			<span class="legend-dot risk-dot"></span>At Risk
		</span>
	</div>
</div>

<div class="graph-stats">
	{nodeCount} CAs · {totalCerts.toLocaleString()} certificates · {expandedCount} expanded
</div>

<style>
	.graph-legend {
		position: absolute;
		bottom: 12px;
		left: 12px;
		background: rgba(15, 23, 42, 0.9);
		border: 1px solid rgba(56, 189, 248, 0.1);
		border-radius: 6px;
		padding: 0.5rem 0.75rem;
		z-index: 10;
	}

	.legend-title {
		font-size: 0.65rem;
		color: #64748b;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		margin-bottom: 0.375rem;
	}

	.legend-items {
		display: flex;
		gap: 1rem;
		font-size: 0.7rem;
		color: #94a3b8;
		align-items: center;
	}

	.legend-item { display: flex; align-items: center; gap: 4px; }
	.legend-dot { display: inline-block; border-radius: 50%; vertical-align: middle; }
	.root-dot { width: 12px; height: 12px; background: rgba(34, 197, 94, 0.15); border: 1.5px solid #22c55e; }
	.int-dot { width: 9px; height: 9px; background: rgba(132, 204, 22, 0.12); border: 1.5px solid #84cc16; }
	.leaf-dot { width: 6px; height: 6px; background: rgba(56, 189, 248, 0.2); border: 1px solid #38bdf8; }
	.risk-dot { width: 8px; height: 8px; border: 1.5px solid #ef4444; animation: pulse 2s infinite; }

	@keyframes pulse {
		0%, 100% { opacity: 1; }
		50% { opacity: 0.4; }
	}

	.graph-stats {
		position: absolute;
		bottom: 12px;
		right: 12px;
		background: rgba(15, 23, 42, 0.9);
		border: 1px solid rgba(56, 189, 248, 0.1);
		border-radius: 6px;
		padding: 0.5rem 0.75rem;
		z-index: 10;
		font-size: 0.7rem;
		color: #94a3b8;
	}
</style>
