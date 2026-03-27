<script lang="ts">
	import type { DeploymentGroup } from '$lib/api';
	import { gradeColor } from './analytics-types';

	interface Props {
		groups: DeploymentGroup[];
	}

	let { groups }: Props = $props();
	let maxCount = $derived(Math.max(...groups.map(g => g.cert_count), 1));
	let hoveredGroup: DeploymentGroup | null = $state(null);
</script>

<div class="deployment-chart">
	{#if groups.length === 0}
		<div class="empty-state">
			No deployment data available. Certificates discovered via passive or active scanning will appear here.
		</div>
	{:else}
		{#each groups.slice(0, 20) as group}
			<div class="bar-row"
				onpointerenter={() => hoveredGroup = group}
				onpointerleave={() => hoveredGroup = null}
			>
				<span class="bar-domain">{group.domain}</span>
				<div class="bar-track">
					<div class="bar-fill"
						style="width: {(group.cert_count / maxCount) * 100}%; background: {gradeColor(group.worst_grade)}"
					></div>
				</div>
				<span class="bar-count">{group.cert_count}</span>
				<span class="bar-ips">{group.unique_ips} IPs</span>
				<span class="bar-grade" style="color: {gradeColor(group.worst_grade)}">{group.worst_grade}</span>
			</div>
		{/each}

		{#if hoveredGroup}
			<div class="bar-detail">
				<span>{hoveredGroup.domain}</span>
				<span>{hoveredGroup.cert_count} certs</span>
				<span>{hoveredGroup.unique_ips} unique IPs</span>
				{#if hoveredGroup.expired_count > 0}
					<span class="detail-expired">{hoveredGroup.expired_count} expired</span>
				{/if}
				<span>Avg score: {hoveredGroup.avg_score.toFixed(0)}</span>
			</div>
		{/if}
	{/if}
</div>

<style>
	.deployment-chart { display: flex; flex-direction: column; gap: 0.375rem; }
	.bar-row { display: flex; align-items: center; gap: 0.75rem; padding: 0.25rem 0; cursor: default; }
	.bar-row:hover { background: rgba(56, 189, 248, 0.03); border-radius: 4px; }
	.bar-domain { width: 200px; font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: #e2e8f0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex-shrink: 0; }
	.bar-track { flex: 1; height: 18px; background: var(--cf-bg-tertiary, rgba(30, 41, 59, 0.5)); border-radius: 3px; overflow: hidden; }
	.bar-fill { height: 100%; border-radius: 3px; opacity: 0.7; transition: width 0.3s ease; }
	.bar-count { width: 36px; text-align: right; font-size: 0.8rem; font-weight: 600; color: #cbd5e1; font-variant-numeric: tabular-nums; flex-shrink: 0; }
	.bar-ips { width: 48px; font-size: 0.7rem; color: #64748b; flex-shrink: 0; }
	.bar-grade { width: 24px; font-size: 0.75rem; font-weight: 700; flex-shrink: 0; text-align: center; }
	.empty-state { padding: 2rem; text-align: center; color: #64748b; font-size: 0.85rem; }
	.bar-detail { display: flex; gap: 1rem; padding: 0.5rem 0.75rem; background: rgba(56, 189, 248, 0.05); border-radius: 6px; font-size: 0.75rem; color: #94a3b8; margin-top: 0.25rem; }
	.detail-expired { color: #ef4444; }
</style>
