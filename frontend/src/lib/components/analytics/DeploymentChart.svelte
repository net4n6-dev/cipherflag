<script lang="ts">
	import { goto } from '$app/navigation';
	import { api, type DeploymentGroup, type CertSearchResult, type Certificate } from '$lib/api';
	import { gradeColor } from './analytics-types';

	interface Props {
		groups: DeploymentGroup[];
	}

	let { groups }: Props = $props();
	let maxCount = $derived(Math.max(...groups.map(g => g.cert_count), 1));

	// Expanded state: domain → certs
	let expandedDomain: string | null = $state(null);
	let expandedCerts: Certificate[] = $state([]);
	let expandedLoading = $state(false);

	async function toggleExpand(domain: string) {
		if (expandedDomain === domain) {
			expandedDomain = null;
			expandedCerts = [];
			return;
		}

		expandedDomain = domain;
		expandedLoading = true;
		expandedCerts = [];

		try {
			const params = new URLSearchParams({ server_name: domain, page_size: '20' });
			const result = await api.searchCerts(params.toString());
			expandedCerts = result.certificates ?? [];
		} catch {
			expandedCerts = [];
		}
		expandedLoading = false;
	}

	function daysUntil(d: string): number {
		return Math.floor((new Date(d).getTime() - Date.now()) / 86400000);
	}

	function viewCert(fp: string) {
		goto(`/certificates/${fp}`);
	}

	function viewDomainReport(domain: string) {
		goto(`/reports?type=domain&q=${encodeURIComponent(domain)}`);
	}
</script>

<div class="deployment-chart">
	{#if groups.length === 0}
		<div class="empty-state">
			No deployment data available. Certificates discovered via passive or active scanning will appear here.
		</div>
	{:else}
		{#each groups.slice(0, 20) as group}
			<div class="bar-wrapper" class:expanded={expandedDomain === group.domain}>
				<button class="bar-row" onclick={() => toggleExpand(group.domain)}>
					<span class="expand-icon">{expandedDomain === group.domain ? '▼' : '▶'}</span>
					<span class="bar-domain">{group.domain}</span>
					<div class="bar-track">
						<div class="bar-fill"
							style="width: {(group.cert_count / maxCount) * 100}%; background: {gradeColor(group.worst_grade)}"
						></div>
					</div>
					<span class="bar-count">{group.cert_count}</span>
					<span class="bar-ips">{group.unique_ips} IPs</span>
					<span class="bar-grade" style="color: {gradeColor(group.worst_grade)}">{group.worst_grade}</span>
				</button>

				{#if expandedDomain === group.domain}
					<div class="expanded-panel">
						<div class="panel-header">
							<span class="panel-title">{group.domain}</span>
							<span class="panel-meta">
								{group.cert_count} certs · {group.unique_ips} IPs · Avg score: {group.avg_score.toFixed(0)}
								{#if group.expired_count > 0}
									· <span class="panel-expired">{group.expired_count} expired</span>
								{/if}
							</span>
							<button class="report-link" onclick={() => viewDomainReport(group.domain)}>
								Full Report →
							</button>
						</div>

						{#if expandedLoading}
							<div class="panel-loading">Loading certificates...</div>
						{:else if expandedCerts.length === 0}
							<div class="panel-empty">No certificates found for this domain.</div>
						{:else}
							<table class="cert-table">
								<thead>
									<tr>
										<th>CN</th>
										<th>Issuer</th>
										<th>Algorithm</th>
										<th>Expires</th>
										<th>Days</th>
										<th>Source</th>
									</tr>
								</thead>
								<tbody>
									{#each expandedCerts as cert}
										{@const days = daysUntil(cert.not_after)}
										<tr onclick={() => viewCert(cert.fingerprint_sha256)}>
											<td class="cell-cn">{cert.subject.common_name || cert.fingerprint_sha256.slice(0, 16)}</td>
											<td class="cell-issuer">{cert.issuer.common_name}</td>
											<td class="cell-algo">{cert.key_algorithm} {cert.key_size_bits}</td>
											<td class="cell-date">{new Date(cert.not_after).toLocaleDateString()}</td>
											<td class="cell-days" class:expired={days < 0} class:warning={days >= 0 && days < 30}>
												{days < 0 ? 'Expired' : days + 'd'}
											</td>
											<td class="cell-source">{cert.source_discovery}</td>
										</tr>
									{/each}
								</tbody>
							</table>
						{/if}
					</div>
				{/if}
			</div>
		{/each}
	{/if}
</div>

<style>
	.deployment-chart { display: flex; flex-direction: column; gap: 0.25rem; }

	.bar-wrapper {
		border: 1px solid transparent;
		border-radius: 6px;
		transition: border-color 0.15s;
	}

	.bar-wrapper.expanded {
		border-color: var(--cf-border, rgba(56, 189, 248, 0.15));
		background: rgba(56, 189, 248, 0.02);
	}

	.bar-row {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 0.375rem 0.5rem;
		width: 100%;
		background: none;
		border: none;
		color: inherit;
		cursor: pointer;
		text-align: left;
		border-radius: 6px;
		transition: background 0.1s;
	}

	.bar-row:hover { background: rgba(56, 189, 248, 0.05); }

	.expand-icon {
		font-size: 0.55rem;
		color: var(--cf-text-muted, #64748b);
		width: 12px;
		flex-shrink: 0;
	}

	.bar-domain {
		width: 190px;
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.75rem;
		color: #e2e8f0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		flex-shrink: 0;
	}

	.bar-track { flex: 1; height: 18px; background: var(--cf-bg-tertiary, rgba(30, 41, 59, 0.5)); border-radius: 3px; overflow: hidden; }
	.bar-fill { height: 100%; border-radius: 3px; opacity: 0.7; transition: width 0.3s ease; }
	.bar-count { width: 36px; text-align: right; font-size: 0.8rem; font-weight: 600; color: #cbd5e1; font-variant-numeric: tabular-nums; flex-shrink: 0; }
	.bar-ips { width: 48px; font-size: 0.7rem; color: #64748b; flex-shrink: 0; }
	.bar-grade { width: 24px; font-size: 0.75rem; font-weight: 700; flex-shrink: 0; text-align: center; }

	/* Expanded panel */
	.expanded-panel {
		padding: 0.5rem 0.75rem 0.75rem;
		border-top: 1px solid var(--cf-border, rgba(56, 189, 248, 0.1));
	}

	.panel-header {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		margin-bottom: 0.5rem;
	}

	.panel-title {
		font-size: 0.85rem;
		font-weight: 600;
		color: var(--cf-text-primary, #e2e8f0);
	}

	.panel-meta {
		font-size: 0.75rem;
		color: var(--cf-text-muted, #64748b);
		flex: 1;
	}

	.panel-expired { color: #ef4444; }

	.report-link {
		font-size: 0.7rem;
		color: var(--cf-accent, #38bdf8);
		background: none;
		border: 1px solid rgba(56, 189, 248, 0.2);
		border-radius: 4px;
		padding: 0.2rem 0.5rem;
		cursor: pointer;
		transition: all 0.15s;
		flex-shrink: 0;
	}

	.report-link:hover { background: rgba(56, 189, 248, 0.1); }

	.panel-loading, .panel-empty {
		padding: 0.75rem;
		text-align: center;
		font-size: 0.8rem;
		color: var(--cf-text-muted, #64748b);
	}

	/* Certificate table */
	.cert-table {
		width: 100%;
		border-collapse: collapse;
		font-size: 0.75rem;
	}

	.cert-table th {
		text-align: left;
		padding: 0.375rem 0.5rem;
		color: var(--cf-text-muted, #64748b);
		font-size: 0.65rem;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		font-weight: 600;
		border-bottom: 1px solid var(--cf-border, rgba(56, 189, 248, 0.1));
	}

	.cert-table td {
		padding: 0.375rem 0.5rem;
		border-bottom: 1px solid rgba(56, 189, 248, 0.05);
		color: var(--cf-text-secondary, #94a3b8);
	}

	.cert-table tr {
		cursor: pointer;
		transition: background 0.1s;
	}

	.cert-table tbody tr:hover {
		background: rgba(56, 189, 248, 0.05);
	}

	.cell-cn {
		color: var(--cf-text-primary, #e2e8f0);
		font-weight: 500;
		max-width: 200px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.cell-issuer {
		max-width: 150px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.cell-algo { font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; }
	.cell-date { font-variant-numeric: tabular-nums; }
	.cell-days { font-weight: 600; font-variant-numeric: tabular-nums; }
	.cell-days.expired { color: #ef4444; }
	.cell-days.warning { color: #eab308; }
	.cell-source { font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; }

	.empty-state { padding: 2rem; text-align: center; color: #64748b; font-size: 0.85rem; }
</style>
