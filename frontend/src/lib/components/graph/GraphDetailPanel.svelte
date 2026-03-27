<script lang="ts">
	import { api, type CertDetail, type HealthFinding, type CertSearchResult } from '$lib/api';
	import type { ForceNode } from './graph-types';
	import { gradeColor } from './graph-types';
	import { onMount } from 'svelte';

	interface Props {
		node: ForceNode;
		onClose: () => void;
		onNavigateCert: (fingerprint: string) => void;
		onBlastRadius: (fingerprint: string) => void;
		onExpandCA: (fingerprint: string) => void;
	}

	let { node, onClose, onNavigateCert, onBlastRadius, onExpandCA }: Props = $props();

	let certDetail: CertDetail | null = $state(null);
	let childCerts: CertSearchResult | null = $state(null);
	let loading = $state(true);
	let activeTab: 'overview' | 'findings' | 'children' = $state('overview');

	onMount(() => {
		loadData();
	});

	// Reload when node changes
	$effect(() => {
		if (node) {
			loading = true;
			activeTab = 'overview';
			loadData();
		}
	});

	async function loadData() {
		try {
			certDetail = await api.getCert(node.id);
			if (node.type !== 'leaf') {
				const params = new URLSearchParams({ issuer_cn: node.label, page: '1', page_size: '10' });
				childCerts = await api.searchCerts(params.toString());
			}
		} catch {
			// Cert may not exist individually (aggregated node)
		}
		loading = false;
	}

	function daysUntil(d: string): number {
		return Math.floor((new Date(d).getTime() - Date.now()) / 86400000);
	}

	function severityColor(sev: string): string {
		if (sev === 'critical') return '#ef4444';
		if (sev === 'high') return '#f97316';
		if (sev === 'medium') return '#eab308';
		return '#64748b';
	}
</script>

<div class="detail-panel">
	<div class="panel-header">
		<div class="header-top">
			<div class="header-grade" style="color: {gradeColor(node.grade)}">
				{node.grade}
			</div>
			<div class="header-info">
				<h3>{node.label}</h3>
				{#if node.organization}
					<span class="header-org">{node.organization}</span>
				{/if}
			</div>
			<button class="close-btn" onclick={onClose}>&times;</button>
		</div>

		<div class="header-stats">
			<div class="stat">
				<span class="stat-val">{node.type === 'leaf' ? '—' : node.certCount.toLocaleString()}</span>
				<span class="stat-label">Certs</span>
			</div>
			<div class="stat">
				<span class="stat-val" class:danger={node.expiredCount > 0}>{node.expiredCount}</span>
				<span class="stat-label">Expired</span>
			</div>
			<div class="stat">
				<span class="stat-val" class:warning={node.expiring30dCount > 0}>{node.expiring30dCount}</span>
				<span class="stat-label">&lt;30d</span>
			</div>
			<div class="stat">
				<span class="stat-val">{node.avgScore.toFixed(0)}</span>
				<span class="stat-label">Score</span>
			</div>
		</div>

		{#if node.type !== 'leaf'}
			<div class="header-actions">
				{#if !node.isExpanded}
					<button class="action-btn" onclick={() => onExpandCA(node.id)}>
						Expand in Graph
					</button>
				{/if}
				<button class="action-btn action-blast" onclick={() => onBlastRadius(node.id)}>
					Blast Radius
				</button>
			</div>
		{/if}
	</div>

	<div class="panel-tabs">
		<button class="tab" class:active={activeTab === 'overview'} onclick={() => activeTab = 'overview'}>
			Overview
		</button>
		{#if certDetail?.health_report?.findings?.length}
			<button class="tab" class:active={activeTab === 'findings'} onclick={() => activeTab = 'findings'}>
				Findings ({certDetail.health_report.findings.length})
			</button>
		{/if}
		{#if node.type !== 'leaf'}
			<button class="tab" class:active={activeTab === 'children'} onclick={() => activeTab = 'children'}>
				Children {childCerts ? `(${childCerts.total})` : ''}
			</button>
		{/if}
	</div>

	<div class="panel-body">
		{#if loading}
			<div class="panel-loading">Loading...</div>
		{:else if activeTab === 'overview'}
			<div class="detail-section">
				<div class="detail-grid">
					<span class="detail-key">Type</span>
					<span class="detail-val cap">{node.type === 'root' ? 'Root CA' : node.type === 'intermediate' ? 'Intermediate CA' : 'End Entity'}</span>

					<span class="detail-key">Algorithm</span>
					<span class="detail-val mono">{node.keyAlgorithm} {node.keySizeBits}</span>

					<span class="detail-key">Fingerprint</span>
					<span class="detail-val mono fp">{node.id}</span>

					{#if certDetail?.certificate}
						<span class="detail-key">Not Before</span>
						<span class="detail-val">{new Date(certDetail.certificate.not_before).toLocaleDateString()}</span>

						<span class="detail-key">Not After</span>
						<span class="detail-val" class:danger={daysUntil(certDetail.certificate.not_after) < 0} class:warning={daysUntil(certDetail.certificate.not_after) >= 0 && daysUntil(certDetail.certificate.not_after) < 30}>
							{new Date(certDetail.certificate.not_after).toLocaleDateString()}
							({daysUntil(certDetail.certificate.not_after) < 0 ? 'expired' : daysUntil(certDetail.certificate.not_after) + 'd'})
						</span>

						<span class="detail-key">Signature</span>
						<span class="detail-val mono">{certDetail.certificate.signature_algorithm}</span>

						<span class="detail-key">Issuer</span>
						<span class="detail-val">{certDetail.certificate.issuer.common_name}</span>

						<span class="detail-key">Source</span>
						<span class="detail-val mono">{certDetail.certificate.source_discovery}</span>

						{#if certDetail.certificate.subject_alt_names?.length > 0}
							<span class="detail-key">SANs</span>
							<span class="detail-val mono">{certDetail.certificate.subject_alt_names.length} entries</span>
						{/if}
					{/if}
				</div>
			</div>

			{#if certDetail?.certificate}
				<a href="/certificates/{node.id}" class="full-detail-link">
					View full certificate detail &rarr;
				</a>
			{/if}

		{:else if activeTab === 'findings' && certDetail?.health_report}
			<div class="findings-list">
				{#each certDetail.health_report.findings as finding}
					<div class="finding-card">
						<div class="finding-header">
							<span class="finding-sev" style="color: {severityColor(finding.severity)}">
								{finding.severity}
							</span>
							<span class="finding-title">{finding.title}</span>
							<span class="finding-ded">-{finding.deduction}</span>
						</div>
						<div class="finding-detail">{finding.detail}</div>
						{#if finding.remediation}
							<div class="finding-rem">{finding.remediation}</div>
						{/if}
					</div>
				{/each}
			</div>

		{:else if activeTab === 'children' && childCerts}
			<div class="children-list">
				{#each childCerts.certificates ?? [] as cert}
					<button class="child-card" onclick={() => onNavigateCert(cert.fingerprint_sha256)}>
						<div class="child-top">
							<span class="child-cn">{cert.subject.common_name || cert.fingerprint_sha256.slice(0, 16)}</span>
							<span class="child-algo">{cert.key_algorithm} {cert.key_size_bits}</span>
						</div>
						<div class="child-bottom">
							<span class="child-org">{cert.subject.organization}</span>
							<span class="child-expiry" class:danger={daysUntil(cert.not_after) < 0} class:warning={daysUntil(cert.not_after) >= 0 && daysUntil(cert.not_after) < 30}>
								{daysUntil(cert.not_after) < 0 ? 'Expired' : daysUntil(cert.not_after) + 'd'}
							</span>
						</div>
					</button>
				{/each}
				{#if childCerts.total > 10}
					<div class="children-more">
						Showing 10 of {childCerts.total} — <a href="/certificates?issuer_cn={encodeURIComponent(node.label)}">view all</a>
					</div>
				{/if}
			</div>
		{/if}
	</div>
</div>

<style>
	.detail-panel {
		position: absolute;
		top: 0;
		right: 0;
		bottom: 0;
		width: 380px;
		background: rgba(15, 23, 42, 0.97);
		border-left: 1px solid rgba(56, 189, 248, 0.15);
		display: flex;
		flex-direction: column;
		z-index: 20;
		overflow: hidden;
	}

	.panel-header {
		padding: 1rem;
		border-bottom: 1px solid rgba(56, 189, 248, 0.1);
		flex-shrink: 0;
	}

	.header-top {
		display: flex;
		align-items: flex-start;
		gap: 0.75rem;
	}

	.header-grade {
		font-size: 1.5rem;
		font-weight: 800;
		line-height: 1;
		flex-shrink: 0;
	}

	.header-info {
		flex: 1;
		min-width: 0;
	}

	.header-info h3 {
		margin: 0;
		font-size: 0.9rem;
		font-weight: 600;
		color: #e2e8f0;
		word-break: break-word;
	}

	.header-org {
		font-size: 0.75rem;
		color: #64748b;
	}

	.close-btn {
		background: none;
		border: none;
		color: #64748b;
		font-size: 1.5rem;
		cursor: pointer;
		line-height: 1;
		padding: 0;
		flex-shrink: 0;
	}

	.close-btn:hover { color: #e2e8f0; }

	.header-stats {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 0.5rem;
		margin-top: 0.75rem;
	}

	.stat {
		text-align: center;
		padding: 0.375rem;
		background: rgba(56, 189, 248, 0.05);
		border-radius: 6px;
	}

	.stat-val {
		display: block;
		font-size: 1rem;
		font-weight: 700;
		color: #e2e8f0;
		font-variant-numeric: tabular-nums;
	}

	.stat-label {
		display: block;
		font-size: 0.6rem;
		color: #64748b;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		margin-top: 0.125rem;
	}

	.header-actions {
		display: flex;
		gap: 0.5rem;
		margin-top: 0.75rem;
	}

	.action-btn {
		flex: 1;
		padding: 0.375rem;
		font-size: 0.75rem;
		font-weight: 500;
		background: rgba(56, 189, 248, 0.1);
		border: 1px solid rgba(56, 189, 248, 0.2);
		border-radius: 6px;
		color: #38bdf8;
		cursor: pointer;
		transition: all 0.15s;
	}

	.action-btn:hover { background: rgba(56, 189, 248, 0.2); }

	.action-blast {
		background: rgba(249, 115, 22, 0.1);
		border-color: rgba(249, 115, 22, 0.2);
		color: #f97316;
	}

	.action-blast:hover { background: rgba(249, 115, 22, 0.2); }

	.panel-tabs {
		display: flex;
		border-bottom: 1px solid rgba(56, 189, 248, 0.1);
		flex-shrink: 0;
	}

	.tab {
		flex: 1;
		padding: 0.5rem;
		font-size: 0.75rem;
		font-weight: 500;
		color: #64748b;
		background: none;
		border: none;
		border-bottom: 2px solid transparent;
		cursor: pointer;
		transition: all 0.15s;
	}

	.tab:hover { color: #94a3b8; }
	.tab.active { color: #38bdf8; border-bottom-color: #38bdf8; }

	.panel-body {
		flex: 1;
		overflow-y: auto;
		padding: 0.75rem 1rem;
	}

	.panel-loading {
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 2rem;
		color: #64748b;
	}

	.detail-grid {
		display: grid;
		grid-template-columns: auto 1fr;
		gap: 0.3rem 0.75rem;
		font-size: 0.8rem;
	}

	.detail-key { color: #64748b; }
	.detail-val { color: #cbd5e1; }
	.detail-val.mono { font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; }
	.detail-val.cap { text-transform: capitalize; }
	.detail-val.fp { word-break: break-all; font-size: 0.65rem; }

	.danger { color: #ef4444 !important; }
	.warning { color: #eab308 !important; }

	.full-detail-link {
		display: block;
		margin-top: 1rem;
		padding: 0.5rem;
		text-align: center;
		font-size: 0.75rem;
		color: #38bdf8;
		text-decoration: none;
		background: rgba(56, 189, 248, 0.05);
		border: 1px solid rgba(56, 189, 248, 0.15);
		border-radius: 6px;
	}

	.full-detail-link:hover { background: rgba(56, 189, 248, 0.1); }

	.findings-list {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.finding-card {
		padding: 0.625rem;
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(56, 189, 248, 0.08);
		border-radius: 6px;
	}

	.finding-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-bottom: 0.25rem;
	}

	.finding-sev {
		font-size: 0.65rem;
		font-weight: 600;
		text-transform: uppercase;
	}

	.finding-title {
		font-size: 0.8rem;
		font-weight: 500;
		color: #e2e8f0;
		flex: 1;
	}

	.finding-ded {
		font-size: 0.75rem;
		font-weight: 600;
		color: #ef4444;
		font-variant-numeric: tabular-nums;
	}

	.finding-detail {
		font-size: 0.75rem;
		color: #94a3b8;
	}

	.finding-rem {
		margin-top: 0.25rem;
		font-size: 0.7rem;
		color: #64748b;
		font-style: italic;
	}

	.children-list {
		display: flex;
		flex-direction: column;
		gap: 0.375rem;
	}

	.child-card {
		display: block;
		width: 100%;
		padding: 0.5rem 0.625rem;
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(56, 189, 248, 0.08);
		border-radius: 6px;
		text-align: left;
		cursor: pointer;
		transition: border-color 0.15s;
		color: inherit;
	}

	.child-card:hover { border-color: rgba(56, 189, 248, 0.3); }

	.child-top {
		display: flex;
		justify-content: space-between;
		gap: 0.5rem;
	}

	.child-cn {
		font-size: 0.8rem;
		font-weight: 500;
		color: #e2e8f0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.child-algo {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.7rem;
		color: #64748b;
		flex-shrink: 0;
	}

	.child-bottom {
		display: flex;
		justify-content: space-between;
		margin-top: 0.15rem;
	}

	.child-org {
		font-size: 0.7rem;
		color: #64748b;
	}

	.child-expiry {
		font-size: 0.7rem;
		color: #94a3b8;
		font-variant-numeric: tabular-nums;
	}

	.children-more {
		padding: 0.5rem;
		text-align: center;
		font-size: 0.75rem;
		color: #64748b;
	}

	.children-more a { color: #38bdf8; }
</style>
