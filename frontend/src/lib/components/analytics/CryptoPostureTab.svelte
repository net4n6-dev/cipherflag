<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { api, type Certificate } from '$lib/api';
	import type { CryptoPostureResponse, CipherStats } from '$lib/api';
	import { gradeColor } from './analytics-types';

	let crypto: CryptoPostureResponse | null = $state(null);
	let ciphers: CipherStats | null = $state(null);
	let loading = $state(true);
	let error: string | null = $state(null);

	// Expanded state
	let expandedPanel: string | null = $state(null);
	let expandedCerts: Certificate[] = $state([]);
	let expandedLoading = $state(false);
	let expandedLabel = $state('');

	onMount(async () => {
		try {
			const [c, ci] = await Promise.all([
				api.getCryptoPosture(),
				api.getCiphers(),
			]);
			crypto = c;
			ciphers = ci;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load crypto posture';
		}
		loading = false;
	});

	const ALGO_COLORS: Record<string, string> = {
		'RSA': '#38bdf8', 'ECDSA': '#a78bfa', 'Ed25519': '#34d399', 'Unknown': '#64748b',
	};

	function algoColor(algo: string): string { return ALGO_COLORS[algo] ?? '#64748b'; }

	const STRENGTH_COLORS: Record<string, string> = {
		'Best': '#22c55e', 'Strong': '#38bdf8', 'Acceptable': '#eab308',
		'Weak': '#f97316', 'Insecure': '#ef4444', 'Unknown': '#64748b',
	};

	function strengthColor(s: string): string { return STRENGTH_COLORS[s] ?? '#64748b'; }

	const TLS_ORDER = ['SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3'];
	const STRENGTH_ORDER = ['Best', 'Strong', 'Acceptable', 'Weak', 'Insecure'];

	function heatmapValue(version: string, strength: string): number {
		if (!ciphers) return 0;
		return ciphers.tls_cipher_matrix.find(r => r.tls_version === version && r.strength === strength)?.count ?? 0;
	}

	function heatmapMax(): number {
		if (!ciphers) return 1;
		return Math.max(...ciphers.tls_cipher_matrix.map(r => r.count), 1);
	}

	function heatmapOpacity(count: number): number {
		if (count === 0) return 0.1;
		return 0.2 + 0.6 * Math.min(count / heatmapMax(), 1);
	}

	function donutArc(startAngle: number, endAngle: number, r: number, cx: number, cy: number): string {
		const x1 = cx + r * Math.cos(startAngle - Math.PI / 2);
		const y1 = cy + r * Math.sin(startAngle - Math.PI / 2);
		const x2 = cx + r * Math.cos(endAngle - Math.PI / 2);
		const y2 = cy + r * Math.sin(endAngle - Math.PI / 2);
		const large = endAngle - startAngle > Math.PI ? 1 : 0;
		return `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`;
	}

	async function drillDown(key: string, label: string, paramName: string, paramValue: string) {
		if (expandedPanel === key) {
			expandedPanel = null;
			expandedCerts = [];
			return;
		}
		expandedPanel = key;
		expandedLabel = label;
		expandedLoading = true;
		expandedCerts = [];

		// Auto-scroll to drilldown panel after render
		requestAnimationFrame(() => {
			document.getElementById('crypto-drilldown')?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
		});

		try {
			const params = new URLSearchParams({ [paramName]: paramValue, page_size: '20' });
			const result = await api.searchCerts(params.toString());
			expandedCerts = result.certificates ?? [];
		} catch {
			expandedCerts = [];
		}
		expandedLoading = false;
	}

	async function drillDownSigAlgo(algo: string) {
		await drillDown(`sig-${algo}`, `Signature: ${algo}`, 'signature_algorithm', algo);
	}

	async function drillDownKeyAlgo(algo: string) {
		await drillDown(`key-${algo}`, `Key Algorithm: ${algo}`, 'key_algorithm', algo);
	}

	async function drillDownKeySize(algo: string, size: number) {
		// Filter by both algo and check size in results (backend doesn't have a key_size filter)
		expandedPanel = `ks-${algo}-${size}`;
		expandedLabel = `${algo} ${size}-bit`;
		expandedLoading = true;
		expandedCerts = [];

		try {
			const params = new URLSearchParams({ key_algorithm: algo, page_size: '50' });
			const result = await api.searchCerts(params.toString());
			expandedCerts = (result.certificates ?? []).filter(c => c.key_size_bits === size);
		} catch {
			expandedCerts = [];
		}
		expandedLoading = false;
	}

	function daysUntil(d: string): number {
		return Math.floor((new Date(d).getTime() - Date.now()) / 86400000);
	}

	function viewCert(fp: string) { goto(`/certificates/${fp}`); }
	function viewComplianceReport() { goto('/reports?type=compliance'); }
</script>

<div class="crypto-tab">
	{#if loading}
		<div class="tab-loading">Loading crypto posture...</div>
	{:else if error}
		<div class="tab-error">{error}</div>
	{:else if crypto && ciphers}
		<div class="tab-header">
			<h2>Crypto Posture</h2>
			<span class="tab-meta">{crypto.total_certs.toLocaleString()} certificates analyzed</span>
			<button class="report-btn" onclick={viewComplianceReport}>Compliance Report →</button>
		</div>

		<div class="panels-grid">
			<!-- Key Algorithm Donut -->
			<div class="panel">
				<h3>Key Algorithm <span class="hint">click to explore</span></h3>
				<div class="donut-row">
					<svg viewBox="0 0 120 120" class="donut-svg">
						{#each crypto.key_algorithms as algo, i}
							{@const total = crypto.total_certs}
							{@const startAngle = crypto.key_algorithms.slice(0, i).reduce((s, a) => s + (a.count / total) * Math.PI * 2, 0)}
							{@const endAngle = startAngle + (algo.count / total) * Math.PI * 2}
							{#if algo.count > 0}
								<path
									d={donutArc(startAngle, Math.min(endAngle, startAngle + Math.PI * 2 - 0.01), 45, 60, 60)}
									fill="none"
									stroke={algoColor(algo.algorithm)}
									stroke-width="14"
									stroke-linecap="round"
								/>
							{/if}
						{/each}
						<text x="60" y="56" text-anchor="middle" fill="#e2e8f0" font-size="14" font-weight="700">
							{crypto.total_certs}
						</text>
						<text x="60" y="70" text-anchor="middle" fill="#64748b" font-size="8">total</text>
					</svg>
					<div class="donut-legend">
						{#each crypto.key_algorithms as algo}
							<button class="legend-row clickable" class:active={expandedPanel === `key-${algo.algorithm}`}
								onclick={() => drillDownKeyAlgo(algo.algorithm)}>
								<span class="legend-dot" style="background: {algoColor(algo.algorithm)}"></span>
								<span class="legend-name">{algo.algorithm}</span>
								<span class="legend-count">{algo.count.toLocaleString()}</span>
								<span class="legend-pct">{(algo.count / crypto.total_certs * 100).toFixed(1)}%</span>
							</button>
						{/each}
					</div>
				</div>
			</div>

			<!-- Key Size Distribution -->
			<div class="panel">
				<h3>Key Size Distribution <span class="hint">click to explore</span></h3>
				<div class="bar-list">
					{#each crypto.key_sizes as ks}
						{@const maxCount = Math.max(...crypto.key_sizes.map(k => k.count), 1)}
						<button class="bar-row clickable" class:active={expandedPanel === `ks-${ks.algorithm}-${ks.size_bits}`}
							onclick={() => drillDownKeySize(ks.algorithm, ks.size_bits)}>
							<span class="bar-label">{ks.algorithm} {ks.size_bits}</span>
							<div class="bar-track">
								<div class="bar-fill" style="width: {(ks.count / maxCount) * 100}%; background: {algoColor(ks.algorithm)}"></div>
							</div>
							<span class="bar-count">{ks.count.toLocaleString()}</span>
						</button>
					{/each}
				</div>
			</div>

			<!-- TLS x Cipher Heatmap -->
			<div class="panel">
				<h3>TLS Version x Cipher Strength</h3>
				<div class="heatmap-container">
					<div class="heatmap-grid" style="grid-template-columns: auto repeat({STRENGTH_ORDER.length}, 1fr);">
						<div class="heatmap-corner"></div>
						{#each STRENGTH_ORDER as strength}
							<div class="heatmap-col-header" style="color: {strengthColor(strength)}">{strength}</div>
						{/each}
						{#each TLS_ORDER as version}
							<div class="heatmap-row-header">{version}</div>
							{#each STRENGTH_ORDER as strength}
								{@const count = heatmapValue(version, strength)}
								<div
									class="heatmap-cell"
									style="background: {count > 0 ? strengthColor(strength) : 'rgba(30,41,59,0.3)'}; opacity: {heatmapOpacity(count)}"
									title="{version} + {strength}: {count}"
								>
									{#if count > 0}
										<span>{count.toLocaleString()}</span>
									{/if}
								</div>
							{/each}
						{/each}
					</div>
				</div>
			</div>

			<!-- Signature Algorithm -->
			<div class="panel">
				<h3>Signature Algorithm <span class="hint">click to explore</span></h3>
				<div class="bar-list">
					{#each crypto.signature_algorithms as sa}
						{@const maxCount = Math.max(...crypto.signature_algorithms.map(s => s.count), 1)}
						{@const isWeak = sa.algorithm.includes('SHA1') || sa.algorithm.includes('MD5')}
						<button class="bar-row clickable" class:active={expandedPanel === `sig-${sa.algorithm}`}
							onclick={() => drillDownSigAlgo(sa.algorithm)}>
							<span class="bar-label" class:weak-algo={isWeak}>{sa.algorithm}</span>
							<div class="bar-track">
								<div class="bar-fill" style="width: {(sa.count / maxCount) * 100}%; background: {isWeak ? '#ef4444' : '#38bdf8'}"></div>
							</div>
							<span class="bar-count">{sa.count.toLocaleString()}</span>
						</button>
					{/each}
				</div>
			</div>
		</div>

		<!-- Expanded drilldown panel (between grid and strength summary) -->
		{#if expandedPanel}
			<div class="drilldown-panel" id="crypto-drilldown">
				<div class="drilldown-header">
					<h3>{expandedLabel}</h3>
					<div class="drilldown-actions">
						<button class="report-btn-sm" onclick={viewComplianceReport}>Full Compliance Report →</button>
						<button class="close-btn" onclick={() => { expandedPanel = null; expandedCerts = []; }}>&times;</button>
					</div>
				</div>

				{#if expandedLoading}
					<div class="drilldown-loading">Loading certificates...</div>
				{:else if expandedCerts.length === 0}
					<div class="drilldown-empty">No certificates found.</div>
				{:else}
					<table class="cert-table">
						<thead>
							<tr>
								<th>CN</th>
								<th>Issuer</th>
								<th>Algorithm</th>
								<th>Signature</th>
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
									<td class="cell-algo">{cert.signature_algorithm}</td>
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

		<!-- Cipher Strength Overview -->
		<div class="strength-summary">
			<h3>Cipher Strength Overview</h3>
			<div class="strength-bars">
				{#each STRENGTH_ORDER as strength}
					{@const count = ciphers.strength_distribution[strength] ?? 0}
					{@const total = Object.values(ciphers.strength_distribution).reduce((s, c) => s + c, 0) || 1}
					{#if count > 0}
						<div class="strength-row">
							<span class="strength-label" style="color: {strengthColor(strength)}">{strength}</span>
							<div class="bar-track">
								<div class="bar-fill" style="width: {(count / total) * 100}%; background: {strengthColor(strength)}"></div>
							</div>
							<span class="bar-count">{count.toLocaleString()}</span>
							<span class="bar-pct">{(count / total * 100).toFixed(1)}%</span>
						</div>
					{/if}
				{/each}
			</div>
		</div>

	{/if}
</div>

<style>
	.crypto-tab { padding: 1.5rem; height: 100%; overflow-y: auto; }

	.tab-header { display: flex; align-items: baseline; gap: 1rem; margin-bottom: 1.25rem; }
	.tab-header h2 { margin: 0; font-size: 1.1rem; font-weight: 700; color: var(--cf-text-primary); }
	.tab-meta { font-size: 0.8rem; color: var(--cf-text-muted); flex: 1; }

	.report-btn {
		font-size: 0.75rem; color: var(--cf-accent, #38bdf8);
		background: none; border: 1px solid rgba(56, 189, 248, 0.2);
		border-radius: 4px; padding: 0.25rem 0.625rem; cursor: pointer;
		transition: all 0.15s;
	}
	.report-btn:hover { background: rgba(56, 189, 248, 0.1); }

	.panels-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.25rem; }

	.panel {
		background: var(--cf-bg-secondary, rgba(15, 23, 42, 0.5));
		border: 1px solid var(--cf-border, rgba(56, 189, 248, 0.1));
		border-radius: 8px; padding: 1rem;
	}

	h3 { margin: 0 0 0.75rem; font-size: 0.75rem; font-weight: 600;
		color: var(--cf-text-muted, #64748b); text-transform: uppercase; letter-spacing: 0.04em;
		display: flex; align-items: center; gap: 0.5rem; }

	.hint {
		font-size: 0.6rem; font-weight: 400; text-transform: none; letter-spacing: normal;
		color: var(--cf-accent, #38bdf8); opacity: 0.6;
	}

	/* Donut */
	.donut-row { display: flex; align-items: center; gap: 1.5rem; }
	.donut-svg { width: 120px; height: 120px; flex-shrink: 0; }
	.donut-legend { display: flex; flex-direction: column; gap: 0.25rem; flex: 1; }

	.legend-row {
		display: flex; align-items: center; gap: 0.5rem;
		background: none; border: none; color: inherit;
		width: 100%; text-align: left; padding: 0.25rem 0.375rem; border-radius: 4px;
	}
	.legend-row.clickable { cursor: pointer; transition: all 0.15s; border: 1px solid transparent; }
	.legend-row.clickable:hover { background: rgba(56, 189, 248, 0.1); border-color: rgba(56, 189, 248, 0.3); }
	.legend-row.active { background: rgba(56, 189, 248, 0.15); border-color: var(--cf-accent, #38bdf8); }

	.legend-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
	.legend-name { font-size: 0.85rem; font-weight: 600; color: var(--cf-text-primary, #e2e8f0); flex: 1; }
	.legend-count { font-size: 0.8rem; color: var(--cf-text-secondary, #94a3b8); font-variant-numeric: tabular-nums; }
	.legend-pct { font-size: 0.75rem; color: var(--cf-text-muted, #64748b); font-variant-numeric: tabular-nums; width: 40px; text-align: right; }

	/* Bars */
	.bar-list { display: flex; flex-direction: column; gap: 0.25rem; }

	.bar-row {
		display: flex; align-items: center; gap: 0.75rem;
		background: none; border: none; color: inherit;
		width: 100%; text-align: left; padding: 0.25rem 0.375rem; border-radius: 4px;
	}
	.bar-row.clickable { cursor: pointer; transition: all 0.15s; border: 1px solid transparent; border-radius: 4px; }
	.bar-row.clickable:hover { background: rgba(56, 189, 248, 0.1); border-color: rgba(56, 189, 248, 0.3); }
	.bar-row.active { background: rgba(56, 189, 248, 0.15); border-color: var(--cf-accent, #38bdf8); }

	.bar-label { width: 140px; font-family: 'JetBrains Mono', monospace; font-size: 0.75rem;
		color: var(--cf-text-primary, #e2e8f0); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex-shrink: 0; }
	.bar-label.weak-algo { color: #ef4444; }
	.bar-track { flex: 1; height: 16px; background: var(--cf-bg-tertiary, rgba(30, 41, 59, 0.5)); border-radius: 3px; overflow: hidden; pointer-events: none; }
	.bar-fill { height: 100%; border-radius: 3px; opacity: 0.7; transition: width 0.3s ease; pointer-events: none; }
	.bar-count { width: 50px; text-align: right; font-size: 0.8rem; color: var(--cf-text-secondary, #94a3b8); font-variant-numeric: tabular-nums; flex-shrink: 0; }
	.bar-pct { width: 45px; text-align: right; font-size: 0.75rem; color: var(--cf-text-muted, #64748b); font-variant-numeric: tabular-nums; flex-shrink: 0; }

	/* Heatmap */
	.heatmap-container { overflow-x: auto; }
	.heatmap-grid { display: grid; gap: 2px; }
	.heatmap-corner { }
	.heatmap-col-header { text-align: center; font-size: 0.65rem; font-weight: 600; padding: 0.25rem; text-transform: uppercase; }
	.heatmap-row-header { font-size: 0.75rem; color: var(--cf-text-secondary, #94a3b8); padding: 0.25rem 0.5rem; display: flex; align-items: center; }
	.heatmap-cell {
		display: flex; align-items: center; justify-content: center;
		border-radius: 4px; min-height: 36px; font-size: 0.75rem;
		font-weight: 600; color: #e2e8f0; cursor: default; transition: opacity 0.15s;
	}
	.heatmap-cell:hover { opacity: 1 !important; }
	.heatmap-cell span { text-shadow: 0 1px 2px rgba(0,0,0,0.5); }

	/* Strength summary */
	.strength-summary {
		background: var(--cf-bg-secondary, rgba(15, 23, 42, 0.5));
		border: 1px solid var(--cf-border, rgba(56, 189, 248, 0.1));
		border-radius: 8px; padding: 1rem; margin-bottom: 1rem;
	}
	.strength-bars { display: flex; flex-direction: column; gap: 0.5rem; }
	.strength-row { display: flex; align-items: center; gap: 0.75rem; }
	.strength-label { width: 80px; font-size: 0.8rem; font-weight: 600; flex-shrink: 0; }

	/* Drilldown panel */
	.drilldown-panel {
		background: var(--cf-bg-secondary, rgba(15, 23, 42, 0.5));
		border: 1px solid var(--cf-border, rgba(56, 189, 248, 0.15));
		border-radius: 8px; padding: 1rem; margin-top: 1rem;
	}

	.drilldown-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.75rem; }
	.drilldown-header h3 { margin: 0; text-transform: none; font-size: 0.9rem; color: var(--cf-text-primary, #e2e8f0); }
	.drilldown-actions { display: flex; align-items: center; gap: 0.5rem; }

	.report-btn-sm {
		font-size: 0.7rem; color: var(--cf-accent, #38bdf8);
		background: none; border: 1px solid rgba(56, 189, 248, 0.2);
		border-radius: 4px; padding: 0.2rem 0.5rem; cursor: pointer;
	}
	.report-btn-sm:hover { background: rgba(56, 189, 248, 0.1); }

	.close-btn { background: none; border: none; color: var(--cf-text-muted); font-size: 1.25rem; cursor: pointer; padding: 0; line-height: 1; }
	.close-btn:hover { color: var(--cf-text-primary); }

	.drilldown-loading, .drilldown-empty { padding: 1rem; text-align: center; font-size: 0.8rem; color: var(--cf-text-muted); }

	.cert-table { width: 100%; border-collapse: collapse; font-size: 0.75rem; }
	.cert-table th { text-align: left; padding: 0.375rem 0.5rem; color: var(--cf-text-muted, #64748b);
		font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.04em; font-weight: 600;
		border-bottom: 1px solid var(--cf-border, rgba(56, 189, 248, 0.1)); }
	.cert-table td { padding: 0.375rem 0.5rem; border-bottom: 1px solid rgba(56, 189, 248, 0.05);
		color: var(--cf-text-secondary, #94a3b8); }
	.cert-table tr { cursor: pointer; transition: background 0.1s; }
	.cert-table tbody tr:hover { background: rgba(56, 189, 248, 0.05); }

	.cell-cn { color: var(--cf-text-primary, #e2e8f0); font-weight: 500; max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.cell-issuer { max-width: 130px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.cell-algo { font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; }
	.cell-date { font-variant-numeric: tabular-nums; }
	.cell-days { font-weight: 600; font-variant-numeric: tabular-nums; }
	.cell-days.expired { color: #ef4444; }
	.cell-days.warning { color: #eab308; }
	.cell-source { font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; }

	.tab-loading, .tab-error { display: flex; align-items: center; justify-content: center; height: 50vh; color: var(--cf-text-muted); font-size: 0.9rem; }
	.tab-error { color: var(--cf-risk-critical); }
</style>
