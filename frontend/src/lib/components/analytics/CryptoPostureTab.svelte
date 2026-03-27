<script lang="ts">
	import { onMount } from 'svelte';
	import { api } from '$lib/api';
	import type { CryptoPostureResponse, CipherStats, TLSCipherRow } from '$lib/api';
	import { gradeColor } from './analytics-types';

	let crypto: CryptoPostureResponse | null = $state(null);
	let ciphers: CipherStats | null = $state(null);
	let loading = $state(true);
	let error: string | null = $state(null);

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

	// Donut chart helpers
	const ALGO_COLORS: Record<string, string> = {
		'RSA': '#38bdf8',
		'ECDSA': '#a78bfa',
		'Ed25519': '#34d399',
		'Unknown': '#64748b',
	};

	function algoColor(algo: string): string {
		return ALGO_COLORS[algo] ?? '#64748b';
	}

	// Strength colors
	const STRENGTH_COLORS: Record<string, string> = {
		'Best': '#22c55e',
		'Strong': '#38bdf8',
		'Acceptable': '#eab308',
		'Weak': '#f97316',
		'Insecure': '#ef4444',
		'Unknown': '#64748b',
	};

	function strengthColor(s: string): string {
		return STRENGTH_COLORS[s] ?? '#64748b';
	}

	// TLS version ordering
	const TLS_ORDER = ['SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3'];
	const STRENGTH_ORDER = ['Best', 'Strong', 'Acceptable', 'Weak', 'Insecure'];

	function heatmapValue(version: string, strength: string): number {
		if (!ciphers) return 0;
		const row = ciphers.tls_cipher_matrix.find(
			r => r.tls_version === version && r.strength === strength
		);
		return row?.count ?? 0;
	}

	function heatmapMax(): number {
		if (!ciphers) return 1;
		return Math.max(...ciphers.tls_cipher_matrix.map(r => r.count), 1);
	}

	function heatmapColor(count: number, version: string, strength: string): string {
		if (count === 0) return 'rgba(30, 41, 59, 0.3)';
		const intensity = Math.min(count / heatmapMax(), 1);
		// Color based on strength, opacity based on count
		const base = strengthColor(strength);
		return base;
	}

	function heatmapOpacity(count: number): number {
		if (count === 0) return 0.1;
		return 0.2 + 0.6 * Math.min(count / heatmapMax(), 1);
	}

	// Donut arc path
	function donutArc(startAngle: number, endAngle: number, r: number, cx: number, cy: number): string {
		const x1 = cx + r * Math.cos(startAngle - Math.PI / 2);
		const y1 = cy + r * Math.sin(startAngle - Math.PI / 2);
		const x2 = cx + r * Math.cos(endAngle - Math.PI / 2);
		const y2 = cy + r * Math.sin(endAngle - Math.PI / 2);
		const large = endAngle - startAngle > Math.PI ? 1 : 0;
		return `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`;
	}
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
		</div>

		<div class="panels-grid">
			<!-- Key Algorithm Donut -->
			<div class="panel">
				<h3>Key Algorithm</h3>
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
						<text x="60" y="70" text-anchor="middle" fill="#64748b" font-size="8">
							total
						</text>
					</svg>
					<div class="donut-legend">
						{#each crypto.key_algorithms as algo}
							<div class="legend-row">
								<span class="legend-dot" style="background: {algoColor(algo.algorithm)}"></span>
								<span class="legend-name">{algo.algorithm}</span>
								<span class="legend-count">{algo.count.toLocaleString()}</span>
								<span class="legend-pct">{(algo.count / crypto.total_certs * 100).toFixed(1)}%</span>
							</div>
						{/each}
					</div>
				</div>
			</div>

			<!-- Key Size Distribution -->
			<div class="panel">
				<h3>Key Size Distribution</h3>
				<div class="bar-list">
					{#each crypto.key_sizes as ks}
						{@const maxCount = Math.max(...crypto.key_sizes.map(k => k.count), 1)}
						<div class="bar-row">
							<span class="bar-label">{ks.algorithm} {ks.size_bits}</span>
							<div class="bar-track">
								<div class="bar-fill" style="width: {(ks.count / maxCount) * 100}%; background: {algoColor(ks.algorithm)}"></div>
							</div>
							<span class="bar-count">{ks.count.toLocaleString()}</span>
						</div>
					{/each}
				</div>
			</div>

			<!-- TLS x Cipher Heatmap -->
			<div class="panel">
				<h3>TLS Version x Cipher Strength</h3>
				<div class="heatmap-container">
					<div class="heatmap-grid" style="grid-template-columns: auto repeat({STRENGTH_ORDER.length}, 1fr);">
						<!-- Header row -->
						<div class="heatmap-corner"></div>
						{#each STRENGTH_ORDER as strength}
							<div class="heatmap-col-header" style="color: {strengthColor(strength)}">{strength}</div>
						{/each}

						<!-- Data rows -->
						{#each TLS_ORDER as version}
							<div class="heatmap-row-header">{version}</div>
							{#each STRENGTH_ORDER as strength}
								{@const count = heatmapValue(version, strength)}
								<div
									class="heatmap-cell"
									style="background: {heatmapColor(count, version, strength)}; opacity: {heatmapOpacity(count)}"
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
				<h3>Signature Algorithm</h3>
				<div class="bar-list">
					{#each crypto.signature_algorithms as sa}
						{@const maxCount = Math.max(...crypto.signature_algorithms.map(s => s.count), 1)}
						{@const isWeak = sa.algorithm.includes('SHA1') || sa.algorithm.includes('MD5')}
						<div class="bar-row">
							<span class="bar-label" class:weak-algo={isWeak}>{sa.algorithm}</span>
							<div class="bar-track">
								<div class="bar-fill" style="width: {(sa.count / maxCount) * 100}%; background: {isWeak ? '#ef4444' : '#38bdf8'}"></div>
							</div>
							<span class="bar-count">{sa.count.toLocaleString()}</span>
						</div>
					{/each}
				</div>
			</div>
		</div>

		<!-- TLS Strength Summary -->
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
	.tab-meta { font-size: 0.8rem; color: var(--cf-text-muted); }

	.panels-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 1rem;
		margin-bottom: 1.25rem;
	}

	.panel {
		background: var(--cf-bg-secondary, rgba(15, 23, 42, 0.5));
		border: 1px solid var(--cf-border, rgba(56, 189, 248, 0.1));
		border-radius: 8px;
		padding: 1rem;
	}

	h3 {
		margin: 0 0 0.75rem;
		font-size: 0.75rem;
		font-weight: 600;
		color: var(--cf-text-muted, #64748b);
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}

	/* Donut */
	.donut-row { display: flex; align-items: center; gap: 1.5rem; }
	.donut-svg { width: 120px; height: 120px; flex-shrink: 0; }
	.donut-legend { display: flex; flex-direction: column; gap: 0.375rem; flex: 1; }
	.legend-row { display: flex; align-items: center; gap: 0.5rem; }
	.legend-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
	.legend-name { font-size: 0.85rem; font-weight: 600; color: var(--cf-text-primary, #e2e8f0); flex: 1; }
	.legend-count { font-size: 0.8rem; color: var(--cf-text-secondary, #94a3b8); font-variant-numeric: tabular-nums; }
	.legend-pct { font-size: 0.75rem; color: var(--cf-text-muted, #64748b); font-variant-numeric: tabular-nums; width: 40px; text-align: right; }

	/* Bars */
	.bar-list { display: flex; flex-direction: column; gap: 0.375rem; }
	.bar-row { display: flex; align-items: center; gap: 0.75rem; }
	.bar-label { width: 140px; font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: var(--cf-text-primary, #e2e8f0); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex-shrink: 0; }
	.bar-label.weak-algo { color: #ef4444; }
	.bar-track { flex: 1; height: 16px; background: var(--cf-bg-tertiary, rgba(30, 41, 59, 0.5)); border-radius: 3px; overflow: hidden; }
	.bar-fill { height: 100%; border-radius: 3px; opacity: 0.7; transition: width 0.3s ease; }
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
		font-weight: 600; color: #e2e8f0; cursor: default;
		transition: opacity 0.15s;
	}
	.heatmap-cell:hover { opacity: 1 !important; }
	.heatmap-cell span { text-shadow: 0 1px 2px rgba(0,0,0,0.5); }

	/* Strength summary */
	.strength-summary {
		background: var(--cf-bg-secondary, rgba(15, 23, 42, 0.5));
		border: 1px solid var(--cf-border, rgba(56, 189, 248, 0.1));
		border-radius: 8px;
		padding: 1rem;
	}
	.strength-bars { display: flex; flex-direction: column; gap: 0.5rem; }
	.strength-row { display: flex; align-items: center; gap: 0.75rem; }
	.strength-label { width: 80px; font-size: 0.8rem; font-weight: 600; flex-shrink: 0; }

	.tab-loading, .tab-error { display: flex; align-items: center; justify-content: center; height: 50vh; color: var(--cf-text-muted); font-size: 0.9rem; }
	.tab-error { color: var(--cf-risk-critical); }
</style>
