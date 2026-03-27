<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import cytoscape from 'cytoscape';
	import { api, type CertDetail, type GraphResponse } from '$lib/api';

	let detail: CertDetail | null = $state(null);
	let chainGraph: GraphResponse | null = $state(null);
	let loading = $state(true);
	let error: string | null = $state(null);
	let graphContainer: HTMLDivElement = $state(null!);
	let cy: cytoscape.Core;

	const GRADE_COLORS: Record<string, string> = {
		'A+': '#22c55e', 'A': '#22c55e', 'B': '#84cc16',
		'C': '#eab308', 'D': '#f97316', 'F': '#ef4444'
	};

	const RISK_COLORS: Record<string, string> = {
		critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e'
	};

	onMount(() => {
		const fp = page.params.fingerprint;
		if (fp) loadCert(fp);
		return () => { if (cy) cy.destroy(); };
	});

	// Init graph when both container and data are ready
	$effect(() => {
		if (graphContainer && chainGraph && !loading) {
			// Small delay to ensure container has layout dimensions
			setTimeout(() => initGraph(chainGraph!), 100);
		}
	});

	async function loadCert(fp: string) {
		loading = true;
		try {
			const [d, g] = await Promise.all([
				api.getCert(fp),
				api.getChainGraph(fp)
			]);
			detail = d;
			chainGraph = g;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load certificate';
		}
		loading = false;
	}

	function initGraph(data: GraphResponse) {
		if (cy) cy.destroy();

		const elements: cytoscape.ElementDefinition[] = [];

		for (const node of data.nodes) {
			if (node.data.type === 'group') continue;
			elements.push({
				group: 'nodes',
				data: {
					...node.data,
					_color: GRADE_COLORS[node.data.grade ?? ''] ?? '#64748b',
					_borderColor: RISK_COLORS[node.data.risk] ?? '#334155',
					_size: node.data.is_ca ? 50 : 40,
					_shape: node.data.is_ca ? 'diamond' : 'ellipse',
					_selected: node.data.id === page.params.fingerprint
				}
			});
		}

		for (const edge of data.edges) {
			elements.push({
				group: 'edges',
				data: { ...edge.data, _color: '#38bdf8', _width: 2 }
			});
		}

		cy = cytoscape({
			container: graphContainer,
			elements,
			style: [
				{
					selector: 'node',
					style: {
						'background-color': 'data(_color)',
						'border-color': 'data(_borderColor)',
						'border-width': 2,
						'width': 'data(_size)',
						'height': 'data(_size)',
						'label': 'data(label)',
						'color': '#cbd5e1',
						'font-size': 11,
						'text-valign': 'bottom',
						'text-margin-y': 8,
						'text-outline-color': '#0a0e17',
						'text-outline-width': 2,
						'shape': 'data(_shape)' as any,
						'overlay-opacity': 0
					}
				},
				{
					selector: 'node[?_selected]',
					style: {
						'border-color': '#38bdf8',
						'border-width': 4
					}
				},
				{
					selector: 'edge',
					style: {
						'line-color': 'data(_color)',
						'target-arrow-color': 'data(_color)',
						'target-arrow-shape': 'triangle',
						'arrow-scale': 1,
						'width': 'data(_width)',
						'curve-style': 'bezier',
						'opacity': 0.7
					}
				}
			],
			layout: {
				name: 'breadthfirst',
				directed: true,
				spacingFactor: 1.5,
				padding: 30,
				animate: true,
				animationDuration: 500
			},
			minZoom: 0.5,
			maxZoom: 2,
			wheelSensitivity: 0.3,
			userZoomingEnabled: true,
			userPanningEnabled: true
		});

		cy.on('tap', 'node', (evt) => {
			const fp = evt.target.data('id');
			if (fp && fp !== page.params.fingerprint) {
				window.location.href = `/certificates/${fp}`;
			}
		});
	}

	function formatDate(d: string): string {
		return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
	}

	function daysUntil(d: string): number {
		return Math.floor((new Date(d).getTime() - Date.now()) / 86400000);
	}

	function gradeColor(g: string): string {
		return GRADE_COLORS[g] ?? '#64748b';
	}

</script>

<div class="cert-detail">
	{#if loading}
		<div class="loading">Loading certificate...</div>
	{:else if error}
		<div class="error">{error}</div>
	{:else if detail}
		{@const cert = detail.certificate}
		{@const health = detail.health_report}

		<div class="detail-top">
			<div class="detail-header">
				<a href="/certificates" class="back-link">&larr; Certificates</a>
				<div class="header-row">
					{#if health}
						<span class="grade-badge" style="background: {gradeColor(health.grade)}">{health.grade}</span>
					{/if}
					<h1>{cert.subject.common_name || cert.fingerprint_sha256.slice(0, 20)}</h1>
					{#if cert.is_ca}<span class="ca-tag">CA</span>{/if}
				</div>
				<div class="sub-info">
					<span>{cert.subject.organization}</span>
					{#if cert.issuer.common_name}
						<span class="sep">&#x2192;</span>
						<span class="issuer">Issued by {cert.issuer.common_name}</span>
					{/if}
				</div>
			</div>

			<!-- Metadata grid -->
			<div class="meta-grid">
				<div class="meta-card">
					<div class="meta-label">Algorithm</div>
					<div class="meta-value mono">{cert.key_algorithm} {cert.key_size_bits}</div>
				</div>
				<div class="meta-card">
					<div class="meta-label">Signature</div>
					<div class="meta-value mono">{cert.signature_algorithm}</div>
				</div>
				<div class="meta-card">
					<div class="meta-label">Valid From</div>
					<div class="meta-value">{formatDate(cert.not_before)}</div>
				</div>
				<div class="meta-card" class:warn={daysUntil(cert.not_after) < 30} class:expired={daysUntil(cert.not_after) < 0}>
					<div class="meta-label">Expires</div>
					<div class="meta-value">{formatDate(cert.not_after)}</div>
					<div class="meta-sub">
						{#if daysUntil(cert.not_after) < 0}
							Expired {Math.abs(daysUntil(cert.not_after))}d ago
						{:else}
							{daysUntil(cert.not_after)}d remaining
						{/if}
					</div>
				</div>
				{#if health}
					<div class="meta-card">
						<div class="meta-label">Health Score</div>
						<div class="meta-value">{health.score} / 100</div>
					</div>
				{/if}
				<div class="meta-card">
					<div class="meta-label">Source</div>
					<div class="meta-value mono">{cert.source_discovery}</div>
				</div>
			</div>

			<!-- Fingerprint -->
			<div class="fingerprint">
				<span class="fp-label">SHA-256</span>
				<code>{cert.fingerprint_sha256}</code>
			</div>
		</div>

		<div class="detail-panels">
			<!-- Chain graph -->
			<div class="chain-panel">
				<h2>Trust Chain</h2>
				<div bind:this={graphContainer} class="chain-graph"></div>
				<div class="chain-legend">
					<span class="cl-item"><span class="cl-dot" style="background: var(--cf-node-root)"></span> Root CA</span>
					<span class="cl-item"><span class="cl-dot" style="background: var(--cf-node-intermediate)"></span> Intermediate</span>
					<span class="cl-item"><span class="cl-dot" style="background: var(--cf-node-leaf)"></span> Leaf</span>
				</div>
			</div>

			<!-- Findings -->
			<div class="findings-panel">
				<h2>Health Findings {health?.findings?.length ? `(${health.findings.length})` : ''}</h2>
				{#if health?.findings?.length}
					<div class="findings-list">
						{#each health.findings as finding}
							<div class="finding-card" data-severity={finding.severity.toLowerCase()}>
								<div class="finding-header">
									<span class="finding-severity">{finding.severity}</span>
									<span class="finding-rule">{finding.rule_id}</span>
									{#if finding.deduction}<span class="finding-ded">-{finding.deduction}</span>{/if}
								</div>
								<p class="finding-title">{finding.title}</p>
								<p class="finding-detail">{finding.detail}</p>
								{#if finding.remediation}
									<p class="finding-rem">{finding.remediation}</p>
								{/if}
							</div>
						{/each}
					</div>
				{:else}
					<div class="no-findings">No findings - certificate is healthy</div>
				{/if}

				{#if cert.subject_alt_names?.length}
					<h2 class="san-title">Subject Alt Names ({cert.subject_alt_names.length})</h2>
					<div class="sans-list">
						{#each cert.subject_alt_names as san}
							<span class="san-chip">{san}</span>
						{/each}
					</div>
				{/if}
			</div>
		</div>
	{/if}
</div>

<style>
	.cert-detail {
		height: 100%;
		overflow-y: auto;
		padding: 1.5rem;
		max-width: 1400px;
		margin: 0 auto;
	}

	.back-link {
		font-size: 0.8rem;
		color: var(--cf-text-muted);
		text-decoration: none;
		margin-bottom: 0.5rem;
		display: inline-block;
	}

	.back-link:hover { color: var(--cf-accent); }

	.header-row {
		display: flex;
		align-items: center;
		gap: 0.75rem;
	}

	h1 {
		font-size: 1.3rem;
		font-weight: 700;
		margin: 0;
		color: var(--cf-text-primary);
	}

	.grade-badge {
		width: 36px;
		height: 36px;
		border-radius: 8px;
		display: flex;
		align-items: center;
		justify-content: center;
		font-weight: 700;
		font-size: 1rem;
		color: white;
		flex-shrink: 0;
	}

	.ca-tag {
		font-size: 0.65rem;
		padding: 0.15rem 0.4rem;
		background: var(--cf-node-intermediate);
		color: white;
		border-radius: 3px;
		font-weight: 600;
	}

	.sub-info {
		display: flex;
		gap: 0.5rem;
		font-size: 0.85rem;
		color: var(--cf-text-secondary);
		margin-top: 0.375rem;
	}

	.sep { color: var(--cf-text-muted); }
	.issuer { color: var(--cf-text-muted); }

	/* Meta grid */
	.meta-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
		gap: 0.75rem;
		margin: 1.25rem 0;
	}

	.meta-card {
		background: var(--cf-bg-secondary);
		border: 1px solid var(--cf-border);
		border-radius: 6px;
		padding: 0.75rem;
	}

	.meta-card.warn { border-color: var(--cf-risk-high); }
	.meta-card.expired { border-color: var(--cf-risk-critical); }

	.meta-label {
		font-size: 0.7rem;
		color: var(--cf-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		margin-bottom: 0.25rem;
	}

	.meta-value {
		font-size: 0.9rem;
		color: var(--cf-text-primary);
		font-weight: 500;
	}

	.meta-value.mono {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.8rem;
	}

	.meta-sub {
		font-size: 0.7rem;
		color: inherit;
		opacity: 0.7;
		margin-top: 0.125rem;
	}

	.meta-card.warn .meta-value, .meta-card.warn .meta-sub { color: var(--cf-risk-high); }
	.meta-card.expired .meta-value, .meta-card.expired .meta-sub { color: var(--cf-risk-critical); }

	.fingerprint {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.5rem 0.75rem;
		background: var(--cf-bg-secondary);
		border: 1px solid var(--cf-border);
		border-radius: 6px;
		margin-bottom: 1.25rem;
	}

	.fp-label {
		font-size: 0.7rem;
		color: var(--cf-text-muted);
		text-transform: uppercase;
		flex-shrink: 0;
	}

	.fingerprint code {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.75rem;
		color: var(--cf-text-secondary);
		word-break: break-all;
	}

	/* Panels */
	h2 {
		font-size: 0.8rem;
		font-weight: 600;
		color: var(--cf-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		margin: 0 0 0.75rem;
	}

	.detail-panels {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 1rem;
	}

	.chain-panel, .findings-panel {
		background: var(--cf-bg-secondary);
		border: 1px solid var(--cf-border);
		border-radius: 8px;
		padding: 1.25rem;
	}

	.chain-graph {
		height: 280px;
		background: var(--cf-bg-primary);
		border-radius: 6px;
		border: 1px solid var(--cf-border);
	}

	.chain-legend {
		display: flex;
		gap: 1rem;
		margin-top: 0.75rem;
		font-size: 0.7rem;
		color: var(--cf-text-muted);
	}

	.cl-item {
		display: flex;
		align-items: center;
		gap: 0.35rem;
	}

	.cl-dot {
		width: 8px;
		height: 8px;
		border-radius: 50%;
	}

	/* Findings */
	.findings-list {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		max-height: 300px;
		overflow-y: auto;
	}

	.finding-card {
		padding: 0.625rem;
		border-radius: 6px;
		background: var(--cf-bg-tertiary);
		border-left: 3px solid;
	}

	.finding-card[data-severity="critical"] { border-left-color: var(--cf-risk-critical); }
	.finding-card[data-severity="high"] { border-left-color: var(--cf-risk-high); }
	.finding-card[data-severity="medium"] { border-left-color: var(--cf-risk-medium); }
	.finding-card[data-severity="low"] { border-left-color: var(--cf-risk-low); }
	.finding-card[data-severity="info"] { border-left-color: var(--cf-accent); }

	.finding-header {
		display: flex;
		gap: 0.5rem;
		align-items: center;
		margin-bottom: 0.25rem;
	}

	.finding-severity {
		font-size: 0.65rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}

	.finding-rule {
		font-size: 0.65rem;
		color: var(--cf-text-muted);
		font-family: 'JetBrains Mono', monospace;
	}

	.finding-ded {
		font-size: 0.65rem;
		color: var(--cf-risk-high);
		font-weight: 600;
		margin-left: auto;
	}

	.finding-title {
		margin: 0;
		font-size: 0.82rem;
		font-weight: 500;
		color: var(--cf-text-primary);
	}

	.finding-detail {
		margin: 0.2rem 0 0;
		font-size: 0.75rem;
		color: var(--cf-text-secondary);
	}

	.finding-rem {
		margin: 0.25rem 0 0;
		font-size: 0.7rem;
		color: var(--cf-accent);
		opacity: 0.8;
	}

	.no-findings {
		padding: 1.5rem;
		text-align: center;
		color: var(--cf-grade-a);
		font-size: 0.85rem;
	}

	/* SANs */
	.san-title { margin-top: 1.25rem; }

	.sans-list {
		display: flex;
		flex-wrap: wrap;
		gap: 0.35rem;
	}

	.san-chip {
		padding: 0.2rem 0.5rem;
		background: var(--cf-bg-tertiary);
		border: 1px solid var(--cf-border);
		border-radius: 4px;
		font-size: 0.72rem;
		font-family: 'JetBrains Mono', monospace;
		color: var(--cf-text-secondary);
	}

	.loading, .error {
		display: flex;
		align-items: center;
		justify-content: center;
		height: 50vh;
		color: var(--cf-text-muted);
	}

	.error { color: var(--cf-risk-critical); }
</style>
