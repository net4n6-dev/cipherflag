<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type Certificate, type HealthReport } from '$lib/api';

	interface CertRow {
		certificate: Certificate;
		health_report: HealthReport | null;
	}

	let certificates: Certificate[] = $state([]);
	let healthMap: Map<string, HealthReport> = $state(new Map());
	let total = $state(0);
	let page = $state(1);
	let pageSize = 50;
	let search = $state('');
	let gradeFilter = $state('');
	let loading = $state(true);
	let error: string | null = $state(null);

	const GRADE_COLORS: Record<string, string> = {
		'A+': '#22c55e', 'A': '#22c55e', 'B': '#84cc16',
		'C': '#eab308', 'D': '#f97316', 'F': '#ef4444'
	};

	async function load() {
		loading = true;
		try {
			const params = new URLSearchParams();
			params.set('page', String(page));
			params.set('page_size', String(pageSize));
			if (search) params.set('search', search);
			if (gradeFilter) params.set('grade', gradeFilter);

			const res = await fetch(`/api/v1/certificates?${params}`);
			const data = await res.json();
			certificates = data.certificates ?? [];
			total = data.total ?? 0;

			// Fetch health reports for each cert
			const map = new Map<string, HealthReport>();
			await Promise.allSettled(
				certificates.map(async (c) => {
					try {
						const h = await api.getHealth(c.fingerprint_sha256);
						map.set(c.fingerprint_sha256, h);
					} catch {}
				})
			);
			healthMap = map;
			error = null;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load';
		}
		loading = false;
	}

	onMount(() => { load(); });

	function handleSearch() {
		page = 1;
		load();
	}

	function setGrade(g: string) {
		gradeFilter = gradeFilter === g ? '' : g;
		page = 1;
		load();
	}

	function formatDate(d: string): string {
		return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
	}

	function daysUntil(d: string): number {
		return Math.floor((new Date(d).getTime() - Date.now()) / 86400000);
	}

	function expiryClass(d: string): string {
		const days = daysUntil(d);
		if (days < 0) return 'expired';
		if (days < 30) return 'expiring-soon';
		if (days < 90) return 'expiring-warn';
		return '';
	}

	let totalPages = $derived(Math.ceil(total / pageSize) || 1);
	let exportOpen = $state(false);

	function currentParams(): string {
		const params = new URLSearchParams();
		if (search) params.set('search', search);
		if (gradeFilter) params.set('grade', gradeFilter);
		const str = params.toString();
		return str || '';
	}

	function exportAs(format: 'csv' | 'json') {
		api.exportCerts(format, currentParams() || undefined);
		exportOpen = false;
	}
</script>

<div class="cert-page">
	<div class="page-header">
		<h1>Certificates</h1>
		<span class="total-count">{total} total</span>
	</div>

	<div class="controls">
		<div class="search-box">
			<input
				type="text"
				placeholder="Search CN, org, fingerprint..."
				bind:value={search}
				onkeydown={(e) => e.key === 'Enter' && handleSearch()}
			/>
			<button onclick={handleSearch}>Search</button>
		</div>
		<div class="grade-filters">
			{#each ['A+', 'A', 'B', 'C', 'D', 'F'] as g}
				<button
					class="grade-pill"
					class:active={gradeFilter === g}
					style="--pill-color: {GRADE_COLORS[g]}"
					onclick={() => setGrade(g)}
				>{g}</button>
			{/each}
		</div>
		<div class="export-wrapper">
			<button class="export-btn" onclick={() => { exportOpen = !exportOpen; }}>
				Export &#9662;
			</button>
			{#if exportOpen}
				<!-- svelte-ignore a11y_no_static_element_interactions a11y_click_events_have_key_events -->
				<div class="export-backdrop" onclick={() => { exportOpen = false; }}></div>
				<div class="export-dropdown">
					<button class="export-option" onclick={() => exportAs('csv')}>Export CSV</button>
					<button class="export-option" onclick={() => exportAs('json')}>Export JSON</button>
				</div>
			{/if}
		</div>
	</div>

	{#if loading}
		<div class="loading">Loading...</div>
	{:else if error}
		<div class="error">{error}</div>
	{:else if certificates.length === 0}
		<div class="empty">No certificates found</div>
	{:else}
		<div class="table-wrap">
			<table>
				<thead>
					<tr>
						<th>Grade</th>
						<th>Common Name</th>
						<th>Issuer</th>
						<th>Algorithm</th>
						<th>Expires</th>
						<th>Source</th>
					</tr>
				</thead>
				<tbody>
					{#each certificates as cert}
						{@const health = healthMap.get(cert.fingerprint_sha256)}
						<tr>
							<td>
								{#if health}
									<span class="grade-badge" style="background: {GRADE_COLORS[health.grade] ?? '#64748b'}">{health.grade}</span>
								{:else}
									<span class="grade-badge" style="background: #64748b">?</span>
								{/if}
							</td>
							<td>
								<div class="cn-cell">
									<a href="/certificates/{cert.fingerprint_sha256}" class="cn-link">{cert.subject.common_name || cert.fingerprint_sha256.slice(0, 16)}</a>
									{#if cert.is_ca}<span class="ca-badge">CA</span>{/if}
								</div>
								<div class="cn-org">{cert.subject.organization}</div>
							</td>
							<td class="issuer-cell">{cert.issuer.common_name}</td>
							<td class="algo-cell">{cert.key_algorithm} {cert.key_size_bits}</td>
							<td class="expiry-cell {expiryClass(cert.not_after)}">
								<div>{formatDate(cert.not_after)}</div>
								<div class="days-label">
									{#if daysUntil(cert.not_after) < 0}
										Expired {Math.abs(daysUntil(cert.not_after))}d ago
									{:else}
										{daysUntil(cert.not_after)}d
									{/if}
								</div>
							</td>
							<td class="source-cell">{cert.source_discovery}</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>

		<div class="pagination">
			<button disabled={page <= 1} onclick={() => { page--; load(); }}>Prev</button>
			<span>Page {page} of {totalPages}</span>
			<button disabled={page >= totalPages} onclick={() => { page++; load(); }}>Next</button>
		</div>
	{/if}
</div>

<style>
	.cert-page {
		padding: 1.5rem;
		max-width: 1400px;
		margin: 0 auto;
		height: 100%;
		display: flex;
		flex-direction: column;
		overflow: hidden;
	}

	.page-header {
		display: flex;
		align-items: baseline;
		gap: 1rem;
		margin-bottom: 1rem;
		flex-shrink: 0;
	}

	.page-header h1 {
		font-size: 1.4rem;
		font-weight: 700;
		margin: 0;
		color: var(--cf-text-primary);
	}

	.total-count {
		font-size: 0.85rem;
		color: var(--cf-text-muted);
	}

	.controls {
		display: flex;
		gap: 1rem;
		align-items: center;
		margin-bottom: 1rem;
		flex-shrink: 0;
		flex-wrap: wrap;
	}

	.search-box {
		display: flex;
		gap: 0.5rem;
		flex: 1;
		min-width: 250px;
	}

	.search-box input {
		flex: 1;
		padding: 0.5rem 0.75rem;
		background: var(--cf-bg-tertiary);
		border: 1px solid var(--cf-border);
		border-radius: 6px;
		color: var(--cf-text-primary);
		font-size: 0.85rem;
		outline: none;
	}

	.search-box input:focus {
		border-color: var(--cf-accent);
	}

	.search-box button, .pagination button {
		padding: 0.5rem 1rem;
		background: var(--cf-bg-tertiary);
		border: 1px solid var(--cf-border);
		border-radius: 6px;
		color: var(--cf-text-secondary);
		font-size: 0.85rem;
		cursor: pointer;
	}

	.search-box button:hover, .pagination button:hover:not(:disabled) {
		background: var(--cf-border);
		color: var(--cf-text-primary);
	}

	.pagination button:disabled {
		opacity: 0.4;
		cursor: default;
	}

	.grade-filters {
		display: flex;
		gap: 0.35rem;
	}

	.grade-pill {
		padding: 0.3rem 0.6rem;
		border-radius: 4px;
		border: 1px solid var(--cf-border);
		background: var(--cf-bg-tertiary);
		color: var(--cf-text-secondary);
		font-size: 0.8rem;
		font-weight: 600;
		cursor: pointer;
	}

	.grade-pill.active {
		background: var(--pill-color);
		color: white;
		border-color: var(--pill-color);
	}

	.table-wrap {
		flex: 1;
		overflow-y: auto;
		border: 1px solid var(--cf-border);
		border-radius: 8px;
	}

	table {
		width: 100%;
		border-collapse: collapse;
		font-size: 0.85rem;
	}

	thead {
		position: sticky;
		top: 0;
		z-index: 1;
	}

	th {
		text-align: left;
		padding: 0.625rem 1rem;
		background: var(--cf-bg-secondary);
		color: var(--cf-text-muted);
		font-weight: 600;
		font-size: 0.75rem;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		border-bottom: 1px solid var(--cf-border);
	}

	td {
		padding: 0.625rem 1rem;
		border-bottom: 1px solid var(--cf-border);
		color: var(--cf-text-secondary);
	}

	tr:hover td {
		background: rgba(56, 189, 248, 0.04);
	}

	.grade-badge {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 28px;
		height: 28px;
		border-radius: 6px;
		font-weight: 700;
		font-size: 0.8rem;
		color: white;
	}

	.cn-cell {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.cn-link {
		color: var(--cf-text-primary);
		text-decoration: none;
		font-weight: 500;
	}

	.cn-link:hover {
		color: var(--cf-accent);
	}

	.ca-badge {
		font-size: 0.65rem;
		padding: 0.1rem 0.35rem;
		border-radius: 3px;
		background: var(--cf-node-intermediate);
		color: white;
		font-weight: 600;
	}

	.cn-org {
		font-size: 0.75rem;
		color: var(--cf-text-muted);
		margin-top: 0.15rem;
	}

	.issuer-cell {
		max-width: 200px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.algo-cell {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.8rem;
	}

	.expiry-cell {
		white-space: nowrap;
	}

	.expiry-cell.expired { color: var(--cf-risk-critical); }
	.expiry-cell.expiring-soon { color: var(--cf-risk-high); }
	.expiry-cell.expiring-warn { color: var(--cf-risk-medium); }

	.days-label {
		font-size: 0.7rem;
		color: inherit;
		opacity: 0.8;
	}

	.source-cell {
		font-size: 0.8rem;
		font-family: 'JetBrains Mono', monospace;
	}

	.pagination {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 1rem;
		padding: 0.75rem 0;
		flex-shrink: 0;
		font-size: 0.85rem;
		color: var(--cf-text-secondary);
	}

	.loading, .error, .empty {
		display: flex;
		align-items: center;
		justify-content: center;
		flex: 1;
		color: var(--cf-text-muted);
		font-size: 0.95rem;
	}

	.error { color: var(--cf-risk-critical); }

	.export-wrapper {
		position: relative;
	}

	.export-btn {
		padding: 0.5rem 1rem;
		background: var(--cf-bg-tertiary);
		border: 1px solid var(--cf-border);
		border-radius: 6px;
		color: var(--cf-text-secondary);
		font-size: 0.85rem;
		cursor: pointer;
		transition: all 0.15s;
		white-space: nowrap;
	}

	.export-btn:hover {
		background: var(--cf-border);
		color: var(--cf-text-primary);
	}

	.export-backdrop {
		position: fixed;
		inset: 0;
		z-index: 9;
	}

	.export-dropdown {
		position: absolute;
		top: calc(100% + 4px);
		right: 0;
		background: var(--cf-bg-secondary);
		border: 1px solid var(--cf-border);
		border-radius: 6px;
		overflow: hidden;
		z-index: 10;
		min-width: 140px;
		box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
	}

	.export-option {
		display: block;
		width: 100%;
		padding: 0.5rem 1rem;
		background: none;
		border: none;
		color: var(--cf-text-secondary);
		font-size: 0.85rem;
		text-align: left;
		cursor: pointer;
		transition: all 0.15s;
	}

	.export-option:hover {
		background: var(--cf-bg-tertiary);
		color: var(--cf-text-primary);
	}

	.export-option + .export-option {
		border-top: 1px solid var(--cf-border);
	}
</style>
