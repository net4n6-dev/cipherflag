<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { api, type DeploymentGroup, type IssuerStat } from '$lib/api';
	import DomainReport from '$lib/components/reports/DomainReport.svelte';
	import CAReport from '$lib/components/reports/CAReport.svelte';
	import ComplianceReport from '$lib/components/reports/ComplianceReport.svelte';
	import ExpiryReport from '$lib/components/reports/ExpiryReport.svelte';

	let reportType = $derived(page.url.searchParams.get('type'));
	let q = $derived(page.url.searchParams.get('q') ?? '');
	let fp = $derived(page.url.searchParams.get('fp') ?? '');
	let issuerCN = $derived(page.url.searchParams.get('issuer_cn') ?? '');
	let daysParam = $derived(Number(page.url.searchParams.get('days')) || 30);

	// Landing page data
	let domains = $state<DeploymentGroup[]>([]);
	let issuers = $state<IssuerStat[]>([]);
	let landingLoading = $state(true);

	let domainSearch = $state('');
	let caSearch = $state('');

	onMount(async () => {
		if (!reportType) {
			try {
				const [dep, iss] = await Promise.all([
					api.getDeployment(),
					api.getIssuers(),
				]);
				domains = dep.groups;
				issuers = (iss as any).issuers ?? [];
			} catch {}
			landingLoading = false;
		}
	});

	const GRADE_COLORS: Record<string, string> = {
		'A+': '#22c55e', 'A': '#22c55e', 'B': '#84cc16',
		'C': '#eab308', 'D': '#f97316', 'F': '#ef4444', '?': '#64748b',
	};

	function gradeColor(g: string): string { return GRADE_COLORS[g] ?? '#64748b'; }

	function openDomainReport(domain: string) {
		goto(`/reports?type=domain&q=${encodeURIComponent(domain)}`);
	}

	function openCAReport(cn: string) {
		goto(`/reports?type=ca&issuer_cn=${encodeURIComponent(cn)}`);
	}

	function searchDomain() {
		if (domainSearch.trim()) openDomainReport(domainSearch.trim());
	}

	function searchCA() {
		if (caSearch.trim()) openCAReport(caSearch.trim());
	}
</script>

<svelte:head>
	<title>Reports - CipherFlag</title>
</svelte:head>

{#if !reportType}
	<div class="reports-landing">
		<div class="landing-header">
			<h1>Reports</h1>
			<p>Select a domain, CA, or report type to generate detailed analysis.</p>
		</div>

		<div class="report-sections">
			<!-- Domain Certificate Reports -->
			<section class="report-section">
				<div class="section-header">
					<h2>Domain Certificate Reports</h2>
					<div class="section-search">
						<input
							type="text"
							placeholder="Search any domain..."
							bind:value={domainSearch}
							onkeydown={(e) => { if (e.key === 'Enter') searchDomain(); }}
						/>
						<button onclick={searchDomain}>Go</button>
					</div>
				</div>
				{#if landingLoading}
					<div class="section-loading">Loading domains...</div>
				{:else if domains.length === 0}
					<div class="section-empty">No deployment data available. Run network capture to discover domains.</div>
				{:else}
					<div class="domain-grid">
						{#each domains.slice(0, 12) as domain}
							<button class="domain-card" onclick={() => openDomainReport(domain.domain)}>
								<div class="dc-top">
									<span class="dc-name">{domain.domain}</span>
									<span class="dc-grade" style="color: {gradeColor(domain.worst_grade)}">{domain.worst_grade}</span>
								</div>
								<div class="dc-stats">
									<span>{domain.cert_count} certs</span>
									<span>{domain.unique_ips} IPs</span>
									{#if domain.expired_count > 0}
										<span class="dc-expired">{domain.expired_count} expired</span>
									{/if}
								</div>
								<div class="dc-score-bar">
									<div class="dc-score-fill" style="width: {domain.avg_score}%; background: {gradeColor(domain.worst_grade)}"></div>
								</div>
							</button>
						{/each}
					</div>
					{#if domains.length > 12}
						<div class="section-more">{domains.length - 12} more domains available — use search above</div>
					{/if}
				{/if}
			</section>

			<!-- CA Authority Reports -->
			<section class="report-section">
				<div class="section-header">
					<h2>CA Authority Reports</h2>
					<div class="section-search">
						<input
							type="text"
							placeholder="Search any CA..."
							bind:value={caSearch}
							onkeydown={(e) => { if (e.key === 'Enter') searchCA(); }}
						/>
						<button onclick={searchCA}>Go</button>
					</div>
				</div>
				{#if landingLoading}
					<div class="section-loading">Loading CAs...</div>
				{:else if issuers.length === 0}
					<div class="section-empty">No CA data available.</div>
				{:else}
					<div class="ca-grid">
						{#each issuers.slice(0, 8) as issuer}
							<button class="ca-card" onclick={() => openCAReport(issuer.issuer_cn)}>
								<div class="ca-top">
									<span class="ca-name">{issuer.issuer_cn}</span>
									<span class="ca-grade" style="color: {gradeColor(issuer.min_grade)}">{issuer.min_grade}</span>
								</div>
								<div class="ca-meta">{issuer.issuer_org}{issuer.country ? ` · ${issuer.country}` : ''}</div>
								<div class="ca-stats">
									<span>{issuer.cert_count} certs</span>
									<span>Avg: {issuer.avg_score}</span>
									{#if issuer.expired_count > 0}
										<span class="ca-expired">{issuer.expired_count} expired</span>
									{/if}
								</div>
							</button>
						{/each}
					</div>
				{/if}
			</section>

			<!-- Quick Reports -->
			<section class="report-section">
				<h2>Quick Reports</h2>
				<div class="quick-grid">
					<button class="quick-card compliance" onclick={() => goto('/reports?type=compliance')}>
						<span class="qc-icon">&#9745;</span>
						<div class="qc-info">
							<h3>Crypto Compliance</h3>
							<p>Full inventory compliance score, critical issues, and remediation priorities</p>
						</div>
						<span class="qc-arrow">→</span>
					</button>
					<button class="quick-card expiry" onclick={() => goto('/reports?type=expiry&days=30')}>
						<span class="qc-icon">&#9200;</span>
						<div class="qc-info">
							<h3>Expiry Risk (30 days)</h3>
							<p>Certificates expiring soon with owner and deployment breakdown</p>
						</div>
						<span class="qc-arrow">→</span>
					</button>
					<button class="quick-card expiry" onclick={() => goto('/reports?type=expiry&days=90')}>
						<span class="qc-icon">&#9200;</span>
						<div class="qc-info">
							<h3>Expiry Risk (90 days)</h3>
							<p>Broader expiry window including ghost certs and at-risk deployments</p>
						</div>
						<span class="qc-arrow">→</span>
					</button>
				</div>
			</section>
		</div>
	</div>
{:else if reportType === 'domain'}
	<DomainReport domain={q} />
{:else if reportType === 'ca'}
	<CAReport fingerprint={fp || undefined} issuerCN={issuerCN || undefined} />
{:else if reportType === 'compliance'}
	<ComplianceReport />
{:else if reportType === 'expiry'}
	<ExpiryReport days={daysParam} />
{:else}
	<div class="report-error">Unknown report type: {reportType}</div>
{/if}

<style>
	.reports-landing { padding: 2rem; overflow-y: auto; height: 100%; }

	.landing-header { margin-bottom: 1.5rem; }
	.landing-header h1 { margin: 0; font-size: 1.5rem; font-weight: 700; color: var(--cf-text-primary); }
	.landing-header p { margin: 0.375rem 0 0; font-size: 0.85rem; color: var(--cf-text-secondary); }

	.report-sections { display: flex; flex-direction: column; gap: 2rem; }

	.report-section h2 { margin: 0; font-size: 1rem; font-weight: 700; color: var(--cf-text-primary); }

	.section-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1rem; }

	.section-search { display: flex; gap: 0.375rem; }
	.section-search input {
		padding: 0.375rem 0.625rem; font-size: 0.8rem;
		background: var(--cf-bg-tertiary); border: 1px solid var(--cf-border);
		border-radius: 6px; color: var(--cf-text-primary); outline: none;
		font-family: 'JetBrains Mono', monospace; width: 200px;
	}
	.section-search input::placeholder { color: var(--cf-text-muted); }
	.section-search input:focus { border-color: var(--cf-accent); }
	.section-search button {
		padding: 0.375rem 0.75rem; font-size: 0.8rem; font-weight: 600;
		background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.2);
		border-radius: 6px; color: var(--cf-accent); cursor: pointer;
	}
	.section-search button:hover { background: rgba(56, 189, 248, 0.2); }

	.section-loading, .section-empty { padding: 1.5rem; text-align: center; font-size: 0.85rem; color: var(--cf-text-muted); }
	.section-more { padding: 0.5rem; text-align: center; font-size: 0.75rem; color: var(--cf-text-muted); }

	/* Domain grid */
	.domain-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 0.75rem; }

	.domain-card {
		display: flex; flex-direction: column; gap: 0.375rem;
		padding: 0.75rem 1rem; background: var(--cf-bg-secondary);
		border: 1px solid var(--cf-border); border-radius: 8px;
		text-align: left; cursor: pointer; transition: all 0.15s;
		color: inherit;
	}
	.domain-card:hover { border-color: var(--cf-accent); background: rgba(56, 189, 248, 0.03); }

	.dc-top { display: flex; justify-content: space-between; align-items: center; }
	.dc-name { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; font-weight: 600; color: var(--cf-text-primary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.dc-grade { font-size: 0.9rem; font-weight: 800; flex-shrink: 0; }
	.dc-stats { display: flex; gap: 0.75rem; font-size: 0.7rem; color: var(--cf-text-muted); }
	.dc-expired { color: #ef4444; }
	.dc-score-bar { height: 3px; background: var(--cf-bg-tertiary); border-radius: 2px; overflow: hidden; }
	.dc-score-fill { height: 100%; border-radius: 2px; opacity: 0.6; }

	/* CA grid */
	.ca-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 0.75rem; }

	.ca-card {
		display: flex; flex-direction: column; gap: 0.25rem;
		padding: 0.75rem 1rem; background: var(--cf-bg-secondary);
		border: 1px solid var(--cf-border); border-radius: 8px;
		text-align: left; cursor: pointer; transition: all 0.15s;
		color: inherit;
	}
	.ca-card:hover { border-color: var(--cf-accent); background: rgba(56, 189, 248, 0.03); }

	.ca-top { display: flex; justify-content: space-between; align-items: center; }
	.ca-name { font-size: 0.8rem; font-weight: 600; color: var(--cf-text-primary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; }
	.ca-grade { font-size: 0.9rem; font-weight: 800; flex-shrink: 0; margin-left: 0.5rem; }
	.ca-meta { font-size: 0.7rem; color: var(--cf-text-muted); }
	.ca-stats { display: flex; gap: 0.75rem; font-size: 0.7rem; color: var(--cf-text-muted); }
	.ca-expired { color: #ef4444; }

	/* Quick reports */
	.quick-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 0.75rem; margin-top: 0.75rem; }

	.quick-card {
		display: flex; align-items: center; gap: 0.75rem;
		padding: 1rem; background: var(--cf-bg-secondary);
		border: 1px solid var(--cf-border); border-radius: 8px;
		text-align: left; cursor: pointer; transition: all 0.15s;
		color: inherit;
	}
	.quick-card:hover { border-color: var(--cf-accent); }

	.qc-icon { font-size: 1.5rem; flex-shrink: 0; }
	.qc-info { flex: 1; }
	.qc-info h3 { margin: 0; font-size: 0.9rem; font-weight: 600; color: var(--cf-text-primary); }
	.qc-info p { margin: 0.25rem 0 0; font-size: 0.75rem; color: var(--cf-text-muted); }
	.qc-arrow { font-size: 1.1rem; color: var(--cf-accent); flex-shrink: 0; }

	.report-error { display: flex; align-items: center; justify-content: center; height: 50vh; color: var(--cf-risk-critical); font-size: 0.9rem; }
</style>
