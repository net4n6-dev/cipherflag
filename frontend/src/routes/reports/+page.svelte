<script lang="ts">
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import DomainReport from '$lib/components/reports/DomainReport.svelte';
	import CAReport from '$lib/components/reports/CAReport.svelte';
	import ComplianceReport from '$lib/components/reports/ComplianceReport.svelte';
	import ExpiryReport from '$lib/components/reports/ExpiryReport.svelte';

	let reportType = $derived(page.url.searchParams.get('type'));
	let q = $derived(page.url.searchParams.get('q') ?? '');
	let fp = $derived(page.url.searchParams.get('fp') ?? '');
	let issuerCN = $derived(page.url.searchParams.get('issuer_cn') ?? '');
	let daysParam = $derived(Number(page.url.searchParams.get('days')) || 30);

	let domainInput = $state('');
	let caInput = $state('');

	function generateDomainReport() {
		if (!domainInput.trim()) return;
		goto(`/reports?type=domain&q=${encodeURIComponent(domainInput.trim())}`, { replaceState: true });
	}

	function generateCAReport() {
		if (!caInput.trim()) return;
		goto(`/reports?type=ca&issuer_cn=${encodeURIComponent(caInput.trim())}`, { replaceState: true });
	}

	function generateComplianceReport() {
		goto('/reports?type=compliance', { replaceState: true });
	}

	function generateExpiryReport(days: number) {
		goto(`/reports?type=expiry&days=${days}`, { replaceState: true });
	}
</script>

<svelte:head>
	<title>Reports - CipherFlag</title>
</svelte:head>

{#if !reportType}
	<div class="reports-landing">
		<div class="landing-header">
			<h1>Reports</h1>
			<p>Generate detailed certificate reports for analysis, compliance, and risk assessment.</p>
		</div>

		<div class="report-cards">
			<!-- Domain Certificate Report -->
			<div class="report-card">
				<div class="card-header">
					<span class="card-icon">&#9673;</span>
					<h2>Domain Certificate Report</h2>
				</div>
				<p class="card-desc">Comprehensive view of all certificates associated with a domain, including deployments, health findings, and wildcard usage.</p>
				<div class="card-input-row">
					<input
						type="text"
						class="card-input"
						placeholder="e.g. example.com"
						bind:value={domainInput}
						onkeydown={(e) => { if (e.key === 'Enter') generateDomainReport(); }}
					/>
					<button class="card-btn" onclick={generateDomainReport}>Generate</button>
				</div>
			</div>

			<!-- CA Authority Report -->
			<div class="report-card">
				<div class="card-header">
					<span class="card-icon">&#9670;</span>
					<h2>CA Authority Report</h2>
				</div>
				<p class="card-desc">Deep dive into a Certificate Authority: identity, issued certificates, cryptographic breakdown, and chain context.</p>
				<div class="card-input-row">
					<input
						type="text"
						class="card-input"
						placeholder="e.g. DigiCert Global G2"
						bind:value={caInput}
						onkeydown={(e) => { if (e.key === 'Enter') generateCAReport(); }}
					/>
					<button class="card-btn" onclick={generateCAReport}>Generate</button>
				</div>
			</div>

			<!-- Crypto Compliance Report -->
			<div class="report-card">
				<div class="card-header">
					<span class="card-icon">&#9745;</span>
					<h2>Crypto Compliance Report</h2>
				</div>
				<p class="card-desc">Compliance score across your full inventory with critical issues, remediation priorities, and category breakdowns.</p>
				<div class="card-input-row">
					<button class="card-btn card-btn-full" onclick={generateComplianceReport}>Generate Report</button>
				</div>
			</div>

			<!-- Expiry Risk Report -->
			<div class="report-card">
				<div class="card-header">
					<span class="card-icon">&#9200;</span>
					<h2>Expiry Risk Report</h2>
				</div>
				<p class="card-desc">Certificates approaching expiry with issuer and owner breakdowns, ghost certificates, and at-risk deployments.</p>
				<div class="card-input-row expiry-btns">
					<button class="card-btn" onclick={() => generateExpiryReport(30)}>30 days</button>
					<button class="card-btn" onclick={() => generateExpiryReport(60)}>60 days</button>
					<button class="card-btn" onclick={() => generateExpiryReport(90)}>90 days</button>
				</div>
			</div>
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
	.reports-landing {
		padding: 2rem;
		overflow-y: auto;
		height: 100%;
	}

	.landing-header {
		margin-bottom: 2rem;
	}

	.landing-header h1 {
		margin: 0;
		font-size: 1.5rem;
		font-weight: 700;
		color: var(--cf-text-primary);
	}

	.landing-header p {
		margin: 0.5rem 0 0 0;
		font-size: 0.9rem;
		color: var(--cf-text-secondary);
	}

	.report-cards {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
		gap: 1.25rem;
	}

	.report-card {
		background: var(--cf-bg-secondary);
		border: 1px solid var(--cf-border);
		border-radius: 8px;
		padding: 1.25rem;
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
		transition: border-color 0.15s;
	}

	.report-card:hover {
		border-color: var(--cf-border-hover);
	}

	.card-header {
		display: flex;
		align-items: center;
		gap: 0.75rem;
	}

	.card-icon {
		font-size: 1.3rem;
		color: var(--cf-accent);
	}

	.card-header h2 {
		margin: 0;
		font-size: 1rem;
		font-weight: 700;
		color: var(--cf-text-primary);
	}

	.card-desc {
		margin: 0;
		font-size: 0.82rem;
		color: var(--cf-text-muted);
		line-height: 1.5;
	}

	.card-input-row {
		display: flex;
		gap: 0.5rem;
		margin-top: auto;
	}

	.card-input {
		flex: 1;
		padding: 0.5rem 0.75rem;
		font-size: 0.82rem;
		background: var(--cf-bg-primary);
		border: 1px solid var(--cf-border);
		border-radius: 6px;
		color: var(--cf-text-primary);
		outline: none;
		font-family: 'JetBrains Mono', monospace;
	}

	.card-input::placeholder {
		color: var(--cf-text-muted);
	}

	.card-input:focus {
		border-color: var(--cf-accent);
	}

	.card-btn {
		padding: 0.5rem 1rem;
		font-size: 0.82rem;
		font-weight: 600;
		background: rgba(56, 189, 248, 0.1);
		border: 1px solid rgba(56, 189, 248, 0.2);
		border-radius: 6px;
		color: var(--cf-accent);
		cursor: pointer;
		transition: all 0.15s;
		white-space: nowrap;
	}

	.card-btn:hover {
		background: rgba(56, 189, 248, 0.2);
	}

	.card-btn-full {
		flex: 1;
	}

	.expiry-btns {
		display: flex;
		gap: 0.5rem;
	}

	.expiry-btns .card-btn {
		flex: 1;
	}

	.report-error {
		display: flex;
		align-items: center;
		justify-content: center;
		height: 50vh;
		color: var(--cf-risk-critical);
		font-size: 0.9rem;
	}
</style>
