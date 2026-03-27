<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { api } from '$lib/api';
	import type { OwnershipGroup, DeploymentGroup } from '$lib/api';
	import OwnershipTreemap from './OwnershipTreemap.svelte';
	import DeploymentChart from './DeploymentChart.svelte';

	let ownershipGroups: OwnershipGroup[] = $state([]);
	let deploymentGroups: DeploymentGroup[] = $state([]);
	let totalCerts = $state(0);
	let totalIssuers = $state(0);
	let totalOUs = $state(0);
	let totalObserved = $state(0);
	let totalDomains = $state(0);
	let loading = $state(true);
	let error: string | null = $state(null);

	onMount(async () => {
		try {
			const [ownership, deployment] = await Promise.all([
				api.getOwnership(),
				api.getDeployment(),
			]);
			ownershipGroups = ownership.groups;
			totalCerts = ownership.total_certs;
			totalIssuers = ownership.total_issuers;
			totalOUs = ownership.total_ous;
			deploymentGroups = deployment.groups;
			totalObserved = deployment.total_observed_certs;
			totalDomains = deployment.total_domains;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load ownership data';
		}
		loading = false;
	});

	function handleTreemapClick(issuerOrg: string, subjectOU: string) {
		const params = new URLSearchParams();
		params.set('issuer_cn', issuerOrg);
		if (subjectOU) params.set('subject_ou', subjectOU);
		goto(`/certificates?${params.toString()}`);
	}
</script>

<div class="ownership-tab">
	{#if loading}
		<div class="tab-loading">Loading ownership data...</div>
	{:else if error}
		<div class="tab-error">{error}</div>
	{:else}
		<section class="ownership-section">
			<div class="section-header">
				<h2>By Certificate Metadata</h2>
				<span class="section-meta">{totalIssuers} issuers · {totalOUs} OUs · {totalCerts.toLocaleString()} certs</span>
			</div>
			<OwnershipTreemap groups={ownershipGroups} onGroupClick={handleTreemapClick} />
		</section>

		<section class="ownership-section">
			<div class="section-header">
				<h2>By Deployment</h2>
				<span class="section-meta">{totalDomains} domains · {totalObserved.toLocaleString()} observed certs</span>
			</div>
			<DeploymentChart groups={deploymentGroups} />
		</section>
	{/if}
</div>

<style>
	.ownership-tab { padding: 1.5rem; height: 100%; overflow-y: auto; }
	.ownership-section { margin-bottom: 2rem; }
	.section-header { display: flex; align-items: baseline; gap: 1rem; margin-bottom: 1rem; }
	.section-header h2 { margin: 0; font-size: 1.1rem; font-weight: 700; color: var(--cf-text-primary); }
	.section-meta { font-size: 0.8rem; color: var(--cf-text-muted); }
	.tab-loading, .tab-error { display: flex; align-items: center; justify-content: center; height: 50vh; color: var(--cf-text-muted); font-size: 0.9rem; }
	.tab-error { color: var(--cf-risk-critical); }
</style>
