<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { api, type SummaryStats, type IssuerStat, type PKITreeResponse, type ComplianceReportPriority } from '$lib/api';
	import RadialTree from '$lib/components/dashboard/RadialTree.svelte';

	let stats: SummaryStats | null = $state(null);
	let issuers: IssuerStat[] = $state([]);
	let pki: PKITreeResponse | null = $state(null);
	let complianceScore = $state(0);
	let complianceByCategory = $state<Record<string, number>>({});
	let priorities: ComplianceReportPriority[] = $state([]);
	let cryptoAlgos = $state<{algorithm: string; count: number}[]>([]);
	let sigAlgos = $state<{algorithm: string; count: number}[]>([]);
	let loading = $state(true);
	let error: string | null = $state(null);

	const GRADE_COLORS: Record<string, string> = {
		'A+': '#22c55e', 'A': '#22c55e', 'B': '#84cc16',
		'C': '#eab308', 'D': '#f97316', 'F': '#ef4444', '?': '#64748b',
	};
	const GRADE_ORDER = ['A+', 'A', 'B', 'C', 'D', 'F'];
	const CATEGORY_LABELS: Record<string, string> = {
		key_strength: 'Key Strength', signature: 'Signature', expiration: 'Expiration',
		chain: 'Chain Trust', revocation: 'Revocation', transparency: 'CT/SCT',
		wildcard: 'Wildcards', agility: 'Crypto Agility',
	};
	const CATEGORY_ORDER = ['key_strength', 'signature', 'expiration', 'chain', 'revocation', 'transparency', 'wildcard', 'agility'];

	function gradeColor(g: string): string { return GRADE_COLORS[g] ?? '#64748b'; }

	function riskLevel(score: number): {label: string; color: string} {
		if (score >= 85) return { label: 'LOW', color: '#22c55e' };
		if (score >= 70) return { label: 'MODERATE', color: '#84cc16' };
		if (score >= 50) return { label: 'ELEVATED', color: '#eab308' };
		return { label: 'HIGH', color: '#ef4444' };
	}

	function gaugeArc(pct: number, r: number, cx: number, cy: number): string {
		const startAngle = -Math.PI * 0.75;
		const endAngle = startAngle + (pct / 100) * Math.PI * 1.5;
		const x1 = cx + r * Math.cos(startAngle);
		const y1 = cy + r * Math.sin(startAngle);
		const x2 = cx + r * Math.cos(endAngle);
		const y2 = cy + r * Math.sin(endAngle);
		const large = (endAngle - startAngle) > Math.PI ? 1 : 0;
		return `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`;
	}

	function donutArc(startAngle: number, endAngle: number, r: number, cx: number, cy: number): string {
		const x1 = cx + r * Math.cos(startAngle - Math.PI / 2);
		const y1 = cy + r * Math.sin(startAngle - Math.PI / 2);
		const x2 = cx + r * Math.cos(endAngle - Math.PI / 2);
		const y2 = cy + r * Math.sin(endAngle - Math.PI / 2);
		const large = endAngle - startAngle > Math.PI ? 1 : 0;
		return `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`;
	}

	const ALGO_COLORS: Record<string, string> = {
		'RSA': '#38bdf8', 'ECDSA': '#a78bfa', 'Ed25519': '#34d399', 'Unknown': '#64748b',
	};

	onMount(async () => {
		try {
			const [s, iss, pkiData, compliance, crypto] = await Promise.all([
				api.getSummary(),
				api.getIssuers(),
				api.getPKITree(),
				api.getComplianceReport(),
				api.getCryptoPosture(),
			]);
			stats = s;
			issuers = (iss as any).issuers ?? [];
			pki = pkiData;
			complianceScore = compliance.compliance_score;
			complianceByCategory = compliance.by_category ?? {};
			priorities = compliance.remediation_priorities ?? [];
			cryptoAlgos = crypto.key_algorithms ?? [];
			sigAlgos = crypto.signature_algorithms ?? [];
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load dashboard';
		}
		loading = false;
	});

	let risk = $derived(riskLevel(complianceScore));
</script>

<div class="dashboard">
	{#if loading}
		<div class="loading">Loading command center...</div>
	{:else if error}
		<div class="error">{error}</div>
	{:else if stats}
		<!-- Header -->
		<div class="dash-header">
			<div class="header-left">
				<h1>Certificate Landscape</h1>
				<span class="header-meta">{stats.total_certs.toLocaleString()} certificates · {stats.total_observations.toLocaleString()} observations</span>
			</div>
			<div class="header-right">
				<div class="risk-indicator">
					<span class="risk-label">RISK LEVEL</span>
					<span class="risk-value" style="color: {risk.color}">{risk.label}</span>
				</div>
			</div>
		</div>

		<!-- Risk Signal Cards -->
		<div class="risk-row">
			<a href="/certificates?expired=true" class="risk-card">
				<div class="risk-num critical">{stats.expired}</div>
				<div class="risk-lbl">Expired</div>
			</a>
			<a href="/reports?type=expiry&days=30" class="risk-card">
				<div class="risk-num high">{stats.expiring_in_30_days}</div>
				<div class="risk-lbl">Expiring &lt;30d</div>
			</a>
			<a href="/reports?type=expiry&days=90" class="risk-card">
				<div class="risk-num medium">{stats.expiring_in_90_days}</div>
				<div class="risk-lbl">Expiring &lt;90d</div>
			</a>
			<a href="/certificates?grade=F" class="risk-card">
				<div class="risk-num critical">{stats.critical_findings}</div>
				<div class="risk-lbl">Grade F</div>
			</a>
			<a href="/reports?type=compliance" class="risk-card">
				<div class="risk-num info">{stats.total_findings}</div>
				<div class="risk-lbl">With Findings</div>
			</a>
		</div>

		<!-- Main Grid: 3 columns -->
		<div class="main-grid">
			<!-- Compliance Scorecard -->
			<div class="panel">
				<h2>Compliance Scorecard</h2>
				<div class="gauge-wrap">
					<svg viewBox="0 0 140 100" class="gauge-svg">
						<path d={gaugeArc(100, 48, 70, 68)} fill="none" stroke="rgba(100,116,139,0.15)" stroke-width="10" stroke-linecap="round" />
						<path d={gaugeArc(complianceScore, 48, 70, 68)} fill="none" stroke={risk.color} stroke-width="10" stroke-linecap="round" />
						<text x="70" y="64" text-anchor="middle" fill="#e2e8f0" font-size="20" font-weight="700">{complianceScore.toFixed(0)}%</text>
						<text x="70" y="78" text-anchor="middle" fill="#64748b" font-size="7">compliant</text>
					</svg>
				</div>
				<div class="category-bars">
					{#each CATEGORY_ORDER as cat}
						{@const count = complianceByCategory[cat] ?? 0}
						{#if count > 0}
							{@const maxCat = Math.max(...Object.values(complianceByCategory), 1)}
							<div class="cat-row">
								<span class="cat-label">{CATEGORY_LABELS[cat] ?? cat}</span>
								<div class="cat-track">
									<div class="cat-fill" style="width: {(count / maxCat) * 100}%; background: {count > maxCat * 0.5 ? '#ef4444' : count > maxCat * 0.2 ? '#eab308' : '#38bdf8'}"></div>
								</div>
								<span class="cat-count">{count}</span>
							</div>
						{/if}
					{/each}
				</div>
				<button class="panel-link" onclick={() => goto('/reports?type=compliance')}>Full Report →</button>
			</div>

			<!-- Grade Distribution -->
			<div class="panel">
				<h2>Grade Distribution</h2>
				<div class="donut-row">
					<svg viewBox="0 0 120 120" class="donut-svg">
						{#each GRADE_ORDER as grade, i}
							{@const count = stats.grade_distribution[grade] ?? 0}
							{@const total = Object.values(stats.grade_distribution).reduce((a, b) => a + b, 0) || 1}
							{@const startAngle = GRADE_ORDER.slice(0, i).reduce((s, g) => s + ((stats!.grade_distribution[g] ?? 0) / total) * Math.PI * 2, 0)}
							{@const endAngle = startAngle + (count / total) * Math.PI * 2}
							{#if count > 0}
								<path
									d={donutArc(startAngle, Math.min(endAngle, startAngle + Math.PI * 2 - 0.01), 45, 60, 60)}
									fill="none"
									stroke={gradeColor(grade)}
									stroke-width="14"
									stroke-linecap="round"
								/>
							{/if}
						{/each}
						<text x="60" y="56" text-anchor="middle" fill="#e2e8f0" font-size="14" font-weight="700">{stats.total_certs}</text>
						<text x="60" y="70" text-anchor="middle" fill="#64748b" font-size="8">total</text>
					</svg>
					<div class="grade-legend">
						{#each GRADE_ORDER as grade}
							{@const count = stats.grade_distribution[grade] ?? 0}
							{@const total = Object.values(stats.grade_distribution).reduce((a, b) => a + b, 0) || 1}
							{#if count > 0}
								<a href="/certificates?grade={grade}" class="gl-row">
									<span class="gl-dot" style="background: {gradeColor(grade)}"></span>
									<span class="gl-grade">{grade}</span>
									<span class="gl-count">{count}</span>
									<span class="gl-pct">{(count / total * 100).toFixed(0)}%</span>
								</a>
							{/if}
						{/each}
					</div>
				</div>
			</div>

			<!-- Algorithm Landscape -->
			<div class="panel">
				<h2>Algorithm Landscape</h2>
				<div class="algo-section">
					<span class="algo-heading">Key Algorithms</span>
					{#each cryptoAlgos as algo}
						{@const maxAlgo = Math.max(...cryptoAlgos.map(a => a.count), 1)}
						<div class="algo-row">
							<span class="algo-name">{algo.algorithm}</span>
							<div class="algo-track">
								<div class="algo-fill" style="width: {(algo.count / maxAlgo) * 100}%; background: {ALGO_COLORS[algo.algorithm] ?? '#64748b'}"></div>
							</div>
							<span class="algo-count">{algo.count}</span>
						</div>
					{/each}
				</div>
				<div class="algo-section" style="margin-top: 0.75rem;">
					<span class="algo-heading">Signature Algorithms</span>
					{#each sigAlgos.slice(0, 5) as sa}
						{@const maxSig = Math.max(...sigAlgos.map(s => s.count), 1)}
						{@const isWeak = sa.algorithm.includes('SHA1') || sa.algorithm.includes('MD5')}
						<div class="algo-row">
							<span class="algo-name" class:weak={isWeak}>{sa.algorithm}</span>
							<div class="algo-track">
								<div class="algo-fill" style="width: {(sa.count / maxSig) * 100}%; background: {isWeak ? '#ef4444' : '#38bdf8'}"></div>
							</div>
							<span class="algo-count">{sa.count}</span>
						</div>
					{/each}
				</div>
				<button class="panel-link" onclick={() => goto('/analytics?tab=crypto-posture')}>Crypto Posture →</button>
			</div>
		</div>

		<!-- Priority Actions + Sources row -->
		<div class="secondary-grid">
			<div class="panel">
				<h2>Priority Actions</h2>
				<div class="priority-list">
					{#each priorities.slice(0, 5) as p, i}
						{@const sevColor = p.severity === 'Critical' ? '#ef4444' : p.severity === 'High' ? '#f97316' : p.severity === 'Medium' ? '#eab308' : '#64748b'}
						<div class="priority-item">
							<span class="pi-num">{i + 1}</span>
							<div class="pi-info">
								<span class="pi-title">{p.title}</span>
								<span class="pi-meta">
									<span style="color: {sevColor}">{p.severity}</span> · {p.affected_count} certs
								</span>
							</div>
						</div>
					{/each}
				</div>
				<button class="panel-link" onclick={() => goto('/reports?type=compliance')}>View All →</button>
			</div>

			<div class="panel">
				<h2>Discovery Sources</h2>
				<div class="source-list">
					{#each Object.entries(stats.source_stats).sort((a, b) => b[1] - a[1]) as [source, count]}
						<div class="source-row">
							<span class="source-name">{source}</span>
							<span class="source-count">{count}</span>
						</div>
					{/each}
				</div>
				<button class="panel-link" onclick={() => goto('/analytics?tab=source-lineage')}>Source Lineage →</button>
			</div>

			<div class="panel">
				<h2>Top Issuers</h2>
				<div class="issuer-list">
					{#each issuers.slice(0, 6) as issuer}
						<button class="issuer-row" onclick={() => goto(`/reports?type=ca&issuer_cn=${encodeURIComponent(issuer.issuer_cn)}`)}>
							<span class="is-name">{issuer.issuer_cn.length > 24 ? issuer.issuer_cn.slice(0, 22) + '...' : issuer.issuer_cn}</span>
							<span class="is-count">{issuer.cert_count}</span>
							<span class="is-grade" style="color: {gradeColor(issuer.min_grade)}">{issuer.min_grade}</span>
						</button>
					{/each}
				</div>
				<button class="panel-link" onclick={() => goto('/analytics?tab=chain-flow')}>Chain Flow →</button>
			</div>
		</div>

		<!-- Radial PKI Tree -->
		{#if pki}
			<div class="panel panel-tree">
				<h2>PKI Hierarchy · {pki.total_cas} CAs · {pki.total_leaves.toLocaleString()} Certificates</h2>
				<RadialTree roots={pki.roots} totalLeaves={pki.total_leaves} />
			</div>
		{/if}
	{/if}
</div>

<style>
	.dashboard { padding: 1.25rem; max-width: 1400px; margin: 0 auto; overflow-y: auto; height: 100%; }

	.dash-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1rem; }
	.header-left h1 { margin: 0; font-size: 1.3rem; font-weight: 700; color: var(--cf-text-primary); }
	.header-meta { font-size: 0.75rem; color: var(--cf-text-muted); }
	.risk-indicator { text-align: right; }
	.risk-label { display: block; font-size: 0.55rem; color: var(--cf-text-muted); text-transform: uppercase; letter-spacing: 0.08em; }
	.risk-value { font-size: 1rem; font-weight: 800; letter-spacing: 0.05em; }

	/* Risk cards */
	.risk-row { display: grid; grid-template-columns: repeat(5, 1fr); gap: 0.625rem; margin-bottom: 1rem; }
	.risk-card { background: var(--cf-bg-secondary); border: 1px solid var(--cf-border); border-radius: 8px; padding: 0.625rem; text-align: center; text-decoration: none; transition: border-color 0.15s; }
	.risk-card:hover { border-color: var(--cf-border-hover); }
	.risk-num { font-size: 1.5rem; font-weight: 700; font-variant-numeric: tabular-nums; }
	.risk-num.critical { color: var(--cf-risk-critical); }
	.risk-num.high { color: var(--cf-risk-high); }
	.risk-num.medium { color: var(--cf-risk-medium); }
	.risk-num.info { color: var(--cf-accent); }
	.risk-lbl { font-size: 0.65rem; color: var(--cf-text-muted); margin-top: 0.125rem; }

	/* Main grid */
	.main-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 0.75rem; margin-bottom: 0.75rem; }
	.secondary-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 0.75rem; margin-bottom: 0.75rem; }

	.panel { background: var(--cf-bg-secondary); border: 1px solid var(--cf-border); border-radius: 8px; padding: 1rem; }
	.panel-tree { margin-bottom: 1rem; }

	h2 { margin: 0 0 0.75rem; font-size: 0.7rem; font-weight: 600; color: var(--cf-text-muted); text-transform: uppercase; letter-spacing: 0.04em; }

	.panel-link { display: block; width: 100%; margin-top: 0.75rem; padding: 0.375rem; font-size: 0.7rem; background: rgba(56, 189, 248, 0.05); border: 1px solid rgba(56, 189, 248, 0.12); border-radius: 4px; color: var(--cf-accent); cursor: pointer; text-align: center; transition: all 0.15s; }
	.panel-link:hover { background: rgba(56, 189, 248, 0.1); }

	/* Gauge */
	.gauge-wrap { display: flex; justify-content: center; margin-bottom: 0.5rem; }
	.gauge-svg { width: 140px; height: 100px; }

	/* Category bars */
	.category-bars { display: flex; flex-direction: column; gap: 0.3rem; }
	.cat-row { display: flex; align-items: center; gap: 0.5rem; }
	.cat-label { width: 85px; font-size: 0.65rem; color: var(--cf-text-secondary); flex-shrink: 0; }
	.cat-track { flex: 1; height: 8px; background: var(--cf-bg-tertiary); border-radius: 4px; overflow: hidden; }
	.cat-fill { height: 100%; border-radius: 4px; opacity: 0.7; }
	.cat-count { width: 28px; text-align: right; font-size: 0.7rem; color: var(--cf-text-muted); font-variant-numeric: tabular-nums; }

	/* Grade donut */
	.donut-row { display: flex; align-items: center; gap: 1rem; }
	.donut-svg { width: 110px; height: 110px; flex-shrink: 0; }
	.grade-legend { display: flex; flex-direction: column; gap: 0.25rem; flex: 1; }
	.gl-row { display: flex; align-items: center; gap: 0.375rem; text-decoration: none; padding: 0.15rem 0.25rem; border-radius: 3px; transition: background 0.15s; }
	.gl-row:hover { background: var(--cf-bg-tertiary); }
	.gl-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
	.gl-grade { font-weight: 600; font-size: 0.8rem; color: var(--cf-text-primary); width: 18px; }
	.gl-count { font-size: 0.8rem; color: var(--cf-text-secondary); font-variant-numeric: tabular-nums; flex: 1; }
	.gl-pct { font-size: 0.7rem; color: var(--cf-text-muted); font-variant-numeric: tabular-nums; }

	/* Algorithm landscape */
	.algo-section { }
	.algo-heading { font-size: 0.6rem; color: var(--cf-text-muted); text-transform: uppercase; letter-spacing: 0.04em; display: block; margin-bottom: 0.25rem; }
	.algo-row { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.2rem; }
	.algo-name { width: 90px; font-family: 'JetBrains Mono', monospace; font-size: 0.65rem; color: var(--cf-text-primary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex-shrink: 0; }
	.algo-name.weak { color: #ef4444; }
	.algo-track { flex: 1; height: 8px; background: var(--cf-bg-tertiary); border-radius: 4px; overflow: hidden; }
	.algo-fill { height: 100%; border-radius: 4px; opacity: 0.7; }
	.algo-count { width: 30px; text-align: right; font-size: 0.7rem; color: var(--cf-text-muted); font-variant-numeric: tabular-nums; }

	/* Priority actions */
	.priority-list { display: flex; flex-direction: column; gap: 0.375rem; }
	.priority-item { display: flex; align-items: flex-start; gap: 0.5rem; }
	.pi-num { width: 18px; height: 18px; background: rgba(56, 189, 248, 0.1); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 0.6rem; font-weight: 700; color: var(--cf-accent); flex-shrink: 0; }
	.pi-info { flex: 1; }
	.pi-title { display: block; font-size: 0.75rem; color: var(--cf-text-primary); }
	.pi-meta { font-size: 0.65rem; color: var(--cf-text-muted); }

	/* Sources */
	.source-list { display: flex; flex-direction: column; gap: 0.25rem; }
	.source-row { display: flex; justify-content: space-between; padding: 0.3rem 0.5rem; background: var(--cf-bg-tertiary); border-radius: 4px; }
	.source-name { font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; color: var(--cf-text-primary); }
	.source-count { font-weight: 600; color: var(--cf-accent); font-variant-numeric: tabular-nums; font-size: 0.75rem; }

	/* Issuers */
	.issuer-list { display: flex; flex-direction: column; gap: 0.25rem; }
	.issuer-row { display: flex; align-items: center; gap: 0.5rem; padding: 0.3rem 0.5rem; background: none; border: none; color: inherit; text-align: left; width: 100%; cursor: pointer; border-radius: 4px; transition: background 0.1s; }
	.issuer-row:hover { background: rgba(56, 189, 248, 0.06); }
	.is-name { flex: 1; font-size: 0.7rem; color: var(--cf-text-primary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.is-count { font-size: 0.7rem; color: var(--cf-text-muted); font-variant-numeric: tabular-nums; }
	.is-grade { font-size: 0.7rem; font-weight: 700; }

	.loading, .error { display: flex; align-items: center; justify-content: center; height: 50vh; color: var(--cf-text-muted); }
	.error { color: var(--cf-risk-critical); }
</style>
