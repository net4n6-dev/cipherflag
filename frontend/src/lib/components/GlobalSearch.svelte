<script lang="ts">
	import { goto } from '$app/navigation';
	import { api } from '$lib/api';
	import type { GlobalSearchResult, GlobalSearchCert, GlobalSearchObs } from '$lib/api';

	let query = $state('');
	let results: GlobalSearchResult | null = $state(null);
	let loading = $state(false);
	let open = $state(false);
	let debounceTimer: ReturnType<typeof setTimeout>;
	let inputEl: HTMLInputElement;

	const GRADE_COLORS: Record<string, string> = {
		'A+': '#22c55e', 'A': '#22c55e', 'B': '#84cc16',
		'C': '#eab308', 'D': '#f97316', 'F': '#ef4444', '?': '#64748b',
	};

	const MATCH_LABELS: Record<string, string> = {
		'text_search': 'Name/Org',
		'fingerprint': 'Fingerprint',
		'san': 'SAN',
	};

	function handleInput() {
		clearTimeout(debounceTimer);

		if (query.length < 2) {
			results = null;
			open = false;
			return;
		}

		loading = true;
		open = true;
		debounceTimer = setTimeout(async () => {
			try {
				results = await api.globalSearch(query, 15);
			} catch {
				results = null;
			}
			loading = false;
		}, 300);
	}

	function selectCert(fp: string) {
		open = false;
		query = '';
		results = null;
		goto(`/certificates/${fp}`);
	}

	function selectObs(fp: string) {
		open = false;
		query = '';
		results = null;
		goto(`/certificates/${fp}`);
	}

	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'Escape') {
			open = false;
			inputEl?.blur();
		}
	}

	function handleBlur() {
		// Delay to allow click on result
		setTimeout(() => { open = false; }, 200);
	}

	function clearSearch() {
		query = '';
		results = null;
		open = false;
	}

	function daysUntil(d: string): number {
		return Math.floor((new Date(d).getTime() - Date.now()) / 86400000);
	}
</script>

<div class="global-search" onkeydown={handleKeydown}>
	<div class="search-input-wrapper">
		<svg class="search-icon" viewBox="0 0 20 20" fill="currentColor">
			<path fill-rule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clip-rule="evenodd" />
		</svg>
		<input
			bind:this={inputEl}
			type="text"
			placeholder="Search certs, SANs, IPs, fingerprints..."
			bind:value={query}
			oninput={handleInput}
			onfocus={() => { if (query.length >= 2) open = true; }}
			onblur={handleBlur}
		/>
		{#if query}
			<button class="search-clear" onclick={clearSearch}>&times;</button>
		{/if}
		{#if loading}
			<span class="search-spinner"></span>
		{/if}
	</div>

	{#if open && (results || loading)}
		<div class="search-dropdown">
			{#if loading && !results}
				<div class="dropdown-loading">Searching...</div>
			{:else if results && results.total === 0}
				<div class="dropdown-empty">No results for "{query}"</div>
			{:else if results}
				{#if results.certificates.length > 0}
					<div class="dropdown-section">
						<div class="dropdown-label">Certificates ({results.certificates.length})</div>
						{#each results.certificates as cert}
							<button class="dropdown-item" onclick={() => selectCert(cert.fingerprint)}>
								<span class="item-grade" style="color: {GRADE_COLORS[cert.grade] ?? '#64748b'}">{cert.grade}</span>
								<div class="item-info">
									<span class="item-cn">{cert.subject_cn || cert.fingerprint.slice(0, 16)}</span>
									<span class="item-meta">
										{cert.issuer_cn}
										<span class="item-sep">·</span>
										{cert.key_algorithm}
										<span class="item-sep">·</span>
										<span class:item-expired={daysUntil(cert.not_after) < 0} class:item-expiring={daysUntil(cert.not_after) >= 0 && daysUntil(cert.not_after) < 30}>
											{daysUntil(cert.not_after) < 0 ? 'Expired' : daysUntil(cert.not_after) + 'd'}
										</span>
									</span>
								</div>
								<span class="item-match">{MATCH_LABELS[cert.match_field] ?? cert.match_field}</span>
							</button>
						{/each}
					</div>
				{/if}

				{#if results.observations.length > 0}
					<div class="dropdown-section">
						<div class="dropdown-label">Endpoints ({results.observations.length})</div>
						{#each results.observations as obs}
							<button class="dropdown-item" onclick={() => selectObs(obs.cert_fingerprint)}>
								<span class="item-grade" style="color: #38bdf8">&#8226;</span>
								<div class="item-info">
									<span class="item-cn">{obs.server_name || obs.server_ip}</span>
									<span class="item-meta">
										{obs.server_ip}:{obs.server_port}
										<span class="item-sep">·</span>
										{obs.tls_version}
										<span class="item-sep">·</span>
										{obs.subject_cn}
									</span>
								</div>
								<span class="item-match">Endpoint</span>
							</button>
						{/each}
					</div>
				{/if}
			{/if}
		</div>
	{/if}
</div>

<style>
	.global-search {
		position: relative;
		flex: 1;
		max-width: 400px;
		margin-left: auto;
	}

	.search-input-wrapper {
		display: flex;
		align-items: center;
		gap: 0.375rem;
		background: var(--cf-bg-tertiary);
		border: 1px solid var(--cf-border);
		border-radius: 6px;
		padding: 0.25rem 0.625rem;
		transition: border-color 0.15s;
	}

	.search-input-wrapper:focus-within {
		border-color: var(--cf-accent);
	}

	.search-icon {
		width: 14px;
		height: 14px;
		color: var(--cf-text-muted);
		flex-shrink: 0;
	}

	input {
		background: none;
		border: none;
		outline: none;
		color: var(--cf-text-primary);
		font-size: 0.8rem;
		width: 100%;
	}

	input::placeholder {
		color: var(--cf-text-muted);
	}

	.search-clear {
		background: none;
		border: none;
		color: var(--cf-text-muted);
		cursor: pointer;
		font-size: 1rem;
		padding: 0;
		line-height: 1;
	}

	.search-spinner {
		width: 12px;
		height: 12px;
		border: 2px solid var(--cf-border);
		border-top-color: var(--cf-accent);
		border-radius: 50%;
		animation: spin 0.6s linear infinite;
		flex-shrink: 0;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	.search-dropdown {
		position: absolute;
		top: calc(100% + 4px);
		left: 0;
		right: 0;
		background: rgba(15, 23, 42, 0.98);
		border: 1px solid var(--cf-border);
		border-radius: 8px;
		max-height: 420px;
		overflow-y: auto;
		z-index: 100;
		box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5);
	}

	.dropdown-section + .dropdown-section {
		border-top: 1px solid var(--cf-border);
	}

	.dropdown-label {
		padding: 0.5rem 0.75rem 0.25rem;
		font-size: 0.6rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--cf-text-muted);
	}

	.dropdown-item {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		width: 100%;
		padding: 0.4rem 0.75rem;
		background: none;
		border: none;
		color: inherit;
		text-align: left;
		cursor: pointer;
		transition: background 0.1s;
	}

	.dropdown-item:hover {
		background: rgba(56, 189, 248, 0.08);
	}

	.item-grade {
		font-weight: 700;
		font-size: 0.85rem;
		width: 20px;
		text-align: center;
		flex-shrink: 0;
	}

	.item-info {
		flex: 1;
		min-width: 0;
		display: flex;
		flex-direction: column;
		gap: 0.05rem;
	}

	.item-cn {
		font-size: 0.8rem;
		font-weight: 500;
		color: var(--cf-text-primary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.item-meta {
		font-size: 0.7rem;
		color: var(--cf-text-muted);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.item-sep { opacity: 0.4; margin: 0 0.15rem; }
	.item-expired { color: #ef4444; }
	.item-expiring { color: #eab308; }

	.item-match {
		font-size: 0.55rem;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		padding: 0.1rem 0.35rem;
		background: rgba(56, 189, 248, 0.08);
		border: 1px solid rgba(56, 189, 248, 0.15);
		border-radius: 3px;
		color: var(--cf-text-muted);
		flex-shrink: 0;
		white-space: nowrap;
	}

	.dropdown-loading, .dropdown-empty {
		padding: 1rem;
		text-align: center;
		color: var(--cf-text-muted);
		font-size: 0.8rem;
	}
</style>
