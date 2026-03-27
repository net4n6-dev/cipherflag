<script lang="ts">
	import type { GraphMode } from './graph-types';
	import type { ForceNode } from './graph-types';
	import type { Certificate } from '$lib/api';
	import { api } from '$lib/api';

	interface SearchResult {
		type: 'graph' | 'server';
		id: string;
		label: string;
		org: string;
		nodeType: string;
		grade?: string;
	}

	interface Props {
		searchQuery: string;
		mode: GraphMode;
		selectedGrades: Set<string>;
		showExpiredOnly: boolean;
		nodeCount: number;
		edgeCount: number;
		expandedCount: number;
		nodes: ForceNode[];
		onSearchChange: (q: string) => void;
		onSearchResultClick: (result: SearchResult) => void;
		onGradeToggle: (grade: string) => void;
		onExpiredToggle: () => void;
		onBlastRadiusToggle: () => void;
		onZoomIn: () => void;
		onZoomOut: () => void;
		onZoomReset: () => void;
	}

	let {
		searchQuery,
		mode,
		selectedGrades,
		showExpiredOnly,
		nodeCount,
		edgeCount,
		expandedCount,
		nodes,
		onSearchChange,
		onSearchResultClick,
		onGradeToggle,
		onExpiredToggle,
		onBlastRadiusToggle,
		onZoomIn,
		onZoomOut,
		onZoomReset,
	}: Props = $props();

	const GRADES = ['A+', 'A', 'B', 'C', 'D', 'F'];

	let dropdownOpen = $state(false);
	let graphResults: SearchResult[] = $state([]);
	let serverResults: SearchResult[] = $state([]);
	let serverLoading = $state(false);
	let debounceTimer: ReturnType<typeof setTimeout>;

	function handleInput(q: string) {
		onSearchChange(q);

		if (!q || q.length < 2) {
			dropdownOpen = false;
			graphResults = [];
			serverResults = [];
			return;
		}

		// Client-side: search loaded graph nodes
		const lower = q.toLowerCase();
		graphResults = nodes
			.filter(n =>
				n.label.toLowerCase().includes(lower) ||
				n.organization.toLowerCase().includes(lower) ||
				n.id.toLowerCase().startsWith(lower)
			)
			.slice(0, 8)
			.map(n => ({
				type: 'graph' as const,
				id: n.id,
				label: n.label,
				org: n.organization,
				nodeType: n.type,
				grade: n.grade,
			}));

		dropdownOpen = true;

		// Server-side: debounced, only if few client matches
		clearTimeout(debounceTimer);
		if (graphResults.length < 5) {
			serverLoading = true;
			debounceTimer = setTimeout(async () => {
				try {
					const params = new URLSearchParams({ search: q, page_size: '10' });
					const resp = await api.searchCerts(params.toString());
					const graphIds = new Set(graphResults.map(r => r.id));
					serverResults = (resp.certificates ?? [])
						.filter((c: Certificate) => !graphIds.has(c.fingerprint_sha256))
						.slice(0, 8)
						.map((c: Certificate) => ({
							type: 'server' as const,
							id: c.fingerprint_sha256,
							label: c.subject.common_name || c.fingerprint_sha256.slice(0, 16),
							org: c.subject.organization,
							nodeType: c.is_ca ? 'ca' : 'leaf',
						}));
				} catch {
					serverResults = [];
				}
				serverLoading = false;
			}, 300);
		} else {
			serverResults = [];
			serverLoading = false;
		}
	}

	function selectResult(result: SearchResult) {
		dropdownOpen = false;
		onSearchResultClick(result);
	}

	function clearSearch() {
		onSearchChange('');
		dropdownOpen = false;
		graphResults = [];
		serverResults = [];
	}
</script>

<div class="graph-toolbar">
	<div class="toolbar-left">
		<div class="search-wrapper">
			<div class="search-box">
				<span class="search-icon">&#128269;</span>
				<input
					type="text"
					placeholder="Search CAs or certificates..."
					value={searchQuery}
					oninput={(e) => handleInput(e.currentTarget.value)}
					onfocus={() => { if (searchQuery.length >= 2) dropdownOpen = true; }}
				/>
				{#if searchQuery}
					<button class="search-clear" onclick={clearSearch}>&times;</button>
				{/if}
			</div>

			{#if dropdownOpen && (graphResults.length > 0 || serverResults.length > 0 || serverLoading)}
				<div class="search-dropdown">
					{#if graphResults.length > 0}
						<div class="dropdown-section">
							<div class="dropdown-label">In Graph</div>
							{#each graphResults as result}
								<button class="dropdown-item" onclick={() => selectResult(result)}>
									<span class="item-type-dot" class:root={result.nodeType === 'root'} class:intermediate={result.nodeType === 'intermediate'} class:leaf={result.nodeType === 'leaf'}></span>
									<span class="item-label">{result.label}</span>
									{#if result.org}
										<span class="item-org">{result.org}</span>
									{/if}
									{#if result.grade}
										<span class="item-grade">{result.grade}</span>
									{/if}
								</button>
							{/each}
						</div>
					{/if}

					{#if serverResults.length > 0}
						<div class="dropdown-section">
							<div class="dropdown-label">All Certificates</div>
							{#each serverResults as result}
								<button class="dropdown-item" onclick={() => selectResult(result)}>
									<span class="item-badge">not loaded</span>
									<span class="item-label">{result.label}</span>
									{#if result.org}
										<span class="item-org">{result.org}</span>
									{/if}
								</button>
							{/each}
						</div>
					{/if}

					{#if serverLoading}
						<div class="dropdown-loading">Searching certificates...</div>
					{/if}
				</div>
			{/if}
		</div>
	</div>

	<div class="toolbar-center">
		<div class="filter-pills">
			{#each GRADES as grade}
				<button
					class="pill"
					class:active={selectedGrades.has(grade)}
					onclick={() => onGradeToggle(grade)}
				>
					{grade}
				</button>
			{/each}
		</div>
		<button
			class="pill pill-expired"
			class:active={showExpiredOnly}
			onclick={onExpiredToggle}
		>
			Expired
		</button>
		<button
			class="pill pill-blast"
			class:active={mode === 'blast-radius'}
			onclick={onBlastRadiusToggle}
		>
			Blast Radius
		</button>
	</div>

	<div class="toolbar-right">
		<button class="zoom-btn" onclick={onZoomIn} title="Zoom in">+</button>
		<button class="zoom-btn" onclick={onZoomOut} title="Zoom out">&minus;</button>
		<button class="zoom-btn" onclick={onZoomReset} title="Reset view">&#8634;</button>
	</div>
</div>

<style>
	.graph-toolbar {
		position: absolute;
		top: 0;
		left: 0;
		right: 0;
		height: 44px;
		background: rgba(15, 23, 42, 0.95);
		border-bottom: 1px solid rgba(56, 189, 248, 0.15);
		display: flex;
		align-items: center;
		padding: 0 1rem;
		gap: 0.75rem;
		z-index: 10;
	}

	.toolbar-left { flex: 1; }

	.search-wrapper {
		position: relative;
		max-width: 320px;
	}

	.search-box {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		background: rgba(56, 189, 248, 0.08);
		border: 1px solid rgba(56, 189, 248, 0.2);
		border-radius: 6px;
		padding: 0.25rem 0.75rem;
	}

	.search-icon { font-size: 0.75rem; color: #64748b; }

	.search-box input {
		background: none;
		border: none;
		outline: none;
		color: #e2e8f0;
		font-size: 0.8rem;
		width: 100%;
	}

	.search-box input::placeholder { color: #64748b; }

	/* Dropdown */
	.search-dropdown {
		position: absolute;
		top: 100%;
		left: 0;
		right: 0;
		margin-top: 4px;
		background: rgba(15, 23, 42, 0.98);
		border: 1px solid rgba(56, 189, 248, 0.2);
		border-radius: 8px;
		max-height: 360px;
		overflow-y: auto;
		z-index: 30;
		box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5);
	}

	.dropdown-section {
		padding: 0.25rem 0;
	}

	.dropdown-section + .dropdown-section {
		border-top: 1px solid rgba(56, 189, 248, 0.1);
	}

	.dropdown-label {
		padding: 0.375rem 0.75rem 0.25rem;
		font-size: 0.6rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: #64748b;
	}

	.dropdown-item {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		width: 100%;
		padding: 0.4rem 0.75rem;
		background: none;
		border: none;
		color: #e2e8f0;
		font-size: 0.8rem;
		text-align: left;
		cursor: pointer;
		transition: background 0.1s;
	}

	.dropdown-item:hover {
		background: rgba(56, 189, 248, 0.1);
	}

	.item-type-dot {
		width: 6px;
		height: 6px;
		border-radius: 50%;
		flex-shrink: 0;
		background: #64748b;
	}

	.item-type-dot.root { background: #22c55e; }
	.item-type-dot.intermediate { background: #84cc16; }
	.item-type-dot.leaf { background: #38bdf8; }

	.item-label {
		flex: 1;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		min-width: 0;
	}

	.item-org {
		font-size: 0.7rem;
		color: #64748b;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		max-width: 100px;
	}

	.item-grade {
		font-size: 0.7rem;
		font-weight: 600;
		color: #94a3b8;
		flex-shrink: 0;
	}

	.item-badge {
		font-size: 0.55rem;
		font-weight: 600;
		text-transform: uppercase;
		padding: 0.1rem 0.3rem;
		background: rgba(56, 189, 248, 0.1);
		border: 1px solid rgba(56, 189, 248, 0.2);
		border-radius: 3px;
		color: #64748b;
		flex-shrink: 0;
	}

	.dropdown-loading {
		padding: 0.5rem 0.75rem;
		font-size: 0.75rem;
		color: #64748b;
		text-align: center;
	}

	.search-clear {
		background: none;
		border: none;
		color: #64748b;
		cursor: pointer;
		font-size: 1rem;
		padding: 0;
		line-height: 1;
	}

	.toolbar-center { display: flex; gap: 0.375rem; align-items: center; }
	.filter-pills { display: flex; gap: 0.25rem; }

	.pill {
		background: rgba(56, 189, 248, 0.08);
		border: 1px solid rgba(56, 189, 248, 0.2);
		border-radius: 4px;
		padding: 0.2rem 0.5rem;
		font-size: 0.7rem;
		color: #94a3b8;
		cursor: pointer;
		transition: all 0.15s;
	}

	.pill:hover { background: rgba(56, 189, 248, 0.15); color: #e2e8f0; }
	.pill.active { background: rgba(56, 189, 248, 0.2); border-color: rgba(56, 189, 248, 0.4); color: #38bdf8; }
	.pill-expired.active { background: rgba(239, 68, 68, 0.15); border-color: rgba(239, 68, 68, 0.3); color: #ef4444; }
	.pill-blast.active { background: rgba(249, 115, 22, 0.15); border-color: rgba(249, 115, 22, 0.3); color: #f97316; }

	.toolbar-right { display: flex; gap: 0.25rem; }

	.zoom-btn {
		width: 28px;
		height: 28px;
		background: rgba(56, 189, 248, 0.08);
		border: 1px solid rgba(56, 189, 248, 0.2);
		border-radius: 4px;
		display: flex;
		align-items: center;
		justify-content: center;
		font-size: 0.85rem;
		color: #94a3b8;
		cursor: pointer;
		transition: all 0.15s;
	}

	.zoom-btn:hover { background: rgba(56, 189, 248, 0.15); color: #e2e8f0; }
</style>
