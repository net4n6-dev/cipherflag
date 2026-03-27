<script lang="ts">
	import type { GraphMode } from './graph-types';

	interface Props {
		searchQuery: string;
		mode: GraphMode;
		selectedGrades: Set<string>;
		showExpiredOnly: boolean;
		nodeCount: number;
		edgeCount: number;
		expandedCount: number;
		onSearchChange: (q: string) => void;
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
		onSearchChange,
		onGradeToggle,
		onExpiredToggle,
		onBlastRadiusToggle,
		onZoomIn,
		onZoomOut,
		onZoomReset,
	}: Props = $props();

	const GRADES = ['A+', 'A', 'B', 'C', 'D', 'F'];
</script>

<div class="graph-toolbar">
	<div class="toolbar-left">
		<div class="search-box">
			<span class="search-icon">&#128269;</span>
			<input
				type="text"
				placeholder="Search CAs or certificates..."
				value={searchQuery}
				oninput={(e) => onSearchChange(e.currentTarget.value)}
			/>
			{#if searchQuery}
				<button class="search-clear" onclick={() => onSearchChange('')}>&times;</button>
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

	.search-box {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		background: rgba(56, 189, 248, 0.08);
		border: 1px solid rgba(56, 189, 248, 0.2);
		border-radius: 6px;
		padding: 0.25rem 0.75rem;
		max-width: 280px;
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
