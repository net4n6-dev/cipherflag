<script lang="ts">
	interface Props {
		title: string;
		onPrint: () => void;
		onExportCSV: () => void;
	}

	let { title, onPrint, onExportCSV }: Props = $props();
</script>

<div class="report-toolbar">
	<div class="toolbar-left">
		<a href="/reports" class="back-link">&larr; Reports</a>
		<h2>{title}</h2>
	</div>
	<div class="toolbar-right">
		<button class="toolbar-btn" onclick={onExportCSV}>Download CSV</button>
		<button class="toolbar-btn" onclick={onPrint}>Print</button>
	</div>
</div>

<style>
	.report-toolbar {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 0.75rem 1.5rem;
		border-bottom: 1px solid var(--cf-border);
		background: var(--cf-bg-secondary);
		flex-shrink: 0;
	}

	.toolbar-left { display: flex; align-items: center; gap: 1rem; }

	.back-link {
		font-size: 0.8rem;
		color: var(--cf-accent);
		text-decoration: none;
	}

	.back-link:hover { text-decoration: underline; }

	h2 { margin: 0; font-size: 1rem; font-weight: 700; color: var(--cf-text-primary); }

	.toolbar-right { display: flex; gap: 0.5rem; }

	.toolbar-btn {
		padding: 0.375rem 0.75rem;
		font-size: 0.8rem;
		font-weight: 500;
		background: rgba(56, 189, 248, 0.1);
		border: 1px solid rgba(56, 189, 248, 0.2);
		border-radius: 6px;
		color: var(--cf-accent);
		cursor: pointer;
		transition: all 0.15s;
	}

	.toolbar-btn:hover { background: rgba(56, 189, 248, 0.2); }

	@media print {
		.report-toolbar { display: none; }
	}
</style>
