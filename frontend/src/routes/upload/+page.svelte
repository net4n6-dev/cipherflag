<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type PCAPJob } from '$lib/api';

	type UploadState = 'idle' | 'uploading' | 'polling' | 'complete' | 'failed';

	let state: UploadState = $state('idle');
	let selectedFile: File | null = $state(null);
	let currentJob: PCAPJob | null = $state(null);
	let recentJobs: PCAPJob[] = $state([]);
	let errorMessage: string | null = $state(null);
	let dragOver = $state(false);
	let pollTimer: ReturnType<typeof setInterval> | undefined = $state(undefined);

	onMount(() => {
		loadRecentJobs();
		return () => {
			if (pollTimer) clearInterval(pollTimer);
		};
	});

	$effect(() => {
		if (state === 'polling' && currentJob) {
			const jobId = currentJob.id;
			pollTimer = setInterval(async () => {
				try {
					const job = await api.getPCAPJob(jobId);
					currentJob = job;
					if (job.status === 'complete') {
						state = 'complete';
						clearInterval(pollTimer);
						pollTimer = undefined;
						loadRecentJobs();
					} else if (job.status === 'failed') {
						state = 'failed';
						errorMessage = job.error ?? 'Job failed';
						clearInterval(pollTimer);
						pollTimer = undefined;
						loadRecentJobs();
					}
				} catch (e) {
					state = 'failed';
					errorMessage = e instanceof Error ? e.message : 'Polling failed';
					clearInterval(pollTimer);
					pollTimer = undefined;
				}
			}, 2000);
		}
	});

	async function loadRecentJobs() {
		try {
			const res = await api.listPCAPJobs();
			recentJobs = res.jobs ?? [];
		} catch {}
	}

	function handleDrop(e: DragEvent) {
		e.preventDefault();
		dragOver = false;
		const file = e.dataTransfer?.files[0];
		if (file && isValidFile(file)) {
			selectedFile = file;
		}
	}

	function handleDragOver(e: DragEvent) {
		e.preventDefault();
		dragOver = true;
	}

	function handleDragLeave() {
		dragOver = false;
	}

	function handleFileInput(e: Event) {
		const input = e.target as HTMLInputElement;
		const file = input.files?.[0];
		if (file && isValidFile(file)) {
			selectedFile = file;
		}
	}

	function isValidFile(file: File): boolean {
		const name = file.name.toLowerCase();
		return name.endsWith('.pcap') || name.endsWith('.pcapng');
	}

	function formatFileSize(bytes: number): string {
		if (bytes < 1024) return `${bytes} B`;
		if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
		return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
	}

	async function upload() {
		if (!selectedFile) return;
		state = 'uploading';
		errorMessage = null;
		try {
			const job = await api.uploadPCAP(selectedFile);
			currentJob = job;
			state = 'polling';
		} catch (e) {
			state = 'failed';
			errorMessage = e instanceof Error ? e.message : 'Upload failed';
		}
	}

	function reset() {
		if (pollTimer) {
			clearInterval(pollTimer);
			pollTimer = undefined;
		}
		state = 'idle';
		selectedFile = null;
		currentJob = null;
		errorMessage = null;
	}

	function formatDate(d: string): string {
		return new Date(d).toLocaleString('en-US', {
			month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
		});
	}

	function statusColor(status: string): string {
		switch (status) {
			case 'complete': return 'var(--cf-grade-a)';
			case 'failed': return 'var(--cf-risk-critical)';
			case 'processing': return 'var(--cf-accent)';
			case 'queued': return 'var(--cf-text-muted)';
			default: return 'var(--cf-text-muted)';
		}
	}
</script>

<div class="upload-page">
	<div class="page-header">
		<h1>PCAP Upload</h1>
		<p class="subtitle">Upload packet capture files to extract and analyze TLS certificates</p>
	</div>

	<div class="upload-section">
		{#if state === 'idle'}
			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<div
				class="drop-zone"
				class:drag-over={dragOver}
				ondrop={handleDrop}
				ondragover={handleDragOver}
				ondragleave={handleDragLeave}
			>
				{#if selectedFile}
					<div class="file-selected">
						<div class="file-icon">&#128196;</div>
						<div class="file-info">
							<div class="file-name">{selectedFile.name}</div>
							<div class="file-size">{formatFileSize(selectedFile.size)}</div>
						</div>
						<button class="clear-btn" onclick={() => { selectedFile = null; }}>&#10005;</button>
					</div>
					<button class="upload-btn" onclick={upload}>Upload &amp; Analyze</button>
				{:else}
					<div class="drop-prompt">
						<div class="drop-icon">&#8682;</div>
						<div class="drop-text">Drag &amp; drop a PCAP file here</div>
						<div class="drop-or">or</div>
						<label class="browse-btn">
							Browse files
							<input type="file" accept=".pcap,.pcapng" onchange={handleFileInput} hidden />
						</label>
						<div class="drop-hint">.pcap and .pcapng files supported</div>
					</div>
				{/if}
			</div>

		{:else if state === 'uploading'}
			<div class="status-card">
				<div class="spinner"></div>
				<div class="status-text">Uploading {selectedFile?.name}...</div>
			</div>

		{:else if state === 'polling' && currentJob}
			<div class="status-card">
				<div class="spinner"></div>
				<div class="status-text">
					Processing <strong>{currentJob.filename}</strong>
				</div>
				<div class="status-detail">
					Status: {currentJob.status} &middot; Certificates found: {currentJob.certs_found}
				</div>
			</div>

		{:else if state === 'complete' && currentJob}
			<div class="status-card success">
				<div class="result-icon">&#10003;</div>
				<div class="status-text">Processing Complete</div>
				<div class="result-stats">
					<div class="stat-item">
						<span class="stat-value">{currentJob.certs_found}</span>
						<span class="stat-label">Certificates Found</span>
					</div>
					<div class="stat-item">
						<span class="stat-value">{currentJob.certs_new}</span>
						<span class="stat-label">New Certificates</span>
					</div>
				</div>
				<div class="result-actions">
					<a href="/certificates" class="action-link">View Certificates</a>
					<button class="action-btn" onclick={reset}>Upload Another</button>
				</div>
			</div>

		{:else if state === 'failed'}
			<div class="status-card error">
				<div class="result-icon error-icon">&#10007;</div>
				<div class="status-text">Upload Failed</div>
				{#if errorMessage}
					<div class="error-detail">{errorMessage}</div>
				{/if}
				<button class="action-btn" onclick={reset}>Try Again</button>
			</div>
		{/if}
	</div>

	{#if recentJobs.length > 0}
		<div class="recent-section">
			<h2>Recent Jobs</h2>
			<div class="jobs-table-wrap">
				<table class="jobs-table">
					<thead>
						<tr>
							<th>File</th>
							<th>Size</th>
							<th>Status</th>
							<th>Certs Found</th>
							<th>New</th>
							<th>Date</th>
						</tr>
					</thead>
					<tbody>
						{#each recentJobs as job}
							<tr>
								<td class="filename-cell">{job.filename}</td>
								<td>{formatFileSize(job.file_size)}</td>
								<td>
									<span class="status-badge" style="color: {statusColor(job.status)}">{job.status}</span>
								</td>
								<td>{job.certs_found}</td>
								<td>{job.certs_new}</td>
								<td class="date-cell">{formatDate(job.created_at)}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		</div>
	{/if}
</div>

<style>
	.upload-page {
		padding: 1.5rem;
		max-width: 900px;
		margin: 0 auto;
		height: 100%;
		overflow-y: auto;
	}

	.page-header {
		margin-bottom: 1.5rem;
	}

	.page-header h1 {
		font-size: 1.4rem;
		font-weight: 700;
		margin: 0 0 0.25rem 0;
		color: var(--cf-text-primary);
	}

	.subtitle {
		font-size: 0.85rem;
		color: var(--cf-text-muted);
		margin: 0;
	}

	.upload-section {
		margin-bottom: 2rem;
	}

	.drop-zone {
		border: 2px dashed var(--cf-border);
		border-radius: 12px;
		padding: 2.5rem;
		text-align: center;
		transition: all 0.2s;
		background: var(--cf-bg-secondary);
	}

	.drop-zone.drag-over {
		border-color: var(--cf-accent);
		background: rgba(56, 189, 248, 0.05);
	}

	.drop-prompt {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 0.5rem;
	}

	.drop-icon {
		font-size: 2.5rem;
		color: var(--cf-text-muted);
	}

	.drop-text {
		font-size: 1rem;
		color: var(--cf-text-secondary);
		font-weight: 500;
	}

	.drop-or {
		font-size: 0.8rem;
		color: var(--cf-text-muted);
	}

	.browse-btn {
		padding: 0.5rem 1.25rem;
		background: var(--cf-bg-tertiary);
		border: 1px solid var(--cf-border);
		border-radius: 6px;
		color: var(--cf-text-primary);
		font-size: 0.85rem;
		cursor: pointer;
		transition: all 0.15s;
	}

	.browse-btn:hover {
		background: var(--cf-border);
	}

	.drop-hint {
		font-size: 0.75rem;
		color: var(--cf-text-muted);
		margin-top: 0.25rem;
	}

	.file-selected {
		display: flex;
		align-items: center;
		gap: 1rem;
		justify-content: center;
		margin-bottom: 1rem;
	}

	.file-icon {
		font-size: 1.5rem;
	}

	.file-info {
		text-align: left;
	}

	.file-name {
		font-weight: 600;
		color: var(--cf-text-primary);
		font-size: 0.95rem;
	}

	.file-size {
		font-size: 0.8rem;
		color: var(--cf-text-muted);
	}

	.clear-btn {
		background: none;
		border: none;
		color: var(--cf-text-muted);
		font-size: 1rem;
		cursor: pointer;
		padding: 0.25rem;
	}

	.clear-btn:hover {
		color: var(--cf-risk-critical);
	}

	.upload-btn {
		padding: 0.6rem 1.5rem;
		background: var(--cf-accent);
		border: none;
		border-radius: 6px;
		color: #0a0e17;
		font-size: 0.9rem;
		font-weight: 600;
		cursor: pointer;
		transition: all 0.15s;
	}

	.upload-btn:hover {
		background: var(--cf-accent-hover);
	}

	.status-card {
		background: var(--cf-bg-secondary);
		border: 1px solid var(--cf-border);
		border-radius: 12px;
		padding: 2.5rem;
		text-align: center;
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 0.75rem;
	}

	.status-card.success {
		border-color: var(--cf-grade-a);
	}

	.status-card.error {
		border-color: var(--cf-risk-critical);
	}

	.spinner {
		width: 32px;
		height: 32px;
		border: 3px solid var(--cf-border);
		border-top-color: var(--cf-accent);
		border-radius: 50%;
		animation: spin 0.8s linear infinite;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	.status-text {
		font-size: 1rem;
		color: var(--cf-text-primary);
		font-weight: 500;
	}

	.status-detail {
		font-size: 0.85rem;
		color: var(--cf-text-muted);
	}

	.result-icon {
		font-size: 2rem;
		color: var(--cf-grade-a);
		font-weight: 700;
	}

	.error-icon {
		color: var(--cf-risk-critical);
	}

	.result-stats {
		display: flex;
		gap: 2rem;
		margin: 0.5rem 0;
	}

	.stat-item {
		display: flex;
		flex-direction: column;
		align-items: center;
	}

	.stat-value {
		font-size: 1.5rem;
		font-weight: 700;
		color: var(--cf-text-primary);
	}

	.stat-label {
		font-size: 0.75rem;
		color: var(--cf-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}

	.result-actions {
		display: flex;
		gap: 0.75rem;
		margin-top: 0.5rem;
	}

	.action-link {
		padding: 0.5rem 1.25rem;
		background: var(--cf-accent);
		border-radius: 6px;
		color: #0a0e17;
		font-size: 0.85rem;
		font-weight: 600;
		text-decoration: none;
		transition: all 0.15s;
	}

	.action-link:hover {
		background: var(--cf-accent-hover);
	}

	.action-btn {
		padding: 0.5rem 1.25rem;
		background: var(--cf-bg-tertiary);
		border: 1px solid var(--cf-border);
		border-radius: 6px;
		color: var(--cf-text-secondary);
		font-size: 0.85rem;
		cursor: pointer;
		transition: all 0.15s;
	}

	.action-btn:hover {
		background: var(--cf-border);
		color: var(--cf-text-primary);
	}

	.error-detail {
		font-size: 0.85rem;
		color: var(--cf-risk-critical);
		font-family: 'JetBrains Mono', monospace;
	}

	.recent-section h2 {
		font-size: 1.1rem;
		font-weight: 600;
		color: var(--cf-text-primary);
		margin: 0 0 0.75rem 0;
	}

	.jobs-table-wrap {
		border: 1px solid var(--cf-border);
		border-radius: 8px;
		overflow: hidden;
	}

	.jobs-table {
		width: 100%;
		border-collapse: collapse;
		font-size: 0.85rem;
	}

	.jobs-table th {
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

	.jobs-table td {
		padding: 0.625rem 1rem;
		border-bottom: 1px solid var(--cf-border);
		color: var(--cf-text-secondary);
	}

	.jobs-table tr:last-child td {
		border-bottom: none;
	}

	.jobs-table tr:hover td {
		background: rgba(56, 189, 248, 0.04);
	}

	.filename-cell {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.8rem;
		color: var(--cf-text-primary);
	}

	.status-badge {
		font-weight: 600;
		text-transform: capitalize;
	}

	.date-cell {
		white-space: nowrap;
	}
</style>
