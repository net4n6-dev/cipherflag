<script lang="ts">
	import { goto } from '$app/navigation';
	import { setupAdmin } from '$lib/auth';

	let email = $state('');
	let password = $state('');
	let confirmPassword = $state('');
	let displayName = $state('');
	let error = $state('');
	let submitting = $state(false);

	async function handleSubmit() {
		error = '';
		if (password !== confirmPassword) {
			error = 'Passwords do not match';
			return;
		}
		if (password.length < 8) {
			error = 'Password must be at least 8 characters';
			return;
		}
		submitting = true;
		try {
			await setupAdmin(email, password, displayName);
			goto('/');
		} catch (e) {
			error = e instanceof Error ? e.message : 'Setup failed';
		}
		submitting = false;
	}
</script>

<svelte:head>
	<title>Setup - CipherFlag</title>
</svelte:head>

<div class="setup-page">
	<div class="setup-card">
		<div class="setup-header">
			<span class="logo-icon">&#9672;</span>
			<h1>CipherFlag</h1>
		</div>
		<p class="setup-subtitle">Create your admin account to get started</p>

		{#if error}
			<div class="setup-error">{error}</div>
		{/if}

		<form onsubmit={(e) => { e.preventDefault(); handleSubmit(); }}>
			<label class="field">
				<span>Display Name</span>
				<input type="text" bind:value={displayName} required placeholder="e.g. Admin" />
			</label>
			<label class="field">
				<span>Email</span>
				<input type="email" bind:value={email} required placeholder="admin@example.com" />
			</label>
			<label class="field">
				<span>Password</span>
				<input type="password" bind:value={password} required minlength="8" />
			</label>
			<label class="field">
				<span>Confirm Password</span>
				<input type="password" bind:value={confirmPassword} required minlength="8" />
			</label>
			<button type="submit" class="setup-btn" disabled={submitting}>
				{submitting ? 'Creating account...' : 'Create Admin Account'}
			</button>
		</form>
	</div>
</div>

<style>
	.setup-page {
		display: flex; align-items: center; justify-content: center;
		height: 100vh; background: var(--cf-bg-primary, #0a0e17);
	}

	.setup-card {
		width: 100%; max-width: 420px; padding: 2rem;
		background: var(--cf-bg-secondary, #111827);
		border: 1px solid var(--cf-border, rgba(56, 189, 248, 0.1));
		border-radius: 12px;
	}

	.setup-header {
		display: flex; align-items: center; gap: 0.75rem;
		margin-bottom: 0.25rem;
	}

	.logo-icon { font-size: 1.5rem; color: var(--cf-accent, #38bdf8); }
	h1 { margin: 0; font-size: 1.3rem; font-weight: 700; color: var(--cf-text-primary, #e2e8f0); }

	.setup-subtitle {
		margin: 0 0 1.5rem; font-size: 0.85rem;
		color: var(--cf-text-muted, #64748b);
	}

	.setup-error {
		padding: 0.625rem; margin-bottom: 1rem;
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.25);
		border-radius: 6px; font-size: 0.85rem; color: #fca5a5;
	}

	.field {
		display: flex; flex-direction: column; gap: 0.25rem;
		margin-bottom: 1rem;
	}

	.field span { font-size: 0.8rem; font-weight: 500; color: var(--cf-text-secondary, #94a3b8); }

	.field input {
		padding: 0.625rem 0.75rem; font-size: 0.9rem;
		background: var(--cf-bg-primary, #0a0e17);
		border: 1px solid var(--cf-border, rgba(56, 189, 248, 0.15));
		border-radius: 6px; color: var(--cf-text-primary, #e2e8f0);
		outline: none;
	}

	.field input:focus { border-color: var(--cf-accent, #38bdf8); }

	.setup-btn {
		width: 100%; padding: 0.75rem; font-size: 0.9rem;
		font-weight: 600; background: var(--cf-accent, #38bdf8);
		color: #0a0e17; border: none; border-radius: 6px;
		cursor: pointer; transition: opacity 0.15s;
	}

	.setup-btn:hover { opacity: 0.9; }
	.setup-btn:disabled { opacity: 0.5; cursor: not-allowed; }
</style>
