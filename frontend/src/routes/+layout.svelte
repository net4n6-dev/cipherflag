<script lang="ts">
	import '../app.css';
	import favicon from '$lib/assets/favicon.svg';
	import { page } from '$app/state';
	import GlobalSearch from '$lib/components/GlobalSearch.svelte';

	let { children } = $props();

	function isActive(href: string): boolean {
		if (href === '/') return page.url.pathname === '/';
		return page.url.pathname.startsWith(href);
	}
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<title>CipherFlag</title>
</svelte:head>

<div class="app-shell">
	<nav class="top-bar">
		<a href="/" class="logo">
			<span class="logo-icon">&#9672;</span>
			<span class="logo-text">CipherFlag</span>
		</a>
		<div class="nav-links">
			<a href="/" class="nav-link" class:active={isActive('/')}>Dashboard</a>
			<a href="/pki" class="nav-link" class:active={isActive('/pki')}>PKI Explorer</a>
			<a href="/certificates" class="nav-link" class:active={isActive('/certificates')}>Certificates</a>
			<a href="/upload" class="nav-link" class:active={isActive('/upload')}>Upload</a>
			<a href="/analytics" class="nav-link" class:active={isActive('/analytics')}>Analytics</a>
		</div>
		<GlobalSearch />
	</nav>
	<main class="main-content">
		{@render children()}
	</main>
</div>

<style>
	.app-shell {
		display: flex;
		flex-direction: column;
		height: 100vh;
		overflow: hidden;
	}

	.top-bar {
		display: flex;
		align-items: center;
		gap: 2rem;
		padding: 0 1.5rem;
		height: 48px;
		background: var(--cf-bg-secondary);
		border-bottom: 1px solid var(--cf-border);
		flex-shrink: 0;
	}

	.logo {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		text-decoration: none;
		color: var(--cf-text-primary);
		font-weight: 700;
		font-size: 1.1rem;
	}

	.logo-icon {
		color: var(--cf-accent);
		font-size: 1.3rem;
	}

	.nav-links {
		display: flex;
		gap: 0.25rem;
	}

	.nav-link {
		padding: 0.375rem 0.75rem;
		border-radius: 6px;
		text-decoration: none;
		color: var(--cf-text-secondary);
		font-size: 0.85rem;
		font-weight: 500;
		transition: all 0.15s;
	}

	.nav-link:hover {
		color: var(--cf-text-primary);
		background: var(--cf-bg-tertiary);
	}

	.nav-link.active {
		color: var(--cf-accent);
		background: rgba(56, 189, 248, 0.1);
	}

	.main-content {
		flex: 1;
		overflow: hidden;
	}
</style>
