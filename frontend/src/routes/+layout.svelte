<script lang="ts">
	import '../app.css';
	import favicon from '$lib/assets/favicon.svg';
	import { page } from '$app/state';
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import GlobalSearch from '$lib/components/GlobalSearch.svelte';
	import { getCurrentUser, checkAuthStatus, logout as doLogout, type AuthUser } from '$lib/auth';

	let { children } = $props();

	let currentUser = $state<AuthUser | null>(null);
	let authChecked = $state(false);

	onMount(async () => {
		const path = window.location.pathname;
		// Skip auth check on login/setup pages
		if (path === '/login' || path === '/setup-admin') {
			authChecked = true;
			return;
		}

		const user = await getCurrentUser();
		if (user) {
			if (user.id === 'anonymous') {
				// No users exist — redirect to setup
				goto('/setup-admin');
				return;
			}
			currentUser = user;
		} else {
			// Not authenticated — check if users exist
			const status = await checkAuthStatus();
			if (!status.has_users) {
				goto('/setup-admin');
				return;
			}
			goto('/login');
			return;
		}
		authChecked = true;
	});

	async function handleLogout() {
		await doLogout();
		currentUser = null;
		goto('/login');
	}

	function isActive(href: string): boolean {
		if (href === '/') return page.url.pathname === '/';
		return page.url.pathname.startsWith(href);
	}

	function isAuthPage(): boolean {
		return page.url.pathname === '/login' || page.url.pathname === '/setup-admin';
	}
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<title>CipherFlag</title>
</svelte:head>

{#if isAuthPage()}
	{@render children()}
{:else}
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
				<a href="/reports" class="nav-link" class:active={isActive('/reports')}>Reports</a>
				<a href="/analytics" class="nav-link" class:active={isActive('/analytics')}>Analytics</a>
			</div>
			<GlobalSearch />
			{#if currentUser && currentUser.id !== ''}
				<div class="user-menu">
					<a href="/settings?tab=profile" class="user-name-link">{currentUser.display_name}</a>
					<span class="user-role" class:admin={currentUser.role === 'admin'}>{currentUser.role}</span>
					<a href="/settings" class="settings-link" title="Settings">&#9881;</a>
					<button class="logout-btn" onclick={handleLogout}>Logout</button>
				</div>
			{/if}
		</nav>
		<main class="main-content">
			{#if authChecked}
				{@render children()}
			{:else}
				<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#64748b;">Loading...</div>
			{/if}
		</main>
	</div>
{/if}

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

	.user-menu {
		display: flex; align-items: center; gap: 0.5rem; margin-left: 0.75rem;
	}
	.user-name { font-size: 0.8rem; color: var(--cf-text-secondary); }
	.user-role {
		font-size: 0.6rem; text-transform: uppercase; letter-spacing: 0.04em;
		padding: 0.1rem 0.375rem; border-radius: 3px;
		background: rgba(56, 189, 248, 0.1); color: var(--cf-accent);
	}
	.user-role.admin { background: rgba(249, 115, 22, 0.1); color: #f97316; }
	.logout-btn {
		font-size: 0.75rem; color: var(--cf-text-muted);
		background: none; border: none; cursor: pointer;
		padding: 0.25rem 0.5rem; border-radius: 4px;
		transition: all 0.15s;
	}
	.logout-btn:hover { color: var(--cf-text-primary); background: var(--cf-bg-tertiary); }

	.user-name-link { font-size: 0.8rem; color: var(--cf-text-secondary); text-decoration: none; }
	.user-name-link:hover { color: var(--cf-text-primary); }

	.settings-link {
		font-size: 1rem; color: var(--cf-text-muted); text-decoration: none;
		padding: 0.125rem 0.25rem; border-radius: 4px; transition: all 0.15s;
	}
	.settings-link:hover { color: var(--cf-text-primary); background: var(--cf-bg-tertiary); }
</style>
