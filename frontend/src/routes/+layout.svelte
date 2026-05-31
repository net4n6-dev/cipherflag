<script lang="ts">
	import '../app.css';
	import favicon from '$lib/assets/favicon.svg';
	import { page } from '$app/state';
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import AppShell from '$lib/components/layout/AppShell.svelte';
	import { initTheme } from '$lib/stores/theme.svelte';
	import { getCurrentUser, checkAuthStatus, logout as doLogout, type AuthUser } from '$lib/auth';

	let { children } = $props();

	let currentUser = $state<AuthUser | null>(null);
	let authChecked = $state(false);
	let sidebarCollapsed = $state(false);

	const BREADCRUMB_LABELS: Record<string, string> = {
		'': 'Dashboard',
		certificates: 'Certificates',
		pki: 'PKI Explorer',
		analytics: 'Analytics',
		reports: 'Reports',
		stats: 'Statistics',
		upload: 'Upload',
		settings: 'Settings'
	};

	const currentPath = $derived(page.url.pathname);
	const breadcrumb = $derived.by(() => {
		const segs = page.url.pathname.split('/').filter(Boolean);
		if (segs.length === 0) return ['Dashboard'];
		return segs.map((s) => BREADCRUMB_LABELS[s] ?? s);
	});

	onMount(async () => {
		initTheme();
		if (typeof localStorage !== 'undefined') {
			sidebarCollapsed = localStorage.getItem('cf.sidebarCollapsed') === 'true';
		}

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

	function toggleSidebar() {
		sidebarCollapsed = !sidebarCollapsed;
		if (typeof localStorage !== 'undefined') {
			localStorage.setItem('cf.sidebarCollapsed', String(sidebarCollapsed));
		}
	}

	function isAuthPage(): boolean {
		return page.url.pathname === '/login' || page.url.pathname === '/setup-admin';
	}
</script>

<svelte:head>
	<link rel="icon" href="/favicon.ico" sizes="any" />
	<link rel="icon" href={favicon} type="image/svg+xml" />
	<link rel="icon" href="/favicon-16x16.png" sizes="16x16" type="image/png" />
	<link rel="icon" href="/favicon-32x32.png" sizes="32x32" type="image/png" />
	<link rel="apple-touch-icon" href="/apple-touch-icon.png" />
	<title>CipherFlag</title>
</svelte:head>

{#if isAuthPage()}
	{@render children()}
{:else}
	{#if authChecked}
		<AppShell
			{currentPath}
			{breadcrumb}
			sseConnected={false}
			{sidebarCollapsed}
			onToggleSidebar={toggleSidebar}
			onLogout={handleLogout}
		>
			{@render children()}
		</AppShell>
		<!-- Global search: TopBar shows a search affordance; wiring it to open the GlobalSearch overlay is a tracked follow-up. -->
	{:else}
		<div
			style="display:flex;align-items:center;justify-content:center;height:100vh;color:var(--cf-text-muted);"
		>
			Loading...
		</div>
	{/if}
{/if}
