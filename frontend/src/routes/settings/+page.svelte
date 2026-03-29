<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { api, type SummaryStats } from '$lib/api';
	import { getCurrentUser, type AuthUser } from '$lib/auth';

	interface UserEntry {
		id: string;
		email: string;
		display_name: string;
		role: string;
		created_at: string;
		last_login_at: string | null;
	}

	interface VenafiStatus {
		enabled: boolean;
		last_push_at: string | null;
		pending: number;
		pushed: number;
		failed: number;
		dead_lettered: number;
		next_push_at: string | null;
	}

	const TABS = [
		{ id: 'users', label: 'Users', adminOnly: true },
		{ id: 'venafi', label: 'Venafi' },
		{ id: 'system', label: 'System' },
		{ id: 'profile', label: 'Profile' },
	];

	let activeTab = $derived(page.url.searchParams.get('tab') ?? 'users');
	let currentUser = $state<AuthUser | null>(null);
	let loading = $state(true);

	// Users tab
	let users = $state<UserEntry[]>([]);
	let usersLoading = $state(false);
	let showCreateUser = $state(false);
	let newEmail = $state('');
	let newPassword = $state('');
	let newDisplayName = $state('');
	let newRole = $state('viewer');
	let userError = $state('');
	let userSuccess = $state('');

	// Venafi tab
	let venafiStatus = $state<VenafiStatus | null>(null);

	// System tab
	let summary = $state<SummaryStats | null>(null);

	// Profile tab
	let currentPassword = $state('');
	let newPw = $state('');
	let confirmPw = $state('');
	let pwError = $state('');
	let pwSuccess = $state('');

	onMount(async () => {
		currentUser = await getCurrentUser();
		if (!currentUser || currentUser.id === 'anonymous') {
			goto('/login');
			return;
		}
		loading = false;
		loadTabData();
	});

	async function loadTabData() {
		if (activeTab === 'users' && currentUser?.role === 'admin') {
			await loadUsers();
		} else if (activeTab === 'venafi') {
			await loadVenafi();
		} else if (activeTab === 'system') {
			await loadSystem();
		}
	}

	$effect(() => {
		if (!loading) loadTabData();
	});

	function switchTab(tab: string) {
		const url = new URL(page.url);
		url.searchParams.set('tab', tab);
		goto(url.toString(), { replaceState: true, noScroll: true });
	}

	// Users
	async function loadUsers() {
		usersLoading = true;
		try {
			const res = await fetch('/api/v1/auth/users');
			if (res.ok) {
				const data = await res.json();
				users = data.users ?? [];
			}
		} catch {}
		usersLoading = false;
	}

	async function createUser() {
		userError = '';
		userSuccess = '';
		try {
			const res = await fetch('/api/v1/auth/users', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ email: newEmail, password: newPassword, display_name: newDisplayName, role: newRole }),
			});
			if (!res.ok) {
				const err = await res.json();
				userError = err.error || 'Failed to create user';
				return;
			}
			userSuccess = `User ${newEmail} created`;
			newEmail = ''; newPassword = ''; newDisplayName = ''; newRole = 'viewer';
			showCreateUser = false;
			await loadUsers();
		} catch (e) {
			userError = 'Failed to create user';
		}
	}

	async function deleteUser(id: string, email: string) {
		if (!confirm(`Delete user ${email}?`)) return;
		try {
			const res = await fetch(`/api/v1/auth/users/${id}`, { method: 'DELETE' });
			if (!res.ok) {
				const err = await res.json();
				userError = err.error || 'Failed to delete user';
				return;
			}
			await loadUsers();
		} catch {}
	}

	async function toggleRole(id: string, currentRole: string) {
		const newRoleVal = currentRole === 'admin' ? 'viewer' : 'admin';
		try {
			await fetch(`/api/v1/auth/users/${id}`, {
				method: 'PUT',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ role: newRoleVal }),
			});
			await loadUsers();
		} catch {}
	}

	// Venafi
	interface VenafiConfig {
		enabled: boolean; platform: string; region: string;
		has_api_key: boolean; base_url: string; client_id: string;
		has_refresh_token: boolean; folder: string; push_interval_minutes: number;
	}
	let venafiConfig = $state<VenafiConfig | null>(null);
	let vfEnabled = $state(false);
	let vfPlatform = $state('cloud');
	let vfRegion = $state('us');
	let vfAPIKey = $state('');
	let vfBaseURL = $state('');
	let vfClientID = $state('');
	let vfRefreshToken = $state('');
	let vfFolder = $state('\\VED\\Policy\\Discovered\\CipherFlag');
	let vfInterval = $state(60);
	let vfError = $state('');
	let vfSuccess = $state('');
	let vfTesting = $state(false);
	let vfTestResult = $state<{connected: boolean; error?: string} | null>(null);

	async function loadVenafi() {
		try {
			venafiStatus = await api.getVenafiStatus();
			const res = await fetch('/api/v1/venafi/config');
			if (res.ok) {
				venafiConfig = await res.json();
				if (venafiConfig) {
					vfEnabled = venafiConfig.enabled;
					vfPlatform = venafiConfig.platform;
					vfRegion = venafiConfig.region;
					vfBaseURL = venafiConfig.base_url;
					vfClientID = venafiConfig.client_id;
					vfFolder = venafiConfig.folder;
					vfInterval = venafiConfig.push_interval_minutes;
				}
			}
		} catch {}
	}

	async function saveVenafiConfig() {
		vfError = ''; vfSuccess = '';
		const body: Record<string, any> = {
			enabled: vfEnabled,
			platform: vfPlatform,
			region: vfRegion,
			push_interval_minutes: vfInterval,
			folder: vfFolder,
		};
		if (vfPlatform === 'cloud' && vfAPIKey) body.api_key = vfAPIKey;
		if (vfPlatform === 'tpp') {
			if (vfBaseURL) body.base_url = vfBaseURL;
			if (vfClientID) body.client_id = vfClientID;
			if (vfRefreshToken) body.refresh_token = vfRefreshToken;
		}
		try {
			const res = await fetch('/api/v1/venafi/config', {
				method: 'PUT',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(body),
			});
			if (!res.ok) {
				const err = await res.json();
				vfError = err.error || 'Failed to save';
				return;
			}
			vfSuccess = 'Configuration saved. Restart required for push scheduler changes.';
			vfAPIKey = ''; vfRefreshToken = '';
			await loadVenafi();
		} catch { vfError = 'Failed to save'; }
	}

	async function testVenafiConnection() {
		vfTesting = true; vfTestResult = null;
		try {
			const res = await fetch('/api/v1/venafi/test-connection', { method: 'POST' });
			vfTestResult = await res.json();
		} catch { vfTestResult = { connected: false, error: 'Request failed' }; }
		vfTesting = false;
	}

	// System
	async function loadSystem() {
		try {
			summary = await api.getSummary();
		} catch {}
	}

	// Profile
	async function changePassword() {
		pwError = '';
		pwSuccess = '';
		if (newPw !== confirmPw) { pwError = 'Passwords do not match'; return; }
		if (newPw.length < 8) { pwError = 'Password must be at least 8 characters'; return; }
		try {
			const res = await fetch('/api/v1/auth/me/password', {
				method: 'PUT',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ current_password: currentPassword, new_password: newPw }),
			});
			if (!res.ok) {
				const err = await res.json();
				pwError = err.error || 'Failed to change password';
				return;
			}
			pwSuccess = 'Password updated successfully';
			currentPassword = ''; newPw = ''; confirmPw = '';
		} catch {
			pwError = 'Failed to change password';
		}
	}

	function formatDate(d: string | null): string {
		if (!d) return 'Never';
		return new Date(d).toLocaleString();
	}

	// Add getVenafiStatus to api if not present
	async function getVenafiStatus(): Promise<VenafiStatus> {
		const res = await fetch('/api/v1/venafi/status');
		return res.json();
	}
</script>

<svelte:head>
	<title>Settings - CipherFlag</title>
</svelte:head>

<div class="settings-page">
	{#if loading}
		<div class="settings-loading">Loading...</div>
	{:else}
		<div class="settings-header">
			<h1>Settings</h1>
		</div>

		<div class="settings-layout">
			<nav class="settings-nav">
				{#each TABS as tab}
					{#if !tab.adminOnly || currentUser?.role === 'admin'}
						<button
							class="nav-item"
							class:active={activeTab === tab.id}
							onclick={() => switchTab(tab.id)}
						>
							{tab.label}
						</button>
					{/if}
				{/each}
			</nav>

			<div class="settings-content">
				<!-- Users Tab -->
				{#if activeTab === 'users' && currentUser?.role === 'admin'}
					<div class="tab-section">
						<div class="section-header">
							<h2>User Management</h2>
							<button class="add-btn" onclick={() => showCreateUser = !showCreateUser}>
								{showCreateUser ? 'Cancel' : '+ Add User'}
							</button>
						</div>

						{#if userError}
							<div class="msg error">{userError}</div>
						{/if}
						{#if userSuccess}
							<div class="msg success">{userSuccess}</div>
						{/if}

						{#if showCreateUser}
							<div class="create-form">
								<div class="form-row">
									<label>
										<span>Display Name</span>
										<input type="text" bind:value={newDisplayName} placeholder="Jane Smith" />
									</label>
									<label>
										<span>Email</span>
										<input type="email" bind:value={newEmail} placeholder="jane@example.com" />
									</label>
								</div>
								<div class="form-row">
									<label>
										<span>Password</span>
										<input type="password" bind:value={newPassword} placeholder="Min 8 characters" />
									</label>
									<label>
										<span>Role</span>
										<select bind:value={newRole}>
											<option value="viewer">Viewer</option>
											<option value="admin">Admin</option>
										</select>
									</label>
								</div>
								<button class="submit-btn" onclick={createUser}>Create User</button>
							</div>
						{/if}

						{#if usersLoading}
							<div class="tab-loading">Loading users...</div>
						{:else}
							<table class="users-table">
								<thead>
									<tr>
										<th>Name</th>
										<th>Email</th>
										<th>Role</th>
										<th>Created</th>
										<th>Last Login</th>
										<th></th>
									</tr>
								</thead>
								<tbody>
									{#each users as user}
										<tr>
											<td class="cell-name">{user.display_name}</td>
											<td class="cell-email">{user.email}</td>
											<td>
												<button class="role-badge" class:admin={user.role === 'admin'}
													onclick={() => toggleRole(user.id, user.role)}
													title="Click to toggle role"
												>
													{user.role}
												</button>
											</td>
											<td class="cell-date">{formatDate(user.created_at)}</td>
											<td class="cell-date">{formatDate(user.last_login_at)}</td>
											<td>
												{#if user.id !== currentUser?.id}
													<button class="delete-btn" onclick={() => deleteUser(user.id, user.email)}>Delete</button>
												{:else}
													<span class="you-badge">You</span>
												{/if}
											</td>
										</tr>
									{/each}
								</tbody>
							</table>
						{/if}
					</div>

				<!-- Venafi Tab -->
				{:else if activeTab === 'venafi'}
					<div class="tab-section">
						<h2>Venafi Integration</h2>

						{#if vfError}<div class="msg error">{vfError}</div>{/if}
						{#if vfSuccess}<div class="msg success">{vfSuccess}</div>{/if}

						<!-- Push Status -->
						{#if venafiStatus}
							<div class="status-card" class:enabled={venafiStatus.enabled}>
								<div class="sc-header">
									<span class="sc-indicator" class:on={venafiStatus.enabled}></span>
									<span class="sc-label">{venafiStatus.enabled ? 'Push Scheduler Active' : 'Push Scheduler Disabled'}</span>
								</div>
								{#if venafiStatus.enabled}
									<div class="venafi-stats">
										<div class="vs-row"><span class="vs-label">Pending</span><span class="vs-val">{venafiStatus.pending.toLocaleString()}</span></div>
										<div class="vs-row"><span class="vs-label">Pushed</span><span class="vs-val pushed">{venafiStatus.pushed.toLocaleString()}</span></div>
										<div class="vs-row"><span class="vs-label">Failed</span><span class="vs-val" class:failed={venafiStatus.failed > 0}>{venafiStatus.failed}</span></div>
										<div class="vs-row"><span class="vs-label">Dead Lettered</span><span class="vs-val" class:failed={venafiStatus.dead_lettered > 0}>{venafiStatus.dead_lettered}</span></div>
										<div class="vs-row"><span class="vs-label">Last Push</span><span class="vs-val">{formatDate(venafiStatus.last_push_at)}</span></div>
										<div class="vs-row"><span class="vs-label">Next Push</span><span class="vs-val">{formatDate(venafiStatus.next_push_at)}</span></div>
									</div>
								{/if}
							</div>
						{/if}

						<!-- Configuration Form -->
						{#if currentUser?.role === 'admin'}
							<div class="venafi-form">
								<h3>Configuration</h3>

								<div class="vf-field">
									<label class="toggle-row">
										<input type="checkbox" bind:checked={vfEnabled} />
										<span>Enable Venafi push</span>
									</label>
								</div>

								<div class="vf-field">
									<span class="vf-label">Platform</span>
									<select bind:value={vfPlatform}>
										<option value="cloud">Venafi Cloud (SaaS)</option>
										<option value="tpp">Venafi TPP (on-prem)</option>
									</select>
								</div>

								{#if vfPlatform === 'cloud'}
									<div class="vf-field">
										<span class="vf-label">Region</span>
										<select bind:value={vfRegion}>
											<option value="us">US (api.venafi.cloud)</option>
											<option value="eu">EU (api.venafi.eu)</option>
										</select>
									</div>
									<div class="vf-field">
										<span class="vf-label">API Key {venafiConfig?.has_api_key ? '(configured)' : '(not set)'}</span>
										<input type="password" bind:value={vfAPIKey} placeholder={venafiConfig?.has_api_key ? '••••••••' : 'Enter API key'} />
									</div>
								{:else}
									<div class="vf-field">
										<span class="vf-label">TPP Base URL</span>
										<input type="url" bind:value={vfBaseURL} placeholder="https://tpp.example.com" />
									</div>
									<div class="vf-field">
										<span class="vf-label">Client ID</span>
										<input type="text" bind:value={vfClientID} placeholder="OAuth2 client ID" />
									</div>
									<div class="vf-field">
										<span class="vf-label">Refresh Token {venafiConfig?.has_refresh_token ? '(configured)' : '(not set)'}</span>
										<input type="password" bind:value={vfRefreshToken} placeholder={venafiConfig?.has_refresh_token ? '••••••••' : 'Enter refresh token'} />
									</div>
									<div class="vf-field">
										<span class="vf-label">Policy Folder</span>
										<input type="text" bind:value={vfFolder} />
									</div>
								{/if}

								<div class="vf-field">
									<span class="vf-label">Push Interval (minutes, 5–1440)</span>
									<input type="number" bind:value={vfInterval} min="5" max="1440" />
								</div>

								<div class="vf-actions">
									<button class="submit-btn" onclick={saveVenafiConfig}>Save Configuration</button>
									<button class="test-btn" onclick={testVenafiConnection} disabled={vfTesting}>
										{vfTesting ? 'Testing...' : 'Test Connection'}
									</button>
								</div>

								{#if vfTestResult}
									<div class="test-result" class:connected={vfTestResult.connected} class:disconnected={!vfTestResult.connected}>
										{#if vfTestResult.connected}
											&#10003; Connected successfully
										{:else}
											&#10007; Connection failed: {vfTestResult.error}
										{/if}
									</div>
								{/if}

								<p class="config-hint">Changes are saved to <code>config/cipherflag.toml</code>. Restart the service for push scheduler changes to take effect.</p>
							</div>
						{:else}
							<div class="config-note">
								<p>Venafi configuration requires admin access.</p>
							</div>
						{/if}
					</div>

				<!-- System Tab -->
				{:else if activeTab === 'system'}
					<div class="tab-section">
						<h2>System Status</h2>

						{#if summary}
							<div class="system-grid">
								<div class="sys-card">
									<span class="sys-label">Total Certificates</span>
									<span class="sys-val">{summary.total_certs.toLocaleString()}</span>
								</div>
								<div class="sys-card">
									<span class="sys-label">Total Observations</span>
									<span class="sys-val">{summary.total_observations.toLocaleString()}</span>
								</div>
								<div class="sys-card">
									<span class="sys-label">Expired</span>
									<span class="sys-val" style="color: #ef4444">{summary.expired}</span>
								</div>
								<div class="sys-card">
									<span class="sys-label">Expiring &lt;30d</span>
									<span class="sys-val" style="color: #eab308">{summary.expiring_in_30_days}</span>
								</div>
								<div class="sys-card">
									<span class="sys-label">Grade F (Critical)</span>
									<span class="sys-val" style="color: #ef4444">{summary.critical_findings}</span>
								</div>
								<div class="sys-card">
									<span class="sys-label">Discovery Sources</span>
									<span class="sys-val">{Object.keys(summary.source_stats).length}</span>
								</div>
							</div>

							<h3>Discovery Sources</h3>
							<div class="source-list">
								{#each Object.entries(summary.source_stats).sort((a, b) => b[1] - a[1]) as [source, count]}
									<div class="source-row">
										<span class="src-name">{source}</span>
										<span class="src-count">{count}</span>
									</div>
								{/each}
							</div>

							<h3>Grade Distribution</h3>
							<div class="grade-list">
								{#each ['A+', 'A', 'B', 'C', 'D', 'F'] as grade}
									{@const count = summary.grade_distribution[grade] ?? 0}
									{#if count > 0}
										<div class="grade-row">
											<span class="gr-grade">{grade}</span>
											<span class="gr-count">{count}</span>
										</div>
									{/if}
								{/each}
							</div>
						{:else}
							<div class="tab-loading">Loading system status...</div>
						{/if}

						<div class="config-note">
							<h3>Configuration</h3>
							<p>System settings are managed in <code>config/cipherflag.toml</code>. Changes require a service restart.</p>
						</div>
					</div>

				<!-- Profile Tab -->
				{:else if activeTab === 'profile'}
					<div class="tab-section">
						<h2>Profile</h2>

						{#if currentUser}
							<div class="profile-card">
								<div class="pc-row">
									<span class="pc-label">Name</span>
									<span class="pc-val">{currentUser.display_name}</span>
								</div>
								<div class="pc-row">
									<span class="pc-label">Email</span>
									<span class="pc-val">{currentUser.email}</span>
								</div>
								<div class="pc-row">
									<span class="pc-label">Role</span>
									<span class="pc-val"><span class="role-badge" class:admin={currentUser.role === 'admin'}>{currentUser.role}</span></span>
								</div>
							</div>

							<h3>Change Password</h3>

							{#if pwError}
								<div class="msg error">{pwError}</div>
							{/if}
							{#if pwSuccess}
								<div class="msg success">{pwSuccess}</div>
							{/if}

							<div class="pw-form">
								<label>
									<span>Current Password</span>
									<input type="password" bind:value={currentPassword} />
								</label>
								<label>
									<span>New Password</span>
									<input type="password" bind:value={newPw} placeholder="Min 8 characters" />
								</label>
								<label>
									<span>Confirm New Password</span>
									<input type="password" bind:value={confirmPw} />
								</label>
								<button class="submit-btn" onclick={changePassword}>Update Password</button>
							</div>
						{/if}
					</div>
				{/if}
			</div>
		</div>
	{/if}
</div>

<style>
	.settings-page { padding: 1.5rem; height: 100%; overflow-y: auto; }
	.settings-loading { display: flex; align-items: center; justify-content: center; height: 50vh; color: var(--cf-text-muted); }

	.settings-header h1 { margin: 0 0 1.25rem; font-size: 1.3rem; font-weight: 700; color: var(--cf-text-primary); }

	.settings-layout { display: flex; gap: 1.5rem; }

	.settings-nav {
		width: 180px; flex-shrink: 0; display: flex; flex-direction: column; gap: 0.25rem;
	}

	.nav-item {
		padding: 0.5rem 0.75rem; font-size: 0.85rem; font-weight: 500;
		color: var(--cf-text-secondary); background: none; border: none;
		border-radius: 6px; cursor: pointer; text-align: left;
		transition: all 0.15s;
	}
	.nav-item:hover { color: var(--cf-text-primary); background: var(--cf-bg-tertiary); }
	.nav-item.active { color: var(--cf-accent); background: rgba(56, 189, 248, 0.1); }

	.settings-content { flex: 1; min-width: 0; }

	.tab-section { }

	h2 { margin: 0 0 1rem; font-size: 1.1rem; font-weight: 700; color: var(--cf-text-primary); }
	h3 { margin: 1.25rem 0 0.75rem; font-size: 0.85rem; font-weight: 600; color: var(--cf-text-muted); text-transform: uppercase; letter-spacing: 0.04em; }

	.section-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1rem; }
	.section-header h2 { margin: 0; }

	.tab-loading { padding: 2rem; text-align: center; color: var(--cf-text-muted); }

	/* Messages */
	.msg { padding: 0.5rem 0.75rem; border-radius: 6px; font-size: 0.8rem; margin-bottom: 0.75rem; }
	.msg.error { background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.25); color: #fca5a5; }
	.msg.success { background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.25); color: #86efac; }

	/* Buttons */
	.add-btn {
		padding: 0.375rem 0.75rem; font-size: 0.8rem; font-weight: 500;
		background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.2);
		border-radius: 6px; color: var(--cf-accent); cursor: pointer;
	}
	.add-btn:hover { background: rgba(56, 189, 248, 0.2); }

	.submit-btn {
		padding: 0.5rem 1.25rem; font-size: 0.85rem; font-weight: 600;
		background: var(--cf-accent); color: #0a0e17; border: none;
		border-radius: 6px; cursor: pointer; margin-top: 0.5rem;
	}
	.submit-btn:hover { opacity: 0.9; }

	.delete-btn {
		padding: 0.2rem 0.5rem; font-size: 0.7rem;
		background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2);
		border-radius: 4px; color: #ef4444; cursor: pointer;
	}
	.delete-btn:hover { background: rgba(239, 68, 68, 0.2); }

	/* Create form */
	.create-form {
		background: var(--cf-bg-secondary); border: 1px solid var(--cf-border);
		border-radius: 8px; padding: 1rem; margin-bottom: 1rem;
	}
	.form-row { display: flex; gap: 1rem; margin-bottom: 0.75rem; }
	.form-row label { flex: 1; display: flex; flex-direction: column; gap: 0.25rem; }
	.form-row span { font-size: 0.75rem; color: var(--cf-text-muted); }
	.form-row input, .form-row select {
		padding: 0.5rem 0.625rem; font-size: 0.85rem;
		background: var(--cf-bg-primary); border: 1px solid var(--cf-border);
		border-radius: 6px; color: var(--cf-text-primary); outline: none;
	}
	.form-row input:focus, .form-row select:focus { border-color: var(--cf-accent); }
	.form-row select { cursor: pointer; }

	/* Users table */
	.users-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
	.users-table th {
		text-align: left; padding: 0.5rem 0.75rem; color: var(--cf-text-muted);
		font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.04em;
		font-weight: 600; border-bottom: 1px solid var(--cf-border);
	}
	.users-table td { padding: 0.625rem 0.75rem; border-bottom: 1px solid var(--cf-border); color: var(--cf-text-secondary); }
	.cell-name { font-weight: 600; color: var(--cf-text-primary); }
	.cell-email { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; }
	.cell-date { font-size: 0.75rem; color: var(--cf-text-muted); }

	.role-badge {
		font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.04em;
		padding: 0.15rem 0.5rem; border-radius: 4px; border: none; cursor: pointer;
		background: rgba(56, 189, 248, 0.1); color: var(--cf-accent);
		transition: all 0.15s;
	}
	.role-badge.admin { background: rgba(249, 115, 22, 0.1); color: #f97316; }
	.role-badge:hover { opacity: 0.8; }

	.you-badge { font-size: 0.65rem; color: var(--cf-text-muted); font-style: italic; }

	/* Venafi */
	.status-card {
		background: var(--cf-bg-secondary); border: 1px solid var(--cf-border);
		border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem;
	}
	.sc-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.75rem; }
	.sc-indicator { width: 10px; height: 10px; border-radius: 50%; background: #64748b; }
	.sc-indicator.on { background: #22c55e; box-shadow: 0 0 6px rgba(34, 197, 94, 0.5); }
	.sc-label { font-size: 0.9rem; font-weight: 600; color: var(--cf-text-primary); }

	.venafi-stats { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; }
	.vs-row { display: flex; justify-content: space-between; padding: 0.375rem 0.625rem; background: var(--cf-bg-tertiary); border-radius: 4px; }
	.vs-label { font-size: 0.8rem; color: var(--cf-text-muted); }
	.vs-val { font-size: 0.8rem; font-weight: 600; color: var(--cf-text-primary); font-variant-numeric: tabular-nums; }
	.vs-val.pushed { color: #22c55e; }
	.vs-val.failed { color: #ef4444; }

	/* Config note */
	.config-note {
		background: var(--cf-bg-secondary); border: 1px solid var(--cf-border);
		border-radius: 8px; padding: 1rem; margin-top: 1rem;
	}
	.config-note h3 { margin: 0 0 0.5rem; }
	.config-note p { margin: 0.25rem 0; font-size: 0.8rem; color: var(--cf-text-secondary); }
	.config-note code { font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; color: var(--cf-accent); background: var(--cf-bg-tertiary); padding: 0.1rem 0.35rem; border-radius: 3px; }
	.config-note a { color: var(--cf-accent); }

	/* System */
	.system-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.75rem; }
	.sys-card {
		background: var(--cf-bg-secondary); border: 1px solid var(--cf-border);
		border-radius: 8px; padding: 0.75rem; text-align: center;
	}
	.sys-label { display: block; font-size: 0.65rem; color: var(--cf-text-muted); text-transform: uppercase; letter-spacing: 0.04em; }
	.sys-val { display: block; font-size: 1.3rem; font-weight: 700; color: var(--cf-text-primary); font-variant-numeric: tabular-nums; margin-top: 0.25rem; }

	.source-list { display: flex; flex-direction: column; gap: 0.25rem; }
	.source-row { display: flex; justify-content: space-between; padding: 0.375rem 0.625rem; background: var(--cf-bg-tertiary); border-radius: 4px; }
	.src-name { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: var(--cf-text-primary); }
	.src-count { font-weight: 600; color: var(--cf-accent); font-variant-numeric: tabular-nums; }

	.grade-list { display: flex; gap: 0.5rem; flex-wrap: wrap; }
	.grade-row { padding: 0.375rem 0.75rem; background: var(--cf-bg-tertiary); border-radius: 6px; }
	.gr-grade { font-weight: 700; font-size: 0.9rem; color: var(--cf-text-primary); margin-right: 0.375rem; }
	.gr-count { font-size: 0.8rem; color: var(--cf-text-muted); }

	/* Profile */
	.profile-card {
		background: var(--cf-bg-secondary); border: 1px solid var(--cf-border);
		border-radius: 8px; padding: 1rem; margin-bottom: 1rem;
	}
	.pc-row { display: flex; align-items: center; padding: 0.5rem 0; border-bottom: 1px solid var(--cf-border); }
	.pc-row:last-child { border-bottom: none; }
	.pc-label { width: 100px; font-size: 0.8rem; color: var(--cf-text-muted); }
	.pc-val { font-size: 0.85rem; color: var(--cf-text-primary); }

	.pw-form { max-width: 400px; }
	.pw-form label { display: flex; flex-direction: column; gap: 0.25rem; margin-bottom: 0.75rem; }
	.pw-form span { font-size: 0.75rem; color: var(--cf-text-muted); }
	.pw-form input {
		padding: 0.5rem 0.625rem; font-size: 0.85rem;
		background: var(--cf-bg-primary); border: 1px solid var(--cf-border);
		border-radius: 6px; color: var(--cf-text-primary); outline: none;
	}
	.pw-form input:focus { border-color: var(--cf-accent); }

	/* Venafi form */
	.venafi-form { background: var(--cf-bg-secondary); border: 1px solid var(--cf-border); border-radius: 8px; padding: 1.25rem; margin-top: 1rem; }
	.venafi-form h3 { margin: 0 0 1rem; }

	.vf-field { margin-bottom: 0.75rem; }
	.vf-label { display: block; font-size: 0.75rem; color: var(--cf-text-muted); margin-bottom: 0.25rem; }
	.vf-field input, .vf-field select {
		width: 100%; max-width: 400px; padding: 0.5rem 0.625rem; font-size: 0.85rem;
		background: var(--cf-bg-primary); border: 1px solid var(--cf-border);
		border-radius: 6px; color: var(--cf-text-primary); outline: none;
	}
	.vf-field input:focus, .vf-field select:focus { border-color: var(--cf-accent); }
	.vf-field select { cursor: pointer; }

	.toggle-row { display: flex; align-items: center; gap: 0.5rem; cursor: pointer; font-size: 0.85rem; color: var(--cf-text-primary); }
	.toggle-row input[type="checkbox"] { width: 16px; height: 16px; accent-color: var(--cf-accent); }

	.vf-actions { display: flex; gap: 0.75rem; margin-top: 1rem; }

	.test-btn {
		padding: 0.5rem 1.25rem; font-size: 0.85rem; font-weight: 500;
		background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.2);
		border-radius: 6px; color: var(--cf-accent); cursor: pointer;
	}
	.test-btn:hover { background: rgba(56, 189, 248, 0.2); }
	.test-btn:disabled { opacity: 0.5; cursor: not-allowed; }

	.test-result {
		margin-top: 0.75rem; padding: 0.5rem 0.75rem; border-radius: 6px; font-size: 0.85rem;
	}
	.test-result.connected { background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.25); color: #86efac; }
	.test-result.disconnected { background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.25); color: #fca5a5; }

	.config-hint { margin-top: 0.75rem; font-size: 0.75rem; color: var(--cf-text-muted); }
	.config-hint code { font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: var(--cf-accent); background: var(--cf-bg-tertiary); padding: 0.1rem 0.3rem; border-radius: 3px; }
</style>
