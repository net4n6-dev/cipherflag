const BASE = '/api/v1';

export interface AuthUser {
	id: string;
	email: string;
	display_name: string;
	role: 'admin' | 'viewer';
	last_login_at?: string;
}

export async function checkAuthStatus(): Promise<{ has_users: boolean }> {
	const res = await fetch(`${BASE}/auth/status`);
	return res.json();
}

export async function getCurrentUser(): Promise<AuthUser | null> {
	const res = await fetch(`${BASE}/auth/me`);
	if (!res.ok) return null;
	return res.json();
}

export async function login(email: string, password: string): Promise<AuthUser> {
	const res = await fetch(`${BASE}/auth/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ email, password }),
	});
	if (!res.ok) {
		const err = await res.json();
		throw new Error(err.error || 'Login failed');
	}
	const data = await res.json();
	return data.user;
}

export async function logout(): Promise<void> {
	await fetch(`${BASE}/auth/logout`, { method: 'POST' });
}

export async function setupAdmin(email: string, password: string, displayName: string): Promise<AuthUser> {
	const res = await fetch(`${BASE}/auth/setup-admin`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ email, password, display_name: displayName }),
	});
	if (!res.ok) {
		const err = await res.json();
		throw new Error(err.error || 'Setup failed');
	}
	const data = await res.json();
	return data.user;
}
