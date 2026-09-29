import { describe, it, expect, vi, afterEach } from 'vitest';
import { getCurrentUser, setupAdmin } from './auth';

function mockFetch(body: unknown, ok = true) {
	const fn = vi.fn().mockResolvedValue({ ok, json: async () => body });
	vi.stubGlobal('fetch', fn);
	return fn;
}

afterEach(() => vi.unstubAllGlobals());

describe('getCurrentUser', () => {
	it('returns null for {user: null} (the login redirect depends on this)', async () => {
		mockFetch({ user: null, authenticated: false });
		expect(await getCurrentUser()).toBeNull();
	});

	it('returns null when the response has no user key', async () => {
		mockFetch({ authenticated: false });
		expect(await getCurrentUser()).toBeNull();
	});

	it('returns the user object when present', async () => {
		mockFetch({ user: { id: 'u1', email: 'a@b.c' }, authenticated: true });
		expect(await getCurrentUser()).toEqual({ id: 'u1', email: 'a@b.c' });
	});

	it('returns null on a non-ok response', async () => {
		mockFetch({}, false);
		expect(await getCurrentUser()).toBeNull();
	});
});

describe('setupAdmin', () => {
	it('sends the trimmed token in X-Setup-Token', async () => {
		const fn = mockFetch({ user: { id: 'u1' } });
		await setupAdmin('a@b.c', 'pw-long-enough', 'Admin', '  tok123\n');
		const init = fn.mock.calls[0][1];
		expect(init.headers['X-Setup-Token']).toBe('tok123');
		expect(init.headers['Content-Type']).toBe('application/json');
	});

	it('surfaces the server error message', async () => {
		mockFetch({ error: 'invalid or missing setup token' }, false);
		await expect(setupAdmin('a@b.c', 'pw', 'A', 'x')).rejects.toThrow('invalid or missing setup token');
	});
});
