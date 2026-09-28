import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render } from '@testing-library/svelte';

const goto = vi.fn();
vi.mock('$app/navigation', () => ({ goto: (...args: unknown[]) => goto(...args) }));

import PkiRedirect from './+page.svelte';

// /pki redirects to /constellation. It used to drop the query string, so a
// /pki?select=<fp> link (the old Chain Flow target, and any bookmark of it)
// arrived with nothing selected.
describe('/pki redirect', () => {
	beforeEach(() => goto.mockReset());
	afterEach(() => window.history.replaceState(null, '', '/'));

	it('keeps the query string', () => {
		window.history.replaceState(null, '', '/pki?select=aa11');
		render(PkiRedirect);
		expect(goto).toHaveBeenCalledWith('/constellation?select=aa11', { replaceState: true });
	});

	it('redirects plainly without one', () => {
		window.history.replaceState(null, '', '/pki');
		render(PkiRedirect);
		expect(goto).toHaveBeenCalledWith('/constellation', { replaceState: true });
	});
});
