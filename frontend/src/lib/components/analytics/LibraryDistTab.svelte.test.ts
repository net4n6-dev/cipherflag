import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render } from '@testing-library/svelte';

const { getLib } = vi.hoisted(() => ({ getLib: vi.fn() }));
vi.mock('$lib/api', () => ({ api: { getLibraryDistribution: getLib } }));

import LibraryDistTab from './LibraryDistTab.svelte';

beforeEach(() => {
	vi.stubGlobal('ResizeObserver', class {
		observe() {}
		unobserve() {}
		disconnect() {}
	});
});

describe('LibraryDistTab', () => {
	it('renders the treemap when data is present', async () => {
		getLib.mockResolvedValue({
			items: [{ library: 'openssl', version: '3.0.0', host_count: 4, has_cves: false }],
			total: 1,
		});
		const { findByText, container } = render(LibraryDistTab);
		expect(await findByText('Library Distribution')).toBeTruthy();
		expect(container.querySelectorAll('rect').length).toBeGreaterThan(0);
	});

	it('shows the empty-state when there are no libraries', async () => {
		getLib.mockResolvedValue({ items: [], total: 0 });
		const { findByText } = render(LibraryDistTab);
		expect(await findByText(/configure a host-based source/i)).toBeTruthy();
	});
});
