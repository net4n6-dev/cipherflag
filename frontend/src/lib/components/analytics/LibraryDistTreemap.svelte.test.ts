import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render } from '@testing-library/svelte';
import LibraryDistTreemap from './LibraryDistTreemap.svelte';

beforeEach(() => {
	// jsdom has no ResizeObserver; the component constructs one in onMount.
	vi.stubGlobal('ResizeObserver', class {
		observe() {}
		unobserve() {}
		disconnect() {}
	});
});

const items = [
	{ library: 'openssl', version: '1.1.1', host_count: 10, has_cves: true },
	{ library: 'openssl', version: '3.0.0', host_count: 5, has_cves: false },
	{ library: 'libgcrypt', version: '1.9.4', host_count: 2, has_cves: false },
];

describe('LibraryDistTreemap', () => {
	it('renders one rect per library item', () => {
		const { container } = render(LibraryDistTreemap, { props: { items } });
		expect(container.querySelectorAll('rect').length).toBe(3);
	});

	it('fills CVE libraries red and others green', () => {
		const { container } = render(LibraryDistTreemap, { props: { items } });
		const fills = Array.from(container.querySelectorAll('rect')).map((r) => r.getAttribute('fill'));
		expect(fills).toContain('#ef4444');
		expect(fills).toContain('#22c55e');
	});

	it('renders no rects for empty items', () => {
		const { container } = render(LibraryDistTreemap, { props: { items: [] } });
		expect(container.querySelectorAll('rect').length).toBe(0);
	});
});
