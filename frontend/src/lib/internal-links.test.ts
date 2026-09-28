import { describe, it, expect } from 'vitest';

// Every in-app navigation target written literally in the source must be a
// route the SPA actually has. Links to routes that only exist in the
// Enterprise Edition (or that were renamed) otherwise fall through to the
// SPA's not-found page with no error anywhere: the constellation's "View
// full detail" link pointed at /assets/certificate/{fp} while the detail
// route is /certificates/[fingerprint].

const sources = import.meta.glob('/src/**/*.{svelte,ts}', {
	query: '?raw',
	import: 'default',
	eager: true
}) as Record<string, string>;

const routeFiles = Object.keys(import.meta.glob('/src/routes/**/+page.svelte'));

// A route's segments, e.g. /src/routes/certificates/[fingerprint]/+page.svelte
// becomes ['certificates', '[fingerprint]']; the root page has none.
const routes: string[][] = routeFiles.map((f) =>
	f.replace(/^\/src\/routes/, '').replace(/\/\+page\.svelte$/, '').split('/').filter(Boolean)
);

// href="/x", href='/x', href: '/x', goto('/x'), goto(`/x`). The target stops
// at a quote, query string or fragment.
const TARGET_PATTERNS = [
	/href\s*=\s*["'`](\/[^"'`?#\s]*)/g,
	/href\s*:\s*["'`](\/[^"'`?#\s]*)/g,
	/goto\(\s*["'`](\/[^"'`?#\s]*)/g
];

const PARAM = ':param';

// Segments built from an expression ({x}, ${x}, fp-{x}) are parameters.
function targetSegments(target: string): string[] {
	return target
		.split('/')
		.filter(Boolean)
		.map((s) => (s.includes('{') ? PARAM : s));
}

function matchesRoute(target: string[]): boolean {
	return routes.some(
		(route) =>
			route.length === target.length &&
			route.every((seg, i) => {
				const isRouteParam = seg.startsWith('[') && seg.endsWith(']');
				return isRouteParam || (target[i] !== PARAM && seg === target[i]);
			})
	);
}

function internalTargets(): { file: string; target: string }[] {
	const found: { file: string; target: string }[] = [];
	for (const [file, text] of Object.entries(sources)) {
		if (file.endsWith('.test.ts')) continue;
		for (const re of TARGET_PATTERNS) {
			for (const m of text.matchAll(re)) {
				const target = m[1];
				if (target.startsWith('//') || target.startsWith('/api/')) continue;
				// Static files served from static/ (favicons), not SPA routes.
				if (/\.[a-z0-9]+$/i.test(target)) continue;
				found.push({ file, target });
			}
		}
	}
	return found;
}

describe('internal navigation targets', () => {
	it('finds the route tree and some links (guards the guard)', () => {
		expect(routes.length).toBeGreaterThan(3);
		expect(internalTargets().length).toBeGreaterThan(5);
	});

	it('all resolve to a route that exists', () => {
		const broken = internalTargets()
			.filter(({ target }) => !matchesRoute(targetSegments(target)))
			.map(({ file, target }) => `${file}: ${target}`);
		expect(broken).toEqual([]);
	});

	it('matches parameters only against parameter segments', () => {
		expect(matchesRoute(targetSegments('/certificates/{fp}'))).toBe(true);
		expect(matchesRoute(targetSegments('/certificates'))).toBe(true);
		expect(matchesRoute(targetSegments('/'))).toBe(true);
		expect(matchesRoute(targetSegments('/assets/certificate/{fp}'))).toBe(false);
		expect(matchesRoute(targetSegments('/{x}'))).toBe(false);
	});
});
