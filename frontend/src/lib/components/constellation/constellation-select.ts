import type { Node3D } from './constellation-types';

// Where selecting a certificate in the constellation lands: its node when the
// certificate is in the graph, otherwise its detail page. Used by the
// ?select=<fingerprint> deep link that the Analytics Chain Flow tab opens. Falling back from the deep link replaces it
// in history: pushing left it behind the detail page, so Back returned to
// the deep link, which redirected forward again.
export type CertTarget =
	| { kind: 'node'; node: Node3D }
	| { kind: 'detail'; href: string; replaceState: boolean };

export function resolveCertTarget(
	nodes: Node3D[],
	fp: string,
	opts: { deepLink?: boolean } = {}
): CertTarget {
	const node = nodes.find((n) => n.id === fp);
	if (node) return { kind: 'node', node };
	// fp can come from the URL; encode it so it names one path segment.
	return {
		kind: 'detail',
		href: `/certificates/${encodeURIComponent(fp)}`,
		replaceState: opts.deepLink === true
	};
}

// The select query parameter, or null when absent or empty.
export function selectParam(search: string): string | null {
	return new URLSearchParams(search).get('select') || null;
}
