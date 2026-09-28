import type { Node3D } from './constellation-types';

// Where selecting a certificate in the constellation lands: its node when the
// certificate is in the graph, otherwise its detail page. Used by the page's
// search navigation and by the ?select=<fingerprint> deep link that the
// Analytics Chain Flow tab opens.
export type CertTarget = { kind: 'node'; node: Node3D } | { kind: 'detail'; href: string };

export function resolveCertTarget(nodes: Node3D[], fp: string): CertTarget {
	const node = nodes.find((n) => n.id === fp);
	if (node) return { kind: 'node', node };
	// fp can come from the URL; encode it so it names one path segment.
	return { kind: 'detail', href: `/certificates/${encodeURIComponent(fp)}` };
}

// The select query parameter, or null when absent or empty.
export function selectParam(search: string): string | null {
	return new URLSearchParams(search).get('select') || null;
}
