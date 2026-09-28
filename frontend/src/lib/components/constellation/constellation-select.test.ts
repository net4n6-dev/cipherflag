import { describe, it, expect } from 'vitest';
import type { Node3D } from './constellation-types';
import { resolveCertTarget, selectParam } from './constellation-select';

function node(id: string): Node3D {
	return {
		id, label: id, type: 'intermediate', grade: 'A', certCount: 1, avgScore: 90,
		expiredCount: 0, expiring30dCount: 0, keyAlgorithm: 'ECDSA', keySizeBits: 256,
		organization: '', isExpanded: false, x: 0, y: 0, z: 0, radius3d: 1,
		color: '#fff', fillOpacity: 1, pulseRate: 0
	};
}

// ChainFlow's CA-node click lands on /constellation?select=<fp>. It used to
// go to /pki?select=<fp>, whose redirect dropped the parameter, so the user
// arrived at an unfocused graph with no error.
describe('constellation-select: resolveCertTarget', () => {
	const nodes = [node('aa11'), node('bb22')];

	it('selects the node when the certificate is in the graph', () => {
		expect(resolveCertTarget(nodes, 'bb22')).toEqual({ kind: 'node', node: nodes[1] });
	});

	it('falls back to the certificate detail page when it is not', () => {
		expect(resolveCertTarget(nodes, 'cc33')).toEqual({ kind: 'detail', href: '/certificates/cc33' });
	});

	it('encodes a fingerprint from the URL so it cannot change the path', () => {
		expect(resolveCertTarget(nodes, '../settings')).toEqual({
			kind: 'detail',
			href: '/certificates/..%2Fsettings'
		});
	});
});

describe('constellation-select: selectParam', () => {
	it('reads the select parameter', () => {
		expect(selectParam('?select=aa11')).toBe('aa11');
		expect(selectParam('?mode=x&select=aa11')).toBe('aa11');
	});

	it('is null when absent or empty', () => {
		expect(selectParam('')).toBeNull();
		expect(selectParam('?select=')).toBeNull();
		expect(selectParam('?other=1')).toBeNull();
	});
});
