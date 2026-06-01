import { describe, it, expect } from 'vitest';
import { gradeColor, nodeShape, GRADE_COLORS } from './constellation-types';
import { apiNodeToNode3D, apiEdgeToEdge3D } from './constellation-physics';

// ---------------------------------------------------------------------------
// constellation-types: pure helpers (no WebGL)
// ---------------------------------------------------------------------------

describe('constellation-types — gradeColor', () => {
	it('returns a hex color string for every known grade', () => {
		for (const [grade, expected] of Object.entries(GRADE_COLORS)) {
			const result = gradeColor(grade);
			expect(result).toBe(expected);
			expect(result.startsWith('#')).toBe(true);
		}
	});

	it('distinguishes best grade (A+) from worst grade (F)', () => {
		expect(gradeColor('A+')).not.toBe(gradeColor('F'));
	});

	it('returns the fallback slate color for an unknown grade without throwing', () => {
		// 'Z' is not in GRADE_COLORS — should return the default '#64748b'
		expect(() => gradeColor('Z')).not.toThrow();
		expect(gradeColor('Z')).toBe('#64748b');
	});

	it('returns the explicit ? entry (not the fallback) for the ? grade', () => {
		// '?' is a first-class entry in GRADE_COLORS, not the ?? fallback path
		expect(gradeColor('?')).toBe('#64748b');
	});
});

describe('constellation-types — nodeShape', () => {
	it('returns sphere for root, intermediate, and leaf node types', () => {
		for (const t of ['root', 'intermediate', 'leaf'] as const) {
			expect(nodeShape(t)).toBe('sphere');
		}
	});

	it('returns octahedron for ssh_key nodes', () => {
		expect(nodeShape('ssh_key')).toBe('octahedron');
	});

	it('returns box for library nodes', () => {
		expect(nodeShape('library')).toBe('box');
	});

	it('returns wireframe-sphere for host nodes', () => {
		expect(nodeShape('host')).toBe('wireframe-sphere');
	});

	it('returns a non-empty string for every Node3D type', () => {
		const types = ['root', 'intermediate', 'leaf', 'ssh_key', 'library', 'host'] as const;
		for (const t of types) {
			const shape = nodeShape(t);
			expect(typeof shape).toBe('string');
			expect(shape.length).toBeGreaterThan(0);
		}
	});
});

// ---------------------------------------------------------------------------
// constellation-physics mappers: pure transform functions (no WebGL, no d3)
// ---------------------------------------------------------------------------

describe('constellation-physics — apiNodeToNode3D', () => {
	const baseApiNode = {
		fingerprint: 'fp-deadbeef1234',
		common_name: 'Root CA',
		type: 'root' as const,
		worst_grade: 'A+',
		cert_count: 42,
		avg_score: 95,
		expired_count: 0,
		expiring_30d_count: 0,
		key_algorithm: 'RSA',
		key_size_bits: 4096,
		organization: 'Acme Corp',
	};

	it('maps fingerprint to Node3D.id', () => {
		const n = apiNodeToNode3D(baseApiNode);
		expect(n.id).toBe('fp-deadbeef1234');
	});

	it('maps common_name to Node3D.label', () => {
		const n = apiNodeToNode3D(baseApiNode);
		expect(n.label).toBe('Root CA');
	});

	it('falls back to truncated fingerprint when common_name is empty', () => {
		const n = apiNodeToNode3D({ ...baseApiNode, common_name: '' });
		// physics.ts: apiNode.fingerprint.slice(0, 12) — 'fp-deadbeef1234'.slice(0,12) = 'fp-deadbeef1'
		expect(n.label).toBe('fp-deadbeef1234'.slice(0, 12));
	});

	it('maps worst_grade to Node3D.grade', () => {
		const n = apiNodeToNode3D(baseApiNode);
		expect(n.grade).toBe('A+');
	});

	it('derives Node3D.color via gradeColor(worst_grade)', () => {
		const n = apiNodeToNode3D(baseApiNode);
		expect(n.color).toBe(gradeColor('A+'));
		expect(n.color.startsWith('#')).toBe(true);
	});

	it('maps cert_count to Node3D.certCount', () => {
		const n = apiNodeToNode3D(baseApiNode);
		expect(n.certCount).toBe(42);
	});

	it('maps avg_score to Node3D.avgScore', () => {
		const n = apiNodeToNode3D(baseApiNode);
		expect(n.avgScore).toBe(95);
	});

	it('maps expired_count to Node3D.expiredCount', () => {
		const n = apiNodeToNode3D(baseApiNode);
		expect(n.expiredCount).toBe(0);
	});

	it('maps expiring_30d_count to Node3D.expiring30dCount', () => {
		const n = apiNodeToNode3D(baseApiNode);
		expect(n.expiring30dCount).toBe(0);
	});

	it('maps key_algorithm to Node3D.keyAlgorithm', () => {
		const n = apiNodeToNode3D(baseApiNode);
		expect(n.keyAlgorithm).toBe('RSA');
	});

	it('maps key_size_bits to Node3D.keySizeBits', () => {
		const n = apiNodeToNode3D(baseApiNode);
		expect(n.keySizeBits).toBe(4096);
	});

	it('maps organization to Node3D.organization', () => {
		const n = apiNodeToNode3D(baseApiNode);
		expect(n.organization).toBe('Acme Corp');
	});

	it('sets isExpanded to false', () => {
		const n = apiNodeToNode3D(baseApiNode);
		expect(n.isExpanded).toBe(false);
	});

	it('sets a non-zero radius3d based on type', () => {
		const n = apiNodeToNode3D(baseApiNode);
		// root with certCount=42: 3.0 + min(42/500, 1.5) = 3.084
		expect(n.radius3d).toBeGreaterThan(3.0);
		expect(n.radius3d).toBeLessThanOrEqual(4.5);
	});

	it('sets pulseRate=2.5 for grade F nodes', () => {
		const n = apiNodeToNode3D({ ...baseApiNode, worst_grade: 'F' });
		expect(n.pulseRate).toBe(2.5);
	});

	it('sets pulseRate=2.0 for nodes with expired certs (non-F grade)', () => {
		const n = apiNodeToNode3D({ ...baseApiNode, worst_grade: 'B', expired_count: 3 });
		expect(n.pulseRate).toBe(2.0);
	});

	it('sets pulseRate=1.0 for nodes expiring within 30 days (no expired, non-F grade)', () => {
		const n = apiNodeToNode3D({ ...baseApiNode, worst_grade: 'C', expiring_30d_count: 5 });
		expect(n.pulseRate).toBe(1.0);
	});

	it('sets pulseRate=0 for healthy nodes', () => {
		const n = apiNodeToNode3D(baseApiNode);
		expect(n.pulseRate).toBe(0);
	});

	it('sets fillOpacity to 0.12', () => {
		const n = apiNodeToNode3D(baseApiNode);
		expect(n.fillOpacity).toBe(0.12);
	});

	it('initialises 3D position fields as numbers', () => {
		const n = apiNodeToNode3D(baseApiNode);
		expect(typeof n.x).toBe('number');
		expect(typeof n.y).toBe('number');
		expect(typeof n.z).toBe('number');
	});
});

describe('constellation-physics — apiEdgeToEdge3D', () => {
	const baseApiEdge = {
		source: 'aaaa1111bbbb2222cccc3333dddd4444',
		target: 'eeee5555ffff6666aaaa7777bbbb8888',
		child_grade: 'B',
	};

	it('builds id from source + target slices', () => {
		const e = apiEdgeToEdge3D(baseApiEdge);
		expect(e.id).toBe(`e-${baseApiEdge.source.slice(0, 8)}-${baseApiEdge.target.slice(0, 8)}`);
	});

	it('sets source and sourceId from apiEdge.source', () => {
		const e = apiEdgeToEdge3D(baseApiEdge);
		expect(e.source).toBe(baseApiEdge.source);
		expect(e.sourceId).toBe(baseApiEdge.source);
	});

	it('sets target and targetId from apiEdge.target', () => {
		const e = apiEdgeToEdge3D(baseApiEdge);
		expect(e.target).toBe(baseApiEdge.target);
		expect(e.targetId).toBe(baseApiEdge.target);
	});

	it('maps child_grade to childGrade', () => {
		const e = apiEdgeToEdge3D(baseApiEdge);
		expect(e.childGrade).toBe('B');
	});

	it('derives color via gradeColor(child_grade)', () => {
		const e = apiEdgeToEdge3D(baseApiEdge);
		expect(e.color).toBe(gradeColor('B'));
	});

	it('hardcodes edgeType to "chain"', () => {
		const e = apiEdgeToEdge3D(baseApiEdge);
		expect(e.edgeType).toBe('chain');
	});
});
