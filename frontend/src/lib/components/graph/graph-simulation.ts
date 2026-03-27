// graph-simulation.ts — D3 force simulation management

import { forceSimulation, forceLink, forceManyBody, forceCenter, forceCollide, type Simulation } from 'd3-force';
import type { ForceNode, ForceEdge } from './graph-types';
import type { AggregatedGraphNode, AggregatedGraphEdge } from '$lib/api';
import { gradeColor, nodeRadius, nodePulseRate } from './graph-types';

export function createSimulation(
	width: number,
	height: number,
	onTick: () => void,
): Simulation<ForceNode, ForceEdge> {
	return forceSimulation<ForceNode>()
		.force('charge', forceManyBody<ForceNode>().strength((d) => {
			// Tight clustering — just enough repulsion to prevent overlap
			if (d.type === 'root') return -80;
			if (d.type === 'intermediate') return -40;
			return -15;
		}))
		.force('link', forceLink<ForceNode, ForceEdge>().id(d => d.id).strength((link) => {
			const target = link.target as ForceNode;
			if (target.type === 'intermediate') return 0.9;
			return 0.5;
		}).distance((link) => {
			const target = link.target as ForceNode;
			if (target.type === 'intermediate') return 50;
			return 30;
		}))
		.force('center', forceCenter(width / 2, height / 2).strength(0.15))
		.force('collision', forceCollide<ForceNode>().radius(d => d.radius + 6))
		.alphaDecay(0.025)
		.on('tick', onTick);
}

// Compute a zoom transform that fits all nodes into the viewport with padding
export function fitToViewport(
	nodes: ForceNode[],
	width: number,
	height: number,
	padding = 60,
): { x: number; y: number; k: number } {
	if (nodes.length === 0) return { x: 0, y: 0, k: 1 };

	let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
	for (const n of nodes) {
		const x = n.x ?? 0;
		const y = n.y ?? 0;
		const r = n.radius + 20; // account for label space
		if (x - r < minX) minX = x - r;
		if (y - r < minY) minY = y - r;
		if (x + r > maxX) maxX = x + r;
		if (y + r > maxY) maxY = y + r;
	}

	const graphW = maxX - minX;
	const graphH = maxY - minY;
	if (graphW === 0 || graphH === 0) return { x: 0, y: 0, k: 1 };

	const k = Math.min(
		(width - padding * 2) / graphW,
		(height - padding * 2) / graphH,
		2.5, // don't zoom in too much
	);
	const cx = (minX + maxX) / 2;
	const cy = (minY + maxY) / 2;

	return {
		x: width / 2 - cx * k,
		y: height / 2 - cy * k,
		k,
	};
}

export function apiNodeToForceNode(apiNode: AggregatedGraphNode): ForceNode {
	const node: ForceNode = {
		id: apiNode.fingerprint,
		label: apiNode.common_name || apiNode.fingerprint.slice(0, 12),
		type: apiNode.type as ForceNode['type'],
		grade: apiNode.worst_grade,
		certCount: apiNode.cert_count,
		avgScore: apiNode.avg_score,
		expiredCount: apiNode.expired_count,
		expiring30dCount: apiNode.expiring_30d_count,
		keyAlgorithm: apiNode.key_algorithm,
		keySizeBits: apiNode.key_size_bits,
		organization: apiNode.organization,
		isExpanded: false,
		radius: 0,
		color: '',
		fillOpacity: 0.12,
		pulseRate: 0,
	};
	node.radius = nodeRadius(node);
	node.color = gradeColor(node.grade);
	node.pulseRate = nodePulseRate(node);
	return node;
}

export function apiEdgeToForceEdge(apiEdge: AggregatedGraphEdge, _index: number): ForceEdge {
	return {
		id: `e-${apiEdge.source.slice(0, 8)}-${apiEdge.target.slice(0, 8)}`,
		source: apiEdge.source,
		target: apiEdge.target,
		sourceId: apiEdge.source,
		targetId: apiEdge.target,
		childGrade: apiEdge.child_grade,
		color: gradeColor(apiEdge.child_grade),
	};
}

export function updateSimulation(
	sim: Simulation<ForceNode, ForceEdge>,
	nodes: ForceNode[],
	edges: ForceEdge[],
): void {
	sim.nodes(nodes);
	const linkForce = sim.force('link') as ReturnType<typeof forceLink<ForceNode, ForceEdge>>;
	if (linkForce) {
		linkForce.links(edges);
	}
	sim.alpha(0.8).restart();
}
