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
			if (d.type === 'root') return -300;
			if (d.type === 'intermediate') return -150;
			return -30;
		}))
		.force('link', forceLink<ForceNode, ForceEdge>().id(d => d.id).strength((link) => {
			const target = link.target as ForceNode;
			if (target.type === 'intermediate') return 0.7;
			return 0.3;
		}).distance((link) => {
			const target = link.target as ForceNode;
			if (target.type === 'intermediate') return 120;
			return 60;
		}))
		.force('center', forceCenter(width / 2, height / 2).strength(0.05))
		.force('collision', forceCollide<ForceNode>().radius(d => d.radius + 4))
		.alphaDecay(0.02)
		.on('tick', onTick);
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
