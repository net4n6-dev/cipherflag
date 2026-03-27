// graph-types.ts — D3-compatible types for the force-directed graph

import type { SimulationNodeDatum, SimulationLinkDatum } from 'd3-force';

export interface ForceNode extends SimulationNodeDatum {
	id: string;
	label: string;
	type: 'root' | 'intermediate' | 'leaf';
	grade: string;
	certCount: number;
	avgScore: number;
	expiredCount: number;
	expiring30dCount: number;
	keyAlgorithm: string;
	keySizeBits: number;
	organization: string;
	isExpanded: boolean;
	// Computed visual properties
	radius: number;
	color: string;
	fillOpacity: number;
	pulseRate: number;
}

export interface ForceEdge extends SimulationLinkDatum<ForceNode> {
	id: string;
	sourceId: string;
	targetId: string;
	childGrade: string;
	color: string;
}

export type GraphMode = 'explore' | 'search' | 'blast-radius';

export interface GraphState {
	nodes: ForceNode[];
	edges: ForceEdge[];
	expandedCAs: Set<string>;
	mode: GraphMode;
	searchQuery: string;
	blastRadiusTarget: string | null;
	blastRadiusNodes: Set<string>;
	hoveredNode: ForceNode | null;
	selectedGrades: Set<string>;
	showExpiredOnly: boolean;
}

export const GRADE_COLORS: Record<string, string> = {
	'A+': '#22c55e',
	'A': '#22c55e',
	'B': '#84cc16',
	'C': '#eab308',
	'D': '#f97316',
	'F': '#ef4444',
	'?': '#64748b',
};

export function gradeColor(grade: string): string {
	return GRADE_COLORS[grade] ?? '#64748b';
}

export function nodeRadius(node: ForceNode): number {
	if (node.type === 'root') return 24 + Math.min(node.certCount / 200, 8);
	if (node.type === 'intermediate') return 14 + Math.min(node.certCount / 100, 6);
	return 6;
}

export function nodePulseRate(node: ForceNode): number {
	if (node.grade === 'F') return 2.5;
	if (node.expiredCount > 0) return 2.0;
	if (node.expiring30dCount > 0) return 1.0;
	return 0;
}
