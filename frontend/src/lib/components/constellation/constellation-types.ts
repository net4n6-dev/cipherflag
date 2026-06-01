// constellation-types.ts — 3D node and edge types for threlte constellation

export interface Node3D {
  id: string;
  label: string;
  type: 'root' | 'intermediate' | 'leaf' | 'ssh_key' | 'library' | 'host';
  grade: string;
  certCount: number;
  avgScore: number;
  expiredCount: number;
  expiring30dCount: number;
  keyAlgorithm: string;
  keySizeBits: number;
  organization: string;
  isExpanded: boolean;
  // 3D position (managed by d3-force-3d)
  x: number;
  y: number;
  z: number;
  // Fixed position (for dragging)
  fx?: number | null;
  fy?: number | null;
  fz?: number | null;
  // Visual properties
  radius3d: number;
  color: string;
  fillOpacity: number;
  pulseRate: number;
}

export interface Edge3D {
  id: string;
  source: string | Node3D;
  target: string | Node3D;
  sourceId: string;
  targetId: string;
  childGrade: string;
  color: string;
  edgeType: 'chain' | 'host-asset' | 'library-host';
}

export type ConstellationMode = 'explore' | 'search' | 'blast-radius';

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

export function nodeRadius3D(node: Node3D): number {
  if (node.type === 'root') return 3.0 + Math.min(node.certCount / 500, 1.5);
  if (node.type === 'intermediate') return 2.0 + Math.min(node.certCount / 300, 1.0);
  if (node.type === 'host') return 2.5;
  if (node.type === 'ssh_key') return 1.2;
  if (node.type === 'library') return 1.5;
  return 0.8; // leaf
}

export function nodeShape(type: Node3D['type']): 'sphere' | 'octahedron' | 'box' | 'wireframe-sphere' {
  if (type === 'ssh_key') return 'octahedron';
  if (type === 'library') return 'box';
  if (type === 'host') return 'wireframe-sphere';
  return 'sphere';
}
