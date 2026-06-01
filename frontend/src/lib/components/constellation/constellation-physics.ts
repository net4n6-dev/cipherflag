// constellation-physics.ts — 3D force simulation for constellation

import type { Node3D, Edge3D } from './constellation-types';
import { gradeColor, nodeRadius3D } from './constellation-types';
import type { AggregatedGraphNode, AggregatedGraphEdge } from '$lib/api';

// d3-force-3d is imported dynamically in createSimulation3D to avoid SSR issues
let d3Force3d: typeof import('d3-force-3d') | null = null;

async function ensureD3Force3d() {
  if (!d3Force3d) {
    d3Force3d = await import('d3-force-3d');
  }
  return d3Force3d;
}

export async function createSimulation3D(
  nodes: Node3D[],
  edges: Edge3D[],
  onTick: () => void,
) {
  const d3 = await ensureD3Force3d();

  const sim = d3.forceSimulation(nodes, 3)
    .force('charge', d3.forceManyBody().strength((d: any) => {
      if (d.type === 'root') return -80;
      if (d.type === 'intermediate') return -35;
      return -10;
    }))
    .force('link', d3.forceLink(edges).id((d: any) => d.id).strength(0.8).distance(28))
    .force('center', d3.forceCenter(0, 0, 0).strength(0.15))
    .force('collision', d3.forceCollide().radius((d: any) => (d.radius3d ?? 2) + 3))
    .alphaDecay(0.025)
    .on('tick', onTick);

  // Pre-settle synchronously (no 'tick' events emitted) so the initial render
  // shows a stable layout instead of a visible outward "explosion".
  sim.tick(250);

  return sim;
}

export function apiNodeToNode3D(apiNode: AggregatedGraphNode): Node3D {
  const node: Node3D = {
    id: apiNode.fingerprint,
    label: apiNode.common_name || apiNode.fingerprint.slice(0, 12),
    type: apiNode.type as Node3D['type'],
    grade: apiNode.worst_grade,
    certCount: apiNode.cert_count,
    avgScore: apiNode.avg_score,
    expiredCount: apiNode.expired_count,
    expiring30dCount: apiNode.expiring_30d_count,
    keyAlgorithm: apiNode.key_algorithm,
    keySizeBits: apiNode.key_size_bits,
    organization: apiNode.organization,
    isExpanded: false,
    x: (Math.random() - 0.5) * 100,
    y: (Math.random() - 0.5) * 100,
    z: (Math.random() - 0.5) * 100,
    radius3d: 0,
    color: '',
    fillOpacity: 0.12,
    pulseRate: 0,
  };
  node.radius3d = nodeRadius3D(node);
  node.color = gradeColor(node.grade);
  if (node.grade === 'F') node.pulseRate = 2.5;
  else if (node.expiredCount > 0) node.pulseRate = 2.0;
  else if (node.expiring30dCount > 0) node.pulseRate = 1.0;
  return node;
}

export function apiEdgeToEdge3D(apiEdge: AggregatedGraphEdge): Edge3D {
  return {
    id: `e-${apiEdge.source.slice(0, 8)}-${apiEdge.target.slice(0, 8)}`,
    source: apiEdge.source,
    target: apiEdge.target,
    sourceId: apiEdge.source,
    targetId: apiEdge.target,
    childGrade: apiEdge.child_grade,
    color: gradeColor(apiEdge.child_grade),
    edgeType: 'chain',
  };
}
