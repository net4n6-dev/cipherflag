<script lang="ts">
  import { T, useTask } from '@threlte/core';
  import { BufferAttribute, BufferGeometry, Color, LineSegments, LineBasicMaterial } from 'three';
  import type { Edge3D, Node3D } from './constellation-types';

  interface Props {
    nodes: Node3D[];
    edges: Edge3D[];
    dimmedNodes: Set<string>;
  }
  let { nodes, edges, dimmedNodes }: Props = $props();

  // Index nodes by id for fast edge resolution each frame.
  let nodeIndex = $derived.by(() => {
    const m = new Map<string, Node3D>();
    for (const n of nodes) m.set(n.id, n);
    return m;
  });

  const geometry = new BufferGeometry();
  const material = new LineBasicMaterial({ vertexColors: true, transparent: true, opacity: 0.35 });
  const lineSegments = new LineSegments(geometry, material);

  // Grow buffers as edges grow. Allocate with slack to avoid reallocating every tick.
  let capacity = 0;
  let positions = new Float32Array(0);
  let colors = new Float32Array(0);

  function ensureCapacity(edgeCount: number) {
    if (edgeCount <= capacity) return;
    capacity = Math.max(edgeCount * 2, 64);
    positions = new Float32Array(capacity * 6);
    colors = new Float32Array(capacity * 6);
    geometry.setAttribute('position', new BufferAttribute(positions, 3));
    geometry.setAttribute('color', new BufferAttribute(colors, 3));
  }

  const tmpColor = new Color();

  useTask(() => {
    ensureCapacity(edges.length);
    const posAttr = geometry.getAttribute('position') as BufferAttribute;
    const colAttr = geometry.getAttribute('color') as BufferAttribute;

    let written = 0;
    for (const e of edges) {
      const srcId = typeof e.source === 'string' ? e.source : e.source.id;
      const tgtId = typeof e.target === 'string' ? e.target : e.target.id;
      const s = nodeIndex.get(srcId);
      const t = nodeIndex.get(tgtId);
      if (!s || !t) continue;

      const dimmed = dimmedNodes.size > 0 && (dimmedNodes.has(srcId) || dimmedNodes.has(tgtId));
      tmpColor.set(e.color);
      if (dimmed) tmpColor.multiplyScalar(0.25);

      const o = written * 6;
      positions[o] = s.x;     positions[o + 1] = s.y;     positions[o + 2] = s.z;
      positions[o + 3] = t.x; positions[o + 4] = t.y;     positions[o + 5] = t.z;
      colors[o] = tmpColor.r;     colors[o + 1] = tmpColor.g; colors[o + 2] = tmpColor.b;
      colors[o + 3] = tmpColor.r; colors[o + 4] = tmpColor.g; colors[o + 5] = tmpColor.b;
      written++;
    }

    posAttr.needsUpdate = true;
    colAttr.needsUpdate = true;
    geometry.setDrawRange(0, written * 2);
  });
</script>

<T is={lineSegments} />
