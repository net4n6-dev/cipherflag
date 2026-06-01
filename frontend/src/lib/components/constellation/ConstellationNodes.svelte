<script lang="ts">
  import { useTask } from '@threlte/core';
  import type { Mesh } from 'three';
  import type { Node3D } from './constellation-types';
  import ConstellationNode from './ConstellationNode.svelte';

  interface Props {
    nodes: Node3D[];
    hoveredNodeId: string | null;
    selectedNodeId: string | null;
    dimmedNodes: Set<string>;
    onHover: (node: Node3D | null) => void;
    onClick: (node: Node3D) => void;
  }
  let {
    nodes,
    hoveredNodeId,
    selectedNodeId,
    dimmedNodes,
    onHover,
    onClick,
  }: Props = $props();

  const meshRefs = new Map<string, Mesh>();

  function register(id: string, mesh: Mesh | null) {
    if (mesh) meshRefs.set(id, mesh);
    else meshRefs.delete(id);
  }

  useTask(() => {
    for (const node of nodes) {
      const m = meshRefs.get(node.id);
      if (m) m.position.set(node.x, node.y, node.z);
    }
  });
</script>

{#each nodes as node (node.id)}
  <ConstellationNode
    {node}
    hovered={hoveredNodeId === node.id}
    selected={selectedNodeId === node.id}
    dim={dimmedNodes.has(node.id)}
    {onHover}
    {onClick}
    {register}
  />
{/each}
