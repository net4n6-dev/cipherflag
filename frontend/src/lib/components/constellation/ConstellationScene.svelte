<script lang="ts">
  import { Canvas } from '@threlte/core';
  import type { Node3D, Edge3D } from './constellation-types';
  import ConstellationSceneBody, { type ConstellationSceneApi } from './ConstellationSceneBody.svelte';

  interface Props {
    nodes: Node3D[];
    edges: Edge3D[];
    hoveredNodeId: string | null;
    selectedNodeId: string | null;
    dimmedNodes: Set<string>;
    onHover: (node: Node3D | null) => void;
    onNodeClick: (node: Node3D) => void;
    onBackgroundClick: () => void;
    onReady?: (api: ConstellationSceneApi) => void;
  }
  let {
    nodes,
    edges,
    hoveredNodeId,
    selectedNodeId,
    dimmedNodes,
    onHover,
    onNodeClick,
    onBackgroundClick,
    onReady,
  }: Props = $props();
</script>

<div
  class="constellation-canvas-wrap"
  role="presentation"
  onpointerdown={(e) => {
    if (e.target === e.currentTarget) onBackgroundClick();
  }}
>
  <Canvas>
    <ConstellationSceneBody
      {nodes}
      {edges}
      {hoveredNodeId}
      {selectedNodeId}
      {dimmedNodes}
      {onHover}
      {onNodeClick}
      {onReady}
    />
  </Canvas>
</div>

<style>
  .constellation-canvas-wrap {
    width: 100%;
    height: 100%;
    position: relative;
  }
</style>
