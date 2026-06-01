<script lang="ts" module>
  export type ConstellationSceneApi = {
    zoomIn: () => void;
    zoomOut: () => void;
    fitView: () => void;
  };
</script>

<script lang="ts">
  import { T } from '@threlte/core';
  import { OrbitControls, interactivity } from '@threlte/extras';
  import type { PerspectiveCamera } from 'three';
  import type { OrbitControls as OrbitControlsImpl } from 'three/examples/jsm/controls/OrbitControls.js';
  import type { Node3D, Edge3D } from './constellation-types';
  import ConstellationNodes from './ConstellationNodes.svelte';
  import ConstellationEdges from './ConstellationEdges.svelte';

  // Register pointer events on meshes; must be called in a descendant of <Canvas>.
  interactivity();

  interface Props {
    nodes: Node3D[];
    edges: Edge3D[];
    hoveredNodeId: string | null;
    selectedNodeId: string | null;
    dimmedNodes: Set<string>;
    onHover: (node: Node3D | null) => void;
    onNodeClick: (node: Node3D) => void;
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
    onReady,
  }: Props = $props();

  let camera = $state<PerspectiveCamera>();
  let controls = $state<OrbitControlsImpl>();
  let readyFired = false;
  let initialFitDone = false;

  function computeBounds() {
    if (nodes.length === 0) return { cx: 0, cy: 0, cz: 0, radius: 120 };
    let cx = 0, cy = 0, cz = 0;
    for (const n of nodes) { cx += n.x; cy += n.y; cz += n.z; }
    cx /= nodes.length; cy /= nodes.length; cz /= nodes.length;
    let maxSq = 0;
    for (const n of nodes) {
      const dx = n.x - cx, dy = n.y - cy, dz = n.z - cz;
      const d = dx * dx + dy * dy + dz * dz;
      if (d > maxSq) maxSq = d;
    }
    const radius = Math.max(40, Math.sqrt(maxSq) + 20);
    return { cx, cy, cz, radius };
  }

  function fitView() {
    if (!camera || !controls) return;
    const { cx, cy, cz, radius } = computeBounds();
    const fovRad = (camera.fov * Math.PI) / 180;
    const ideal = radius / Math.tan(fovRad / 2);
    const dist = Math.min(controls.maxDistance, Math.max(controls.minDistance, ideal));
    const dir = camera.position.clone().sub(controls.target);
    if (dir.lengthSq() < 1e-4) dir.set(0, 0, 1);
    dir.normalize().multiplyScalar(dist);
    controls.target.set(cx, cy, cz);
    camera.position.copy(controls.target).add(dir);
    camera.updateProjectionMatrix();
    controls.update();
  }

  function zoomBy(factor: number) {
    if (!camera || !controls) return;
    const offset = camera.position.clone().sub(controls.target);
    const currentDist = offset.length();
    if (currentDist < 1e-4) return;
    const newDist = Math.min(
      controls.maxDistance,
      Math.max(controls.minDistance, currentDist * factor),
    );
    offset.normalize().multiplyScalar(newDist);
    camera.position.copy(controls.target).add(offset);
    controls.update();
  }

  function zoomIn() { zoomBy(0.75); }
  function zoomOut() { zoomBy(1 / 0.75); }

  $effect(() => {
    if (!readyFired && camera && controls) {
      readyFired = true;
      onReady?.({ zoomIn, zoomOut, fitView });
    }
  });

  $effect(() => {
    if (!initialFitDone && camera && controls && nodes.length > 0) {
      initialFitDone = true;
      fitView();
    }
  });
</script>

<T.PerspectiveCamera bind:ref={camera} makeDefault position={[0, 0, 220]} fov={55} near={1} far={2000}>
  <OrbitControls
    bind:ref={controls}
    enableDamping
    dampingFactor={0.08}
    rotateSpeed={0.6}
    zoomSpeed={0.8}
    panSpeed={0.6}
    minDistance={30}
    maxDistance={800}
  />
</T.PerspectiveCamera>

<T.AmbientLight intensity={0.6} />
<T.DirectionalLight position={[120, 180, 140]} intensity={0.8} />
<T.PointLight position={[0, 0, 0]} intensity={0.4} distance={400} color="#38bdf8" />

<T.Color attach="background" args={['#050914']} />
<T.Fog attach="fog" args={['#050914', 320, 900]} />

<ConstellationEdges {nodes} {edges} {dimmedNodes} />
<ConstellationNodes
  {nodes}
  {hoveredNodeId}
  {selectedNodeId}
  {dimmedNodes}
  {onHover}
  onClick={onNodeClick}
/>
