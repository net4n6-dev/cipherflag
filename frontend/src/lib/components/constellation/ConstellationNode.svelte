<script lang="ts">
  import { T } from '@threlte/core';
  import type { Mesh } from 'three';
  import type { Node3D } from './constellation-types';

  interface Props {
    node: Node3D;
    hovered: boolean;
    selected: boolean;
    dim: boolean;
    onHover: (node: Node3D | null) => void;
    onClick: (node: Node3D) => void;
    register: (id: string, mesh: Mesh | null) => void;
  }
  let {
    node,
    hovered,
    selected,
    dim,
    onHover,
    onClick,
    register,
  }: Props = $props();

  let mesh = $state<Mesh>();

  $effect(() => {
    if (mesh) register(node.id, mesh);
    return () => register(node.id, null);
  });

  let opacity = $derived(dim ? 0.1 : 1);
  let emissiveIntensity = $derived(hovered ? 0.7 : selected ? 0.45 : 0);
</script>

<T.Mesh
  bind:ref={mesh}
  onpointerenter={() => onHover(node)}
  onpointerleave={() => onHover(null)}
  onclick={(e: PointerEvent) => {
    e.stopPropagation();
    onClick(node);
  }}
>
  {#if node.type === 'ssh_key'}
    <T.OctahedronGeometry args={[node.radius3d, 0]} />
    <T.MeshStandardMaterial
      color={node.color}
      emissive={node.color}
      {emissiveIntensity}
      {opacity}
      transparent
      roughness={0.45}
      metalness={0.15}
    />
  {:else if node.type === 'library'}
    {@const s = node.radius3d * 1.35}
    <T.BoxGeometry args={[s, s, s]} />
    <T.MeshStandardMaterial
      color={node.color}
      emissive={node.color}
      {emissiveIntensity}
      {opacity}
      transparent
      roughness={0.5}
      metalness={0.1}
    />
  {:else if node.type === 'host'}
    <T.SphereGeometry args={[node.radius3d, 14, 14]} />
    <T.MeshStandardMaterial
      color={node.color}
      emissive={node.color}
      {emissiveIntensity}
      opacity={opacity * 0.7}
      transparent
      wireframe
    />
  {:else}
    <T.SphereGeometry args={[node.radius3d, 20, 20]} />
    <T.MeshStandardMaterial
      color={node.color}
      emissive={node.color}
      {emissiveIntensity}
      {opacity}
      transparent
      roughness={0.35}
      metalness={0.2}
    />
  {/if}
</T.Mesh>
