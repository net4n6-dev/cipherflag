<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { Plus, Minus, Maximize2 } from 'lucide-svelte';
  import { api, type BlastRadiusResponse } from '$lib/api';
  import type { Node3D, Edge3D, ConstellationMode } from '$lib/components/constellation/constellation-types';
  import { gradeColor, nodeRadius3D } from '$lib/components/constellation/constellation-types';
  import { apiNodeToNode3D, apiEdgeToEdge3D, createSimulation3D } from '$lib/components/constellation/constellation-physics';
  import { onAssetDiscovered, onAssetScored } from '$lib/events.svelte';
  import ConstellationScene from '$lib/components/constellation/ConstellationScene.svelte';
  import type { ConstellationSceneApi } from '$lib/components/constellation/ConstellationSceneBody.svelte';

  // ── State ─────────────────────────────────────────────────────────────────
  let nodes: Node3D[] = $state([]);
  let edges: Edge3D[] = $state([]);
  let expandedCAs: Set<string> = $state(new Set());
  let mode: ConstellationMode = $state('explore');
  let searchQuery = $state('');
  let blastRadiusTarget: string | null = $state(null);
  let blastRadiusNodes: Set<string> = $state(new Set());
  let hoveredNode: Node3D | null = $state(null);
  let selectedNode: Node3D | null = $state(null);
  let selectedGrades: Set<string> = $state(new Set());
  let showExpiredOnly = $state(false);
  let loading = $state(true);
  let error: string | null = $state(null);
  let totalCerts = $state(0);
  let threlteAvailable = $state(false);
  let simulation: any = null;
  let tickCounter = $state(0);
  let sceneApi = $state<ConstellationSceneApi | null>(null);

  // ── Dimmed nodes (derived) ────────────────────────────────────────────────
  let dimmedNodes: Set<string> = $derived.by(() => {
    const dimmed = new Set<string>();
    if (mode === 'blast-radius' && blastRadiusTarget) {
      for (const n of nodes) {
        if (n.id !== blastRadiusTarget && !blastRadiusNodes.has(n.id)) dimmed.add(n.id);
      }
      return dimmed;
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      for (const n of nodes) {
        if (!n.label.toLowerCase().includes(q) && !n.organization.toLowerCase().includes(q) && !n.id.toLowerCase().startsWith(q)) dimmed.add(n.id);
      }
      return dimmed;
    }
    if (selectedGrades.size > 0) {
      for (const n of nodes) { if (!selectedGrades.has(n.grade)) dimmed.add(n.id); }
    }
    if (showExpiredOnly) {
      for (const n of nodes) { if (n.expiredCount === 0) dimmed.add(n.id); }
    }
    return dimmed;
  });

  // ── WebGL capability probe ──────────────────────────────────────────────────
  // The 3D scene needs a real WebGL context, not just the threlte module. Checking
  // the import alone is insufficient: threlte's <Canvas> throws "Error creating
  // WebGL context" on GPU-less / WebGL-disabled clients, which would leave a blank
  // graph. When WebGL is unavailable we fall back to the 2D SVG view.
  function webglAvailable(): boolean {
    if (typeof document === 'undefined') return false;
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl2') || canvas.getContext('webgl');
      return gl != null;
    } catch {
      return false;
    }
  }

  // ── Data loading ──────────────────────────────────────────────────────────
  onMount(async () => {
    // Check if threlte is available
    try {
      await import('@threlte/core');
      threlteAvailable = webglAvailable();
    } catch {
      threlteAvailable = false;
    }

    // Load graph data
    try {
      const resp = await api.getAggregatedLandscape();
      nodes = resp.nodes.map(apiNodeToNode3D);
      edges = resp.edges.map(apiEdgeToEdge3D);
      totalCerts = resp.nodes.reduce((sum, n) => sum + n.cert_count, 0);

      // Start 3D simulation
      simulation = await createSimulation3D(nodes, edges, () => {
        tickCounter++;
      });
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to load landscape';
    }
    loading = false;
  });

  // ── SSE ───────────────────────────────────────────────────────────────────
  // Only asset_type='certificate' participates in the chain graph; others are
  // surfaced in the inventory page but not the PKI constellation.
  $effect(() => {
    const unsub1 = onAssetDiscovered((ev) => {
      if (ev.asset_type !== 'certificate') return;
      if (nodes.some((n) => n.id === ev.asset_id)) return;
      const fresh: Node3D = {
        id: ev.asset_id,
        label: ev.asset_id.slice(0, 12),
        type: 'leaf',
        grade: '?',
        certCount: 1,
        avgScore: 0,
        expiredCount: 0,
        expiring30dCount: 0,
        keyAlgorithm: '',
        keySizeBits: 0,
        organization: '',
        isExpanded: false,
        x: (Math.random() - 0.5) * 60,
        y: (Math.random() - 0.5) * 60,
        z: (Math.random() - 0.5) * 60,
        radius3d: 0,
        color: gradeColor('?'),
        fillOpacity: 0.12,
        pulseRate: 1.5,
      };
      fresh.radius3d = nodeRadius3D(fresh);
      nodes = [...nodes, fresh];
      // Warm the simulation so the new node settles into the graph.
      if (simulation) simulation.alpha(0.3).restart();
    });
    const unsub2 = onAssetScored((ev) => {
      if (ev.asset_type !== 'certificate') return;
      const idx = nodes.findIndex((n) => n.id === ev.asset_id);
      if (idx < 0) return;
      const n = nodes[idx];
      n.grade = ev.grade;
      n.color = gradeColor(ev.grade);
      n.avgScore = ev.risk_score;
      n.pulseRate = ev.grade === 'F' ? 2.5 : 0;
      // Reassign to trigger reactive re-read in child components.
      nodes = [...nodes];
    });
    return () => { unsub1(); unsub2(); };
  });

  // ── Node interaction ──────────────────────────────────────────────────────
  function handleNodeClick(node: Node3D) {
    selectedNode = node;
  }

  function handleBackgroundClick() {
    selectedNode = null;
    hoveredNode = null;
    if (mode === 'blast-radius') {
      blastRadiusTarget = null;
      blastRadiusNodes = new Set();
      mode = 'explore';
    }
  }

  function handleSearchChange(q: string) {
    searchQuery = q;
    mode = q ? 'search' : 'explore';
  }

  function handleGradeToggle(grade: string) {
    const next = new Set(selectedGrades);
    if (next.has(grade)) next.delete(grade);
    else next.add(grade);
    selectedGrades = next;
  }

  function handleExpiredToggle() {
    showExpiredOnly = !showExpiredOnly;
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      if (selectedNode) selectedNode = null;
      else if (mode === 'blast-radius') { blastRadiusTarget = null; blastRadiusNodes = new Set(); mode = 'explore'; }
      else if (searchQuery) handleSearchChange('');
    }
  }

  async function handleExpandCA(fp: string) {
    try {
      const resp = await api.getCAChildren(fp);
      const newNodes = resp.nodes.map(apiNodeToNode3D);
      const newEdges = resp.edges.map(apiEdgeToEdge3D);
      const parent = nodes.find(n => n.id === fp);
      if (parent) {
        for (const n of newNodes) {
          n.x = parent.x + (Math.random() - 0.5) * 40;
          n.y = parent.y + (Math.random() - 0.5) * 40;
          n.z = parent.z + (Math.random() - 0.5) * 40;
        }
      }
      nodes = [...nodes, ...newNodes];
      edges = [...edges, ...newEdges];
      expandedCAs = new Set([...expandedCAs, fp]);
      const parentNode = nodes.find(n => n.id === fp);
      if (parentNode) parentNode.isExpanded = true;
      // Restart simulation with new data
      if (simulation) {
        simulation = await createSimulation3D(nodes, edges, () => { tickCounter++; });
      }
    } catch (e) {
      console.error('Failed to expand CA:', e);
    }
  }

  async function handleBlastRadius(fp: string) {
    try {
      const resp = await api.getBlastRadius(fp);
      blastRadiusTarget = fp;
      blastRadiusNodes = new Set(resp.nodes.map(n => n.fingerprint));
      mode = 'blast-radius';
    } catch (e) {
      console.error('Failed to load blast radius:', e);
    }
  }

  function handleNavigateCert(fp: string) {
    const target = nodes.find(n => n.id === fp);
    if (target) selectedNode = target;
    else goto(`/assets/certificate/${fp}`);
  }

  function nodeOpacity(node: Node3D): number {
    if (dimmedNodes.size === 0) return 1;
    return dimmedNodes.has(node.id) ? 0.1 : 1;
  }
</script>

<svelte:window onkeydown={handleKeydown} />
<svelte:head>
  <title>PKI Constellation - CipherFlag</title>
</svelte:head>

<div class="constellation-page cf-dark-zone">
  {#if loading}
    <div class="loading-overlay">Loading PKI constellation...</div>
  {:else if error}
    <div class="error-overlay">{error}</div>
  {:else}
    <!-- 3D Canvas or 2D fallback -->
    <div class="graph-container" data-tick={tickCounter}>
      {#if !threlteAvailable}
        <!-- Fallback: render a simplified 2D SVG view using the same data -->
        <svg class="fallback-svg" viewBox="-160 -160 320 320" preserveAspectRatio="xMidYMid meet" onclick={handleBackgroundClick} role="img" aria-label="PKI constellation graph">
          <g>
            {#each edges as edge}
              {@const src = typeof edge.source === 'object' ? edge.source : nodes.find(n => n.id === edge.source)}
              {@const tgt = typeof edge.target === 'object' ? edge.target : nodes.find(n => n.id === edge.target)}
              {#if src && tgt}
                <line
                  x1={src.x * 2}
                  y1={src.y * 2}
                  x2={tgt.x * 2}
                  y2={tgt.y * 2}
                  stroke={edge.color}
                  stroke-opacity="0.15"
                  stroke-width="1"
                />
              {/if}
            {/each}
            {#each nodes as node}
              <circle
                cx={node.x * 2}
                cy={node.y * 2}
                r={node.radius3d * 3}
                fill={node.color}
                fill-opacity={nodeOpacity(node) * 0.3}
                stroke={node.color}
                stroke-opacity={nodeOpacity(node)}
                stroke-width={node.type === 'root' ? 2 : 1}
                role="button"
                tabindex="-1"
                onclick={() => handleNodeClick(node)}
                onpointerenter={() => hoveredNode = node}
                onpointerleave={() => hoveredNode = null}
                style="cursor: pointer"
              />
            {/each}
          </g>
        </svg>
      {:else}
        <ConstellationScene
          {nodes}
          {edges}
          hoveredNodeId={hoveredNode?.id ?? null}
          selectedNodeId={selectedNode?.id ?? null}
          {dimmedNodes}
          onHover={(n) => (hoveredNode = n)}
          onNodeClick={handleNodeClick}
          onBackgroundClick={handleBackgroundClick}
          onReady={(api) => (sceneApi = api)}
        />
      {/if}
    </div>

    <!-- Toolbar overlay -->
    <div class="constellation-toolbar">
      <div class="toolbar-left">
        <div class="search-box">
          <input
            type="text"
            placeholder="Search CAs or certificates..."
            value={searchQuery}
            oninput={(e) => handleSearchChange(e.currentTarget.value)}
          />
          {#if searchQuery}
            <button class="search-clear" onclick={() => handleSearchChange('')}>&times;</button>
          {/if}
        </div>
      </div>
      <div class="toolbar-center">
        <div class="filter-pills">
          {#each ['A+', 'A', 'B', 'C', 'D', 'F'] as grade}
            <button class="pill" class:active={selectedGrades.has(grade)} onclick={() => handleGradeToggle(grade)}>{grade}</button>
          {/each}
        </div>
        <button class="pill pill-expired" class:active={showExpiredOnly} onclick={handleExpiredToggle}>Expired</button>
      </div>
      <div class="toolbar-right">
        <span class="toolbar-stats">{nodes.length} nodes · {totalCerts.toLocaleString()} certs</span>
      </div>
    </div>

    <!-- Zoom controls -->
    {#if threlteAvailable && sceneApi}
      <div class="constellation-zoom" class:shifted={selectedNode !== null}>
        <button type="button" aria-label="Zoom in" title="Zoom in" onclick={() => sceneApi?.zoomIn()}>
          <Plus size={14} />
        </button>
        <button type="button" aria-label="Zoom out" title="Zoom out" onclick={() => sceneApi?.zoomOut()}>
          <Minus size={14} />
        </button>
        <button type="button" aria-label="Fit all to view" title="Fit all to view" onclick={() => sceneApi?.fitView()}>
          <Maximize2 size={14} />
        </button>
      </div>
    {/if}

    <!-- Legend -->
    <div class="constellation-legend">
      <div class="legend-title">Legend</div>
      <div class="legend-items">
        <span class="legend-item"><span class="legend-dot root-dot"></span>Root CA</span>
        <span class="legend-item"><span class="legend-dot int-dot"></span>Intermediate</span>
        <span class="legend-item"><span class="legend-dot leaf-dot"></span>Leaf</span>
        <span class="legend-item"><span class="legend-dot risk-dot"></span>At Risk</span>
      </div>
    </div>

    <!-- Hover tooltip -->
    {#if hoveredNode}
      <div class="constellation-tooltip">
        <div class="tt-name">{hoveredNode.label}</div>
        {#if hoveredNode.organization}<div class="tt-org">{hoveredNode.organization}</div>{/if}
        <div class="tt-stats">
          <span style="color: {hoveredNode.color}; font-weight: 600">{hoveredNode.grade}</span>
          {#if hoveredNode.type !== 'leaf'}
            <span>{hoveredNode.certCount.toLocaleString()} certs</span>
            <span>{hoveredNode.expiredCount} expired</span>
          {/if}
        </div>
      </div>
    {/if}

    <!-- Detail panel -->
    {#if selectedNode}
      <div class="detail-panel">
        <div class="panel-header">
          <div class="header-top">
            <div class="header-grade" style="color: {gradeColor(selectedNode.grade)}">{selectedNode.grade}</div>
            <div class="header-info">
              <h3>{selectedNode.label}</h3>
              {#if selectedNode.organization}<span class="header-org">{selectedNode.organization}</span>{/if}
            </div>
            <button class="close-btn" onclick={() => selectedNode = null}>&times;</button>
          </div>
          <div class="header-stats">
            <div class="stat"><span class="stat-val">{selectedNode.type === 'leaf' ? '—' : selectedNode.certCount.toLocaleString()}</span><span class="stat-label">Certs</span></div>
            <div class="stat"><span class="stat-val" class:danger={selectedNode.expiredCount > 0}>{selectedNode.expiredCount}</span><span class="stat-label">Expired</span></div>
            <div class="stat"><span class="stat-val" class:warning={selectedNode.expiring30dCount > 0}>{selectedNode.expiring30dCount}</span><span class="stat-label">&lt;30d</span></div>
            <div class="stat"><span class="stat-val">{selectedNode.avgScore.toFixed(0)}</span><span class="stat-label">Score</span></div>
          </div>
          {#if selectedNode.type === 'root' || selectedNode.type === 'intermediate'}
            <div class="header-actions">
              {#if !selectedNode.isExpanded}
                <button class="action-btn" onclick={() => handleExpandCA(selectedNode!.id)}>Expand in Graph</button>
              {/if}
              <button class="action-btn action-blast" onclick={() => handleBlastRadius(selectedNode!.id)}>Blast Radius</button>
            </div>
          {/if}
        </div>
        <div class="panel-body">
          <div class="detail-grid">
            <span class="detail-key">Type</span>
            <span class="detail-val cap">{selectedNode.type === 'root' ? 'Root CA' : selectedNode.type === 'intermediate' ? 'Intermediate CA' : 'End Entity'}</span>
            <span class="detail-key">Algorithm</span>
            <span class="detail-val mono">{selectedNode.keyAlgorithm} {selectedNode.keySizeBits}</span>
            <span class="detail-key">Fingerprint</span>
            <span class="detail-val mono fp">{selectedNode.id}</span>
          </div>
          <a href="/assets/certificate/{selectedNode.id}" class="full-detail-link">View full detail &rarr;</a>
        </div>
      </div>
    {/if}
  {/if}
</div>

<style>
  .constellation-page { position: relative; width: 100%; height: 100%; overflow: hidden; background: var(--cf-bg-base); }
	.cf-dark-zone {
		background: var(--cf-bg-base);
	}

  .loading-overlay, .error-overlay { display: flex; align-items: center; justify-content: center; height: 100%; color: #64748b; font-size: 14px; }
  .error-overlay { color: #ef4444; }

  .graph-container { width: 100%; height: 100%; }
  .fallback-svg { width: 100%; height: 100%; display: block; cursor: grab; }
  .fallback-svg:active { cursor: grabbing; }

  .threlte-placeholder { display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; color: #64748b; font-size: 14px; gap: 8px; }
  .threlte-hint { font-size: 12px; color: #38bdf8; }

  /* Toolbar */
  .constellation-toolbar { position: absolute; top: 0; left: 0; right: 0; height: 44px; background: rgba(15, 23, 42, 0.95); border-bottom: 1px solid rgba(56, 189, 248, 0.15); display: flex; align-items: center; padding: 0 16px; gap: 12px; z-index: 10; }
  .toolbar-left { flex: 1; }
  .search-box { display: flex; align-items: center; gap: 8px; background: rgba(56, 189, 248, 0.08); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 6px; padding: 4px 12px; max-width: 320px; }
  .search-box input { background: none; border: none; outline: none; color: #e2e8f0; font-size: 12px; width: 100%; }
  .search-box input::placeholder { color: #64748b; }
  .search-clear { background: none; border: none; color: #64748b; cursor: pointer; font-size: 16px; padding: 0; line-height: 1; }
  .toolbar-center { display: flex; gap: 6px; align-items: center; }
  .filter-pills { display: flex; gap: 4px; }
  .pill { background: rgba(56, 189, 248, 0.08); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 4px; padding: 3px 8px; font-size: 11px; color: #94a3b8; cursor: pointer; transition: all 0.15s; }
  .pill:hover { background: rgba(56, 189, 248, 0.15); color: #e2e8f0; }
  .pill.active { background: rgba(56, 189, 248, 0.2); border-color: rgba(56, 189, 248, 0.4); color: #38bdf8; }
  .pill-expired.active { background: rgba(239, 68, 68, 0.15); border-color: rgba(239, 68, 68, 0.3); color: #ef4444; }
  .toolbar-right { display: flex; gap: 4px; }
  .toolbar-stats { font-size: 11px; color: #64748b; }

  /* Zoom controls */
  .constellation-zoom {
    position: absolute;
    bottom: 12px;
    right: 12px;
    display: flex;
    flex-direction: column;
    gap: 2px;
    background: rgba(15, 23, 42, 0.9);
    border: 1px solid rgba(56, 189, 248, 0.15);
    border-radius: 6px;
    padding: 3px;
    z-index: 10;
    transition: right 0.18s ease;
  }
  .constellation-zoom.shifted { right: 392px; }
  .constellation-zoom button {
    width: 28px;
    height: 28px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: transparent;
    border: none;
    border-radius: 4px;
    color: #94a3b8;
    cursor: pointer;
    transition: background-color 0.15s, color 0.15s;
  }
  .constellation-zoom button:hover {
    background: rgba(56, 189, 248, 0.15);
    color: #38bdf8;
  }

  /* Legend */
  .constellation-legend { position: absolute; bottom: 12px; left: 12px; background: rgba(15, 23, 42, 0.9); border: 1px solid rgba(56, 189, 248, 0.1); border-radius: 6px; padding: 8px 12px; z-index: 10; }
  .legend-title { font-size: 10px; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px; }
  .legend-items { display: flex; gap: 16px; font-size: 11px; color: #94a3b8; align-items: center; }
  .legend-item { display: flex; align-items: center; gap: 4px; }
  .legend-dot { display: inline-block; border-radius: 50%; }
  .root-dot { width: 12px; height: 12px; background: rgba(34, 197, 94, 0.15); border: 1.5px solid #22c55e; }
  .int-dot { width: 9px; height: 9px; background: rgba(132, 204, 22, 0.12); border: 1.5px solid #84cc16; }
  .leaf-dot { width: 6px; height: 6px; background: rgba(56, 189, 248, 0.2); border: 1px solid #38bdf8; }
  .risk-dot { width: 8px; height: 8px; border: 1.5px solid #ef4444; animation: pulse 2s infinite; }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }

  /* Tooltip */
  .constellation-tooltip { position: absolute; top: 56px; left: 16px; background: rgba(15, 23, 42, 0.95); border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 8px; padding: 10px 14px; min-width: 200px; z-index: 15; pointer-events: none; }
  .tt-name { font-size: 13px; font-weight: 600; color: #e2e8f0; }
  .tt-org { font-size: 11px; color: #64748b; margin-top: 2px; }
  .tt-stats { display: flex; gap: 12px; font-size: 11px; color: #94a3b8; margin-top: 6px; }

  /* Detail panel */
  .detail-panel { position: absolute; top: 0; right: 0; bottom: 0; width: 380px; background: rgba(15, 23, 42, 0.97); border-left: 1px solid rgba(56, 189, 248, 0.15); display: flex; flex-direction: column; z-index: 20; overflow: hidden; }
  .panel-header { padding: 16px; border-bottom: 1px solid rgba(56, 189, 248, 0.1); flex-shrink: 0; }
  .header-top { display: flex; align-items: flex-start; gap: 12px; }
  .header-grade { font-size: 24px; font-weight: 800; line-height: 1; flex-shrink: 0; }
  .header-info { flex: 1; min-width: 0; }
  .header-info h3 { margin: 0; font-size: 14px; font-weight: 600; color: #e2e8f0; word-break: break-word; }
  .header-org { font-size: 12px; color: #64748b; }
  .close-btn { background: none; border: none; color: #64748b; font-size: 24px; cursor: pointer; line-height: 1; padding: 0; flex-shrink: 0; }
  .close-btn:hover { color: #e2e8f0; }
  .header-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-top: 12px; }
  .stat { text-align: center; padding: 6px; background: rgba(56, 189, 248, 0.05); border-radius: 6px; }
  .stat-val { display: block; font-size: 16px; font-weight: 700; color: #e2e8f0; font-variant-numeric: tabular-nums; }
  .stat-label { display: block; font-size: 9px; color: #64748b; text-transform: uppercase; letter-spacing: 0.04em; margin-top: 2px; }
  .header-actions { display: flex; gap: 8px; margin-top: 12px; }
  .action-btn { flex: 1; padding: 6px; font-size: 12px; font-weight: 500; background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 6px; color: #38bdf8; cursor: pointer; transition: all 0.15s; }
  .action-btn:hover { background: rgba(56, 189, 248, 0.2); }
  .action-blast { background: rgba(249, 115, 22, 0.1); border-color: rgba(249, 115, 22, 0.2); color: #f97316; }
  .action-blast:hover { background: rgba(249, 115, 22, 0.2); }
  .panel-body { flex: 1; overflow-y: auto; padding: 12px 16px; }
  .detail-grid { display: grid; grid-template-columns: auto 1fr; gap: 5px 12px; font-size: 13px; }
  .detail-key { color: #64748b; }
  .detail-val { color: #cbd5e1; }
  .detail-val.mono { font-family: 'JetBrains Mono', monospace; font-size: 12px; }
  .detail-val.cap { text-transform: capitalize; }
  .detail-val.fp { word-break: break-all; font-size: 10px; }
  .danger { color: #ef4444 !important; }
  .warning { color: #eab308 !important; }
  .full-detail-link { display: block; margin-top: 16px; padding: 8px; text-align: center; font-size: 12px; color: #38bdf8; text-decoration: none; background: rgba(56, 189, 248, 0.05); border: 1px solid rgba(56, 189, 248, 0.15); border-radius: 6px; }
  .full-detail-link:hover { background: rgba(56, 189, 248, 0.1); }
</style>
