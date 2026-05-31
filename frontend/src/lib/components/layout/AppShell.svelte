<script lang="ts">
  import type { Snippet } from 'svelte';
  import Sidebar from './Sidebar.svelte';
  import TopBar from './TopBar.svelte';

  interface Props {
    currentPath: string;
    breadcrumb: string[];
    sseConnected: boolean;
    sidebarCollapsed?: boolean;
    onToggleSidebar?: () => void;
    onLogout?: () => void;
    children?: Snippet;
  }
  let {
    currentPath,
    breadcrumb,
    sseConnected,
    sidebarCollapsed = false,
    onToggleSidebar,
    onLogout,
    children,
  }: Props = $props();
</script>

<div class="cf-app-shell">
  <Sidebar {currentPath} collapsed={sidebarCollapsed} onToggleCollapse={onToggleSidebar} />
  <div class="cf-app-main">
    <TopBar {breadcrumb} {sseConnected} {onLogout} />
    <div class="cf-app-content">
      {#if children}
        {@render children()}
      {/if}
    </div>
  </div>
</div>

<style>
  .cf-app-shell {
    display: flex;
    height: 100vh;
    width: 100%;
    background: var(--cf-bg-base);
  }
  .cf-app-main {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-width: 0;
  }
  .cf-app-content {
    flex: 1;
    overflow: auto;
  }
</style>
