<script lang="ts">
  import { Sun, Moon, Monitor, Search, User } from 'lucide-svelte';
  import { themeStore, setTheme, type ThemeMode } from '../../stores/theme.svelte';

  interface Props {
    breadcrumb: string[];
    sseConnected: boolean;
    onLogout?: () => void;
  }
  let { breadcrumb, sseConnected, onLogout }: Props = $props();

  function cycleTheme(): void {
    const order: ThemeMode[] = ['dark', 'light', 'system'];
    const current = order.indexOf(themeStore.mode);
    const next = order[(current + 1) % order.length];
    setTheme(next);
  }

  const ThemeIcon = $derived(
    themeStore.mode === 'light' ? Sun :
    themeStore.mode === 'system' ? Monitor : Moon
  );
  let themeLabel = $derived(`Theme: ${themeStore.mode}`);
</script>

<header class="cf-topbar">
  <div class="cf-breadcrumb" aria-label="Breadcrumb">
    {#each breadcrumb as segment, i}
      {#if i > 0}
        <span class="cf-breadcrumb-sep" aria-hidden="true">›</span>
      {/if}
      <span class="cf-breadcrumb-segment" class:cf-breadcrumb-current={i === breadcrumb.length - 1}>
        {segment}
      </span>
    {/each}
  </div>

  <div class="cf-topbar-spacer"></div>

  <button class="cf-search-trigger" aria-label="Open global search">
    <Search size={14} />
    <span>Search assets, hosts, findings...</span>
    <kbd class="cf-kbd">⌘K</kbd>
  </button>

  <button class="cf-time-range" aria-label="Time range">
    Last 7d ▾
  </button>

  <span
    data-testid="sse-indicator"
    class="cf-sse-indicator {sseConnected ? 'cf-sse-connected' : 'cf-sse-disconnected'}"
    aria-label={sseConnected ? 'Live updates connected' : 'Live updates disconnected'}
    title={sseConnected ? 'Live updates connected' : 'Live updates disconnected'}
  ></span>

  <button
    class="cf-theme-toggle"
    onclick={cycleTheme}
    aria-label={themeLabel}
    title={themeLabel}
  >
    <ThemeIcon size={14} />
  </button>

  <button
    class="cf-user-menu"
    onclick={onLogout}
    aria-label="Log out"
    title="Log out"
  >
    <User size={14} />
  </button>
</header>

<style>
  .cf-topbar {
    height: 48px;
    background: var(--cf-bg-surface);
    border-bottom: 1px solid var(--cf-border);
    display: flex;
    align-items: center;
    padding: 0 20px;
    gap: 12px;
    flex-shrink: 0;
  }

  .cf-breadcrumb {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 11px;
    color: var(--cf-text-muted);
  }
  .cf-breadcrumb-current {
    color: var(--cf-text-primary);
  }
  .cf-breadcrumb-sep {
    color: var(--cf-text-disabled);
  }

  .cf-topbar-spacer { flex: 1; }

  .cf-search-trigger {
    display: flex;
    align-items: center;
    gap: 6px;
    background: var(--cf-bg-elevated);
    border: 1px solid var(--cf-border-accent);
    border-radius: 6px;
    padding: 4px 12px;
    font-size: 12px;
    color: var(--cf-text-muted);
    width: 280px;
    cursor: pointer;
    transition: border-color 150ms ease;
  }
  .cf-search-trigger:hover {
    border-color: var(--cf-accent);
  }

  .cf-kbd {
    margin-left: auto;
    font-size: 10px;
    color: var(--cf-text-disabled);
    border: 1px solid var(--cf-border-accent);
    border-radius: 3px;
    padding: 1px 4px;
    font-family: inherit;
  }

  .cf-time-range,
  .cf-theme-toggle,
  .cf-user-menu {
    color: var(--cf-text-secondary);
    border: 1px solid var(--cf-border-accent);
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 12px;
    background: transparent;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    transition: border-color 150ms ease, color 150ms ease;
  }
  .cf-time-range:hover,
  .cf-theme-toggle:hover,
  .cf-user-menu:hover {
    color: var(--cf-accent);
    border-color: var(--cf-accent);
  }

  .cf-sse-indicator {
    width: 8px;
    height: 8px;
    border-radius: 50%;
  }
  .cf-sse-connected {
    background: var(--cf-status-active);
    box-shadow: 0 0 0 2px color-mix(in srgb, var(--cf-status-active) 25%, transparent);
  }
  .cf-sse-disconnected {
    background: var(--cf-text-disabled);
  }
</style>
