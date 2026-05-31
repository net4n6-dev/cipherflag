<script lang="ts">
  import {
    LayoutGrid, Shield, Orbit, BarChart3, FileText, Layers, Upload, Settings,
    PanelLeftClose, PanelLeftOpen,
  } from 'lucide-svelte';
  import scopeIcon from '$lib/assets/favicon.svg';

  interface NavItem { label: string; href: string; icon: typeof LayoutGrid; }
  interface NavGroup { label: string; items: NavItem[]; }

  interface Props {
    currentPath: string;
    collapsed?: boolean;
    onToggleCollapse?: () => void;
  }
  let { currentPath, collapsed = false, onToggleCollapse }: Props = $props();

  const groups: NavGroup[] = [
    { label: 'Overview', items: [
      { label: 'Dashboard', href: '/', icon: LayoutGrid },
    ]},
    { label: 'Inventory', items: [
      { label: 'Certificates', href: '/certificates', icon: Shield },
    ]},
    { label: 'Explore', items: [
      { label: 'PKI Explorer', href: '/pki', icon: Orbit },
      { label: 'Analytics', href: '/analytics', icon: BarChart3 },
      { label: 'Reports', href: '/reports', icon: FileText },
      { label: 'Statistics', href: '/stats', icon: Layers },
    ]},
    { label: 'Ingest', items: [
      { label: 'Upload', href: '/upload', icon: Upload },
    ]},
  ];

  const settingsItem: NavItem = { label: 'Settings', href: '/settings', icon: Settings };

  function isActive(href: string): boolean {
    if (href === '/') return currentPath === '/';
    return currentPath === href || currentPath.startsWith(href + '/');
  }
</script>

<aside class="cf-sidebar" data-collapsed={collapsed}>
  <div class="cf-logo">
    <img src={scopeIcon} alt="" aria-hidden="true" class="cf-logo-mark" />
    {#if !collapsed}
      <span class="cf-logo-text">CipherFlag</span>
      <span class="cf-logo-badge">CE</span>
    {/if}
  </div>

  <nav class="cf-nav" aria-label="Primary">
    {#each groups as group}
      {#if !collapsed}
        <div class="cf-nav-group-label">{group.label}</div>
      {/if}
      {#each group.items as item}
        <a
          href={item.href}
          class="cf-nav-item {isActive(item.href) ? 'cf-nav-item-active' : ''}"
          aria-current={isActive(item.href) ? 'page' : undefined}
        >
          <item.icon size={16} />
          {#if !collapsed}
            <span>{item.label}</span>
          {/if}
        </a>
      {/each}
    {/each}
  </nav>

  <div class="cf-sidebar-bottom">
    <a
      href={settingsItem.href}
      class="cf-nav-item {isActive(settingsItem.href) ? 'cf-nav-item-active' : ''}"
      aria-current={isActive(settingsItem.href) ? 'page' : undefined}
    >
      <settingsItem.icon size={16} />
      {#if !collapsed}
        <span>{settingsItem.label}</span>
      {/if}
    </a>
    <button
      type="button"
      class="cf-nav-item cf-collapse-btn"
      aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
      aria-expanded={!collapsed}
      title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
      onclick={onToggleCollapse}
    >
      {#if collapsed}
        <PanelLeftOpen size={16} />
      {:else}
        <PanelLeftClose size={16} />
        <span>Collapse</span>
      {/if}
    </button>
  </div>
</aside>

<style>
  .cf-sidebar {
    width: 220px;
    background: var(--cf-bg-sidebar);
    border-right: 1px solid var(--cf-border);
    display: flex;
    flex-direction: column;
    padding: 12px 0;
    flex-shrink: 0;
    transition: width 300ms cubic-bezier(0.34, 1.56, 0.64, 1);
  }

  .cf-sidebar[data-collapsed="true"] {
    width: 56px;
  }

  .cf-logo {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 4px 16px 16px;
  }

  .cf-logo-mark {
    width: 24px;
    height: 24px;
    border-radius: 6px;
    flex-shrink: 0;
  }

  .cf-logo-text {
    color: var(--cf-text-primary);
    font-size: 14px;
    font-weight: 600;
    letter-spacing: -0.02em;
  }

  .cf-logo-badge {
    font-size: 10px;
    color: var(--cf-accent-secondary);
    border: 1px solid var(--cf-accent-secondary);
    border-radius: 3px;
    padding: 0 4px;
  }

  .cf-nav {
    display: flex;
    flex-direction: column;
    padding: 0 8px;
    gap: 1px;
  }

  .cf-nav-group-label {
    color: var(--cf-text-disabled);
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    padding: 10px 8px 4px;
  }

  .cf-nav-item {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--cf-text-secondary);
    font-size: 12px;
    padding: 7px 8px;
    border-radius: 6px;
    text-decoration: none;
    transition: background 100ms ease, color 100ms ease;
  }
  .cf-nav-item:hover {
    background: var(--cf-bg-elevated);
    color: var(--cf-text-primary);
  }
  .cf-nav-item-active {
    background: var(--cf-bg-active);
    color: var(--cf-text-primary);
    font-weight: 500;
  }

  .cf-sidebar-bottom {
    margin-top: auto;
    padding: 8px;
    border-top: 1px solid var(--cf-border);
    padding-top: 8px;
    display: flex;
    flex-direction: column;
    gap: 1px;
  }

  .cf-collapse-btn {
    background: transparent;
    border: none;
    cursor: pointer;
    width: 100%;
    text-align: left;
    font: inherit;
    color: var(--cf-text-muted);
  }
  .cf-collapse-btn:hover {
    color: var(--cf-text-primary);
  }
</style>
