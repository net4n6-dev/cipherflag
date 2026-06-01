<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '$lib/api';
  import type { SSHKeyAnalytics } from '$lib/api';

  let data = $state<SSHKeyAnalytics | null>(null);
  let loading = $state(true);
  let error: string | null = $state(null);

  onMount(async () => {
    try {
      data = await api.getSSHKeyAnalytics();
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to load SSH analytics';
    }
    loading = false;
  });

  const STRENGTH_ORDER = ['weak', 'acceptable', 'strong', 'modern'] as const;
  const STRENGTH_COLORS: Record<string, string> = {
    weak: 'var(--cf-severity-critical)',
    acceptable: 'var(--cf-severity-medium)',
    strong: 'var(--cf-severity-low)',
    modern: 'var(--cf-accent)',
    unknown: 'var(--cf-text-disabled)',
  };
  const STRENGTH_LABELS: Record<string, string> = {
    weak: 'Weak',
    acceptable: 'Acceptable',
    strong: 'Strong',
    modern: 'Modern (Ed25519)',
    unknown: 'Unknown',
  };

  const KEY_TYPE_COLORS: Record<string, string> = {
    dsa: 'var(--cf-severity-critical)',
    rsa: 'var(--cf-severity-medium)',
    ecdsa: 'var(--cf-severity-low)',
    ed25519: 'var(--cf-accent)',
  };

  const AGE_COLORS: Record<string, string> = {
    '0-30d': 'var(--cf-severity-low)',
    '31-90d': 'var(--cf-accent)',
    '91-365d': 'var(--cf-severity-medium)',
    '1y+': 'var(--cf-severity-high)',
  };

  const SOURCE_LABELS: Record<string, string> = {
    zeek_passive: 'Zeek Passive',
    zeek_active: 'Zeek Active',
    corelight: 'Corelight',
    manual_upload: 'Manual Upload',
    active_scan: 'Active Scan',
    unknown: 'Unknown',
  };

  // Prefer the backend-computed total; fall back to summing key_types so
  // percentages remain meaningful if an older server is still running.
  let totalKeys = $derived(
    data?.total_keys ||
    Object.values(data?.key_types ?? {}).reduce((s, v) => s + v, 0),
  );
  let weakCount = $derived(data?.strength_distribution?.weak ?? 0);
  let rootCount = $derived(data?.root_authorized_count ?? 0);
  let sharedCount = $derived(data?.shared_keys_count ?? 0);
  let sharedInstances = $derived(data?.shared_keys_instances ?? 0);
  let unprotectedCount = $derived(data?.protection?.unprotected ?? 0);
  let protectedCount = $derived(data?.protection?.protected ?? 0);

  function pct(part: number): number {
    if (totalKeys === 0) return 0;
    return (part / totalKeys) * 100;
  }

  function pctLabel(part: number): string {
    return pct(part).toFixed(1);
  }

  type Severity = 'critical' | 'high' | 'medium' | 'info';

  function classify(count: number, critFrac: number, highFrac: number): Severity {
    const frac = totalKeys > 0 ? count / totalKeys : 0;
    if (frac >= critFrac) return 'critical';
    if (frac >= highFrac) return 'high';
    if (count > 0) return 'medium';
    return 'info';
  }

  let strengthSegments = $derived.by(() => {
    if (!data) return [] as Array<{ key: string; label: string; count: number; color: string; pct: string }>;
    return STRENGTH_ORDER
      .filter((b) => (data!.strength_distribution?.[b] ?? 0) > 0)
      .map((b) => {
        const count = data!.strength_distribution[b] ?? 0;
        return {
          key: b,
          label: STRENGTH_LABELS[b],
          count,
          color: STRENGTH_COLORS[b],
          pct: pctLabel(count),
        };
      });
  });

  let keyTypeEntries = $derived(
    Object.entries(data?.key_types ?? {}).sort((a, b) => b[1] - a[1])
  );
  let ageEntries = $derived(data?.age_distribution ?? []);
  let sourceEntries = $derived(
    Object.entries(data?.source_breakdown ?? {}).sort((a, b) => b[1] - a[1])
  );
</script>

<div class="ssh-tab">
  {#if loading}
    <div class="tab-loading">Loading SSH key analytics...</div>
  {:else if error}
    <div class="tab-error">{error}</div>
  {:else if data && totalKeys === 0}
    <div class="tab-empty">No SSH key data yet — configure a host-based source (osquery or EDR) to populate this view.</div>
  {:else if data}
    <div class="tab-header">
      <h2>SSH Key Analytics</h2>
      <span class="tab-meta">{totalKeys.toLocaleString()} total keys</span>
    </div>

    <div class="kpi-row">
      <div class="kpi {classify(weakCount, 0.05, 0.01)}">
        <div class="kpi-value">{weakCount.toLocaleString()}</div>
        <div class="kpi-label">Weak keys</div>
        <div class="kpi-sub">{pctLabel(weakCount)}% of total</div>
      </div>
      <div class="kpi {classify(rootCount, 0.10, 0.02)}">
        <div class="kpi-value">{rootCount.toLocaleString()}</div>
        <div class="kpi-label">Root-authorized</div>
        <div class="kpi-sub">{pctLabel(rootCount)}% of total</div>
      </div>
      <div class="kpi {classify(sharedCount, 0.10, 0.02)}">
        <div class="kpi-value">{sharedCount.toLocaleString()}</div>
        <div class="kpi-label">Shared across hosts</div>
        <div class="kpi-sub">{sharedInstances.toLocaleString()} instance{sharedInstances === 1 ? '' : 's'}</div>
      </div>
      <div class="kpi {classify(unprotectedCount, 0.50, 0.20)}">
        <div class="kpi-value">{unprotectedCount.toLocaleString()}</div>
        <div class="kpi-label">Unprotected</div>
        <div class="kpi-sub">{protectedCount.toLocaleString()} protected</div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <h3>Key Strength</h3>
        <span class="panel-meta">Classical strength by (type, size)</span>
      </div>
      {#if strengthSegments.length === 0}
        <div class="panel-empty">No keys to classify.</div>
      {:else}
        <div class="strength-bar">
          {#each strengthSegments as seg (seg.key)}
            <div
              class="strength-seg"
              style="flex: {seg.count}; background: {seg.color};"
              title="{seg.label}: {seg.count.toLocaleString()} ({seg.pct}%)"
            ></div>
          {/each}
        </div>
        <div class="strength-legend">
          {#each strengthSegments as seg (seg.key)}
            <div class="leg-item">
              <span class="leg-dot" style="background: {seg.color};"></span>
              <span class="leg-label">{seg.label}</span>
              <span class="leg-count">{seg.count.toLocaleString()}</span>
              <span class="leg-pct">{seg.pct}%</span>
            </div>
          {/each}
        </div>
      {/if}
    </div>

    <div class="three-panel">
      <div class="panel">
        <div class="panel-head"><h3>Key Types</h3></div>
        {#if keyTypeEntries.length === 0}
          <div class="panel-empty">No keys.</div>
        {:else}
          <div class="row-list">
            {#each keyTypeEntries as [kt, count] (kt)}
              {@const color = KEY_TYPE_COLORS[kt.toLowerCase()] ?? 'var(--cf-text-disabled)'}
              <div class="row">
                <span class="row-dot" style="background: {color};"></span>
                <span class="row-label">{kt.toUpperCase()}</span>
                <div class="row-bar">
                  <div class="row-bar-fill" style="width: {pct(count)}%; background: {color};"></div>
                </div>
                <span class="row-count">{count.toLocaleString()}</span>
              </div>
            {/each}
          </div>
        {/if}
      </div>

      <div class="panel">
        <div class="panel-head"><h3>Key Age</h3></div>
        {#if ageEntries.length === 0}
          <div class="panel-empty">No age data.</div>
        {:else}
          <div class="row-list">
            {#each ageEntries as bucket (bucket.bucket)}
              {@const color = AGE_COLORS[bucket.bucket] ?? 'var(--cf-text-disabled)'}
              <div class="row">
                <span class="row-dot" style="background: {color};"></span>
                <span class="row-label">{bucket.bucket}</span>
                <div class="row-bar">
                  <div class="row-bar-fill" style="width: {pct(bucket.count)}%; background: {color};"></div>
                </div>
                <span class="row-count">{bucket.count.toLocaleString()}</span>
              </div>
            {/each}
          </div>
        {/if}
      </div>

      <div class="panel">
        <div class="panel-head"><h3>Discovery Sources</h3></div>
        {#if sourceEntries.length === 0}
          <div class="panel-empty">No source data.</div>
        {:else}
          <div class="row-list">
            {#each sourceEntries as [src, count] (src)}
              <div class="row">
                <span class="row-dot src-dot"></span>
                <span class="row-label src-label">{SOURCE_LABELS[src] ?? src}</span>
                <div class="row-bar">
                  <div class="row-bar-fill src-fill" style="width: {pct(count)}%;"></div>
                </div>
                <span class="row-count">{count.toLocaleString()}</span>
              </div>
            {/each}
          </div>
        {/if}
      </div>
    </div>
  {/if}
</div>

<style>
  .ssh-tab { padding: 1.5rem; height: 100%; overflow-y: auto; }

  .tab-header { display: flex; align-items: baseline; gap: 1rem; margin-bottom: 1rem; }
  .tab-header h2 { margin: 0; font-size: 1.1rem; font-weight: 700; color: var(--cf-text-primary); }
  .tab-meta { font-size: 0.8rem; color: var(--cf-text-muted); }

  .tab-loading, .tab-error { display: flex; align-items: center; justify-content: center; height: 50vh; color: var(--cf-text-muted); font-size: 0.9rem; }
  .tab-error { color: var(--cf-severity-critical); }
  .tab-empty { display: flex; align-items: center; justify-content: center; height: 50vh; color: var(--cf-text-muted); font-size: 0.9rem; text-align: center; padding: 0 2rem; }

  .kpi-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin-bottom: 16px;
  }
  .kpi {
    background: var(--cf-bg-surface);
    border: 1px solid var(--cf-border);
    border-left: 3px solid var(--cf-text-disabled);
    border-radius: 8px;
    padding: 14px 16px;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .kpi.critical { border-left-color: var(--cf-severity-critical); }
  .kpi.high { border-left-color: var(--cf-severity-high); }
  .kpi.medium { border-left-color: var(--cf-severity-medium); }
  .kpi.info { border-left-color: var(--cf-status-active); }

  .kpi-value {
    font-size: 28px;
    font-weight: 700;
    color: var(--cf-text-primary);
    font-variant-numeric: tabular-nums;
    line-height: 1.1;
  }
  .kpi.critical .kpi-value { color: var(--cf-severity-critical); }
  .kpi.high .kpi-value { color: var(--cf-severity-high); }
  .kpi-label {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--cf-text-muted);
    margin-top: 4px;
  }
  .kpi-sub { font-size: 11px; color: var(--cf-text-muted); }

  .panel {
    background: var(--cf-bg-surface);
    border: 1px solid var(--cf-border);
    border-radius: 8px;
    padding: 14px 16px;
    margin-bottom: 16px;
  }
  .panel-head { display: flex; align-items: baseline; gap: 10px; margin-bottom: 10px; }
  .panel-head h3 {
    margin: 0;
    font-size: 11px;
    font-weight: 600;
    color: var(--cf-text-muted);
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }
  .panel-meta { font-size: 11px; color: var(--cf-text-disabled); }
  .panel-empty { font-size: 12px; color: var(--cf-text-muted); padding: 16px 0; text-align: center; }

  .strength-bar {
    display: flex;
    height: 12px;
    border-radius: 6px;
    overflow: hidden;
    background: var(--cf-bg-elevated);
    gap: 1px;
  }
  .strength-seg { min-width: 2px; }

  .strength-legend {
    display: flex;
    flex-wrap: wrap;
    gap: 14px;
    margin-top: 10px;
  }
  .leg-item { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; }
  .leg-dot { width: 10px; height: 10px; border-radius: 50%; }
  .leg-label { color: var(--cf-text-secondary); }
  .leg-count { color: var(--cf-text-primary); font-weight: 600; font-variant-numeric: tabular-nums; }
  .leg-pct { color: var(--cf-text-muted); font-variant-numeric: tabular-nums; }

  .three-panel {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 16px;
    margin-bottom: 16px;
  }

  .row-list { display: flex; flex-direction: column; gap: 8px; }
  .row {
    display: grid;
    grid-template-columns: 10px 90px 1fr 60px;
    align-items: center;
    gap: 10px;
    font-size: 12px;
  }
  .row-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    display: inline-block;
  }
  .row-label {
    color: var(--cf-text-secondary);
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .src-label { font-family: 'JetBrains Mono', ui-monospace, monospace; font-size: 11px; }
  .row-bar {
    height: 6px;
    background: var(--cf-bg-elevated);
    border-radius: 3px;
    overflow: hidden;
  }
  .row-bar-fill {
    height: 100%;
    border-radius: 3px;
    transition: width 0.2s ease;
  }
  .src-dot { background: var(--cf-accent); }
  .src-fill { background: var(--cf-accent); }
  .row-count {
    text-align: right;
    color: var(--cf-text-primary);
    font-weight: 600;
    font-variant-numeric: tabular-nums;
  }

  @media (max-width: 1100px) {
    .kpi-row { grid-template-columns: repeat(2, 1fr); }
    .three-panel { grid-template-columns: 1fr; }
  }
</style>
