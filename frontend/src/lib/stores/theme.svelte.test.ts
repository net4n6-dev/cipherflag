import { describe, it, expect, beforeEach, vi } from 'vitest';
import { themeStore, setTheme } from './theme.svelte';

describe('theme store', () => {
  beforeEach(() => {
    // Node 25 exposes a native global localStorage that lacks .clear() unless
    // --localstorage-file is provided; replace it with an in-memory stub so
    // tests are hermetic regardless of Node version.
    const store: Record<string, string> = {};
    vi.stubGlobal('localStorage', {
      getItem: (k: string) => store[k] ?? null,
      setItem: (k: string, v: string) => { store[k] = v; },
      removeItem: (k: string) => { delete store[k]; },
      clear: () => { for (const k in store) delete store[k]; },
    });
    // jsdom does not implement matchMedia; stub it to return dark (matches: false).
    vi.stubGlobal('matchMedia', (_q: string) => ({ matches: false, addEventListener: vi.fn() }));
    document.documentElement.removeAttribute('data-theme');
  });

  it('setTheme(light) sets data-theme=light and persists', () => {
    setTheme('light');
    expect(themeStore.mode).toBe('light');
    expect(themeStore.effective).toBe('light');
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
    expect(localStorage.getItem('cf-theme')).toBe('light');
  });

  it('setTheme(dark) removes data-theme attribute', () => {
    setTheme('light');
    setTheme('dark');
    expect(themeStore.mode).toBe('dark');
    expect(document.documentElement.hasAttribute('data-theme')).toBe(false);
    expect(localStorage.getItem('cf-theme')).toBe('dark');
  });

  it('setTheme(system) persists system and resolves an effective theme', () => {
    setTheme('system');
    expect(themeStore.mode).toBe('system');
    expect(['dark', 'light']).toContain(themeStore.effective);
    expect(localStorage.getItem('cf-theme')).toBe('system');
  });
});
