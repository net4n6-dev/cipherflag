/**
 * Theme store — manages dark/light/system preference.
 * - Preference stored in localStorage under 'cf-theme'
 * - 'system' honors prefers-color-scheme media query
 * - Writes data-theme attribute on <html> (absent = dark, "light" = light)
 */

export type ThemeMode = 'dark' | 'light' | 'system';
export type EffectiveTheme = 'dark' | 'light';

const STORAGE_KEY = 'cf-theme';

interface ThemeStore {
  mode: ThemeMode;
  effective: EffectiveTheme;
}

export const themeStore: ThemeStore = $state({
  mode: 'system',
  effective: 'dark',
});

function computeEffective(mode: ThemeMode): EffectiveTheme {
  if (mode === 'system') {
    if (typeof window === 'undefined') return 'dark';
    return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }
  return mode;
}

function applyTheme(effective: EffectiveTheme): void {
  if (typeof document === 'undefined') return;
  if (effective === 'light') {
    document.documentElement.setAttribute('data-theme', 'light');
  } else {
    document.documentElement.removeAttribute('data-theme');
  }
}

export function setTheme(mode: ThemeMode): void {
  themeStore.mode = mode;
  themeStore.effective = computeEffective(mode);
  if (typeof window !== 'undefined') {
    localStorage.setItem(STORAGE_KEY, mode);
  }
  applyTheme(themeStore.effective);
}

export function initTheme(): void {
  let mode: ThemeMode = 'system';
  if (typeof window !== 'undefined') {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === 'dark' || stored === 'light' || stored === 'system') {
      mode = stored;
    }
  }
  themeStore.mode = mode;
  themeStore.effective = computeEffective(mode);
  applyTheme(themeStore.effective);

  if (typeof window !== 'undefined') {
    const mq = window.matchMedia('(prefers-color-scheme: light)');
    mq.addEventListener('change', () => {
      if (themeStore.mode === 'system') {
        themeStore.effective = computeEffective('system');
        applyTheme(themeStore.effective);
      }
    });
  }
}
