import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/svelte';
import Sidebar from './Sidebar.svelte';

describe('Sidebar', () => {
  it('renders the CE-native nav items', () => {
    const { getByText } = render(Sidebar, { props: { currentPath: '/' } });
    for (const label of ['Dashboard', 'Certificates', 'PKI Constellation', 'Analytics', 'Reports', 'Statistics', 'Upload', 'Settings']) {
      expect(getByText(label)).toBeTruthy();
    }
  });

  it('shows the CE badge, not EE', () => {
    const { getByText, queryByText } = render(Sidebar, { props: { currentPath: '/' } });
    expect(getByText('CE')).toBeTruthy();
    expect(queryByText('EE')).toBeNull();
  });

  it('marks the active route', () => {
    const { container } = render(Sidebar, { props: { currentPath: '/certificates' } });
    const active = container.querySelector('.cf-nav-item.cf-nav-item-active');
    expect(active?.textContent).toContain('Certificates');
  });

  it('reflects collapsed state', () => {
    const { container } = render(Sidebar, { props: { currentPath: '/', collapsed: true } });
    expect(container.querySelector('.cf-sidebar[data-collapsed="true"]')).toBeTruthy();
  });
});
