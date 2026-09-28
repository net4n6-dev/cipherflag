import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/svelte';
import Sidebar from './Sidebar.svelte';

describe('Sidebar', () => {
  it('renders the CE-native nav items', () => {
    const { getByText } = render(Sidebar, { props: { currentPath: '/' } });
    for (const label of ['Dashboard', 'Certificates', 'PKI Constellation', 'Analytics', 'Reports', 'Statistics', 'Settings']) {
      expect(getByText(label)).toBeTruthy();
    }
  });

  // PCAP upload is an Enterprise Edition feature; CE has no PCAP backend, so
  // the page could never work and is not offered.
  it('does not offer the EE-only PCAP upload page', () => {
    const { queryByText, container } = render(Sidebar, { props: { currentPath: '/' } });
    expect(queryByText('Upload')).toBeNull();
    expect(queryByText('Ingest')).toBeNull();
    expect(container.querySelector('a[href="/upload"]')).toBeNull();
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
