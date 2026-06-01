import { describe, it, expect, vi } from 'vitest';
import { render } from '@testing-library/svelte';

const { getSSH } = vi.hoisted(() => ({ getSSH: vi.fn() }));
vi.mock('$lib/api', () => ({ api: { getSSHKeyAnalytics: getSSH } }));

import SSHAnalyticsTab from './SSHAnalyticsTab.svelte';

const sample = {
	key_types: { rsa: 3, ed25519: 2 },
	age_distribution: [{ bucket: '0-30d', count: 2 }],
	protection: { protected: 4, unprotected: 1 },
	root_authorized_count: 1,
	strength_distribution: { weak: 1, strong: 4 },
	shared_keys_count: 0,
	shared_keys_instances: 0,
	source_breakdown: { osquery: 5 },
	total_keys: 5,
};

describe('SSHAnalyticsTab', () => {
	it('renders analytics when data is present', async () => {
		getSSH.mockResolvedValue(sample);
		const { findByText } = render(SSHAnalyticsTab);
		expect(await findByText('SSH Key Analytics')).toBeTruthy();
		expect(await findByText('5 total keys')).toBeTruthy();
	});

	it('shows the empty-state when there are no keys', async () => {
		getSSH.mockResolvedValue({
			key_types: {},
			age_distribution: [],
			protection: { protected: 0, unprotected: 0 },
			root_authorized_count: 0,
			strength_distribution: {},
			shared_keys_count: 0,
			shared_keys_instances: 0,
			source_breakdown: {},
			total_keys: 0,
		});
		const { findByText } = render(SSHAnalyticsTab);
		expect(await findByText(/configure a host-based source/i)).toBeTruthy();
	});
});
