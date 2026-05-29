// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import FindingSource from './FindingSource.svelte';

describe('FindingSource', () => {
	it('renders a source link for an https url', () => {
		render(FindingSource, { sourceUrl: 'https://endoflife.date/openssl' });
		const link = screen.getByRole('link', { name: /source/i });
		expect(link).toHaveAttribute('href', 'https://endoflife.date/openssl');
		expect(link).toHaveAttribute('target', '_blank');
		expect(link).toHaveAttribute('rel', expect.stringContaining('noopener'));
	});
	it('renders a "manually curated" indicator for the literal "manual"', () => {
		render(FindingSource, { sourceUrl: 'manual' });
		expect(screen.getByText(/manually curated/i)).toBeInTheDocument();
		expect(screen.queryByRole('link')).toBeNull();
	});
	it('renders nothing when sourceUrl is absent', () => {
		const { container } = render(FindingSource, { sourceUrl: undefined });
		expect(container.textContent?.trim()).toBe('');
	});
});
