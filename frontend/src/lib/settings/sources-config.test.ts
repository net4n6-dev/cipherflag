import { describe, it, expect } from 'vitest';
import fixture from '$lib/testdata/sources-config.json';
import { parseSourcesConfig } from './sources-config';

// The other half of a contract test with
// internal/api/handler/config_sources_test.go, which checks that
// GET /config/sources returns exactly this fixture. The Settings → Sources
// page read fields the API no longer sent, kept its hard-coded defaults, and
// a Save wrote them over the real Zeek config.
describe('parseSourcesConfig', () => {
	it('reads the response the backend actually returns', () => {
		expect(parseSourcesConfig(fixture)).toEqual({
			zeek: {
				enabled: false,
				log_dir: '/data/zeek/current',
				poll_interval_seconds: 45,
				network_interface: 'eth1'
			}
		});
	});

	it('rejects the response without a zeek object (the shape that broke the page)', () => {
		const { zeek: _zeek, ...withoutZeek } = fixture;
		expect(() => parseSourcesConfig(withoutZeek)).toThrow(/zeek/);
	});

	it('rejects a field of the wrong type instead of defaulting it', () => {
		const bad = { ...fixture, zeek: { ...fixture.zeek, enabled: 'false' } };
		expect(() => parseSourcesConfig(bad)).toThrow(/zeek\.enabled/);
	});

	it('rejects a body that is not an object', () => {
		expect(() => parseSourcesConfig(null)).toThrow();
		expect(() => parseSourcesConfig([])).toThrow();
	});
});
