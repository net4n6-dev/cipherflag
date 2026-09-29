// The editable parts of GET /api/v1/config/sources that Settings → Sources
// shows and saves back. The response is checked, not trusted: a missing or
// mistyped field throws, so the page reports the problem instead of showing
// hard-coded defaults that a Save would then write over the real config.
// Only the Zeek table is editable here; other sections of the response are
// ignored. The shape is pinned by src/lib/testdata/sources-config.json, which the
// backend's handler test also checks against.

export interface SourcesConfig {
	zeek: { enabled: boolean; log_dir: string; poll_interval_seconds: number; network_interface: string };
}

type FieldType = 'boolean' | 'string' | 'number';

function object(value: unknown, path: string): Record<string, unknown> {
	if (typeof value !== 'object' || value === null || Array.isArray(value)) {
		throw new Error(`sources config: ${path} is not an object`);
	}
	return value as Record<string, unknown>;
}

function fields<T>(value: unknown, path: string, spec: Record<string, FieldType>): T {
	const obj = object(value, path);
	const out: Record<string, unknown> = {};
	for (const [key, type] of Object.entries(spec)) {
		if (typeof obj[key] !== type) {
			throw new Error(`sources config: ${path}.${key} is ${typeof obj[key]}, want ${type}`);
		}
		out[key] = obj[key];
	}
	return out as T;
}

export function parseSourcesConfig(body: unknown): SourcesConfig {
	const root = object(body, 'response');
	return {
		zeek: fields(root.zeek, 'zeek', {
			enabled: 'boolean',
			log_dir: 'string',
			poll_interval_seconds: 'number',
			network_interface: 'string'
		})
	};
}
