// SSE live-update client. Connects to /api/v1/events/stream (same-origin, cookie
// auth) and dispatches typed events to registered callbacks. Singleton module
// state; Svelte 5 runes.

// ── Event payload types (mirror the backend pg_notify payloads) ──────────────

export interface AssetDiscoveredEvent {
	asset_type: string;
	asset_id: string;
	host_id?: string;
	source: string;
}

export interface AssetScoredEvent {
	asset_type: string;
	asset_id: string;
	grade: string;
	risk_score: number;
	pqc_status: string;
}

export interface ScanProgressEvent {
	scan_id: string;
	status: string;
}

export interface ScanCompletedEvent {
	scan_id: string;
	status: string;
	findings_count: number;
	duration_ms?: number;
}

export interface BriefingUpdatedEvent {
	item_count: number;
	max_severity: string;
}

export interface ExternalSourceScanCompletedEvent {
	source_id: string;
	kind: string;
	status: 'ok' | 'partial' | 'error';
	last_scan_at: string; // ISO8601
}

// ── Reactive state ──────────────────────────────────────────────────────────

export const sseState: { connected: boolean; reconnecting: boolean } = $state({
	connected: false,
	reconnecting: false,
});

// ── Callback registrations ──────────────────────────────────────────────────

type Callback<T> = (data: T) => void;
type Unsubscribe = () => void;

const assetDiscoveredCbs = new Set<Callback<AssetDiscoveredEvent>>();
const assetScoredCbs = new Set<Callback<AssetScoredEvent>>();
const scanProgressCbs = new Set<Callback<ScanProgressEvent>>();
const scanCompletedCbs = new Set<Callback<ScanCompletedEvent>>();
const briefingUpdatedCbs = new Set<Callback<BriefingUpdatedEvent>>();
const externalSourceScanCompletedCbs = new Set<Callback<ExternalSourceScanCompletedEvent>>();

export function onAssetDiscovered(cb: Callback<AssetDiscoveredEvent>): Unsubscribe {
	assetDiscoveredCbs.add(cb);
	return () => { assetDiscoveredCbs.delete(cb); };
}

export function onAssetScored(cb: Callback<AssetScoredEvent>): Unsubscribe {
	assetScoredCbs.add(cb);
	return () => { assetScoredCbs.delete(cb); };
}

export function onScanProgress(cb: Callback<ScanProgressEvent>): Unsubscribe {
	scanProgressCbs.add(cb);
	return () => { scanProgressCbs.delete(cb); };
}

export function onScanCompleted(cb: Callback<ScanCompletedEvent>): Unsubscribe {
	scanCompletedCbs.add(cb);
	return () => { scanCompletedCbs.delete(cb); };
}

export function onBriefingUpdated(cb: Callback<BriefingUpdatedEvent>): Unsubscribe {
	briefingUpdatedCbs.add(cb);
	return () => { briefingUpdatedCbs.delete(cb); };
}

export function onExternalSourceScanCompleted(cb: Callback<ExternalSourceScanCompletedEvent>): Unsubscribe {
	externalSourceScanCompletedCbs.add(cb);
	return () => { externalSourceScanCompletedCbs.delete(cb); };
}

// ── Connection management ───────────────────────────────────────────────────

let eventSource: EventSource | null = null;
let reconnectAttempts = 0;
let reconnectTimer: ReturnType<typeof setTimeout> | undefined;
let heartbeatTimer: ReturnType<typeof setTimeout> | undefined;
let visibilityTimer: ReturnType<typeof setTimeout> | undefined;

const MAX_BACKOFF_MS = 30_000;
const HEARTBEAT_TIMEOUT_MS = 60_000;
const VISIBILITY_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

function resetHeartbeat(): void {
	clearTimeout(heartbeatTimer);
	heartbeatTimer = setTimeout(() => {
		// No event for 60s — force reconnect
		closeEventSource();
		scheduleReconnect();
	}, HEARTBEAT_TIMEOUT_MS);
}

function dispatchToCallbacks(type: string, data: unknown): void {
	switch (type) {
		case 'asset.discovered':
			assetDiscoveredCbs.forEach((cb) => cb(data as AssetDiscoveredEvent));
			break;
		case 'asset.scored':
			assetScoredCbs.forEach((cb) => cb(data as AssetScoredEvent));
			break;
		case 'scan.progress':
			scanProgressCbs.forEach((cb) => cb(data as ScanProgressEvent));
			break;
		case 'scan.completed':
			scanCompletedCbs.forEach((cb) => cb(data as ScanCompletedEvent));
			break;
		case 'briefing.updated':
			briefingUpdatedCbs.forEach((cb) => cb(data as BriefingUpdatedEvent));
			break;
		case 'external_source.scan.completed':
			externalSourceScanCompletedCbs.forEach((cb) => cb(data as ExternalSourceScanCompletedEvent));
			break;
	}
}

function createEventSource(): void {
	if (eventSource) return;

	eventSource = new EventSource('/api/v1/events/stream');

	eventSource.onopen = () => {
		sseState.connected = true;
		sseState.reconnecting = false;
		reconnectAttempts = 0;
		resetHeartbeat();
	};

	eventSource.onerror = () => {
		sseState.connected = false;
		closeEventSource();
		scheduleReconnect();
	};

	// Register typed event listeners
	const eventTypes = [
		'asset.discovered',
		'asset.scored',
		'scan.progress',
		'scan.completed',
		'briefing.updated',
		'external_source.scan.completed',
		'heartbeat',
	];

	for (const type of eventTypes) {
		eventSource.addEventListener(type, (e: MessageEvent) => {
			resetHeartbeat();
			if (type === 'heartbeat') return;
			try {
				const data = JSON.parse(e.data);
				dispatchToCallbacks(type, data);
			} catch {
				// Ignore malformed events
			}
		});
	}
}

function closeEventSource(): void {
	clearTimeout(heartbeatTimer);
	if (eventSource) {
		eventSource.close();
		eventSource = null;
	}
	sseState.connected = false;
}

function scheduleReconnect(): void {
	if (reconnectTimer) return;

	sseState.reconnecting = true;
	const backoff = Math.min(
		1000 * Math.pow(2, reconnectAttempts),
		MAX_BACKOFF_MS,
	);
	reconnectAttempts++;

	reconnectTimer = setTimeout(() => {
		reconnectTimer = undefined;
		createEventSource();
	}, backoff);
}

// ── Tab visibility handling ─────────────────────────────────────────────────

function handleVisibilityChange(): void {
	if (typeof document === 'undefined') return;

	if (document.hidden) {
		// Start 5-minute timer to disconnect
		visibilityTimer = setTimeout(() => {
			closeEventSource();
		}, VISIBILITY_TIMEOUT_MS);
	} else {
		// Tab focused — cancel timer and reconnect if needed
		clearTimeout(visibilityTimer);
		if (!eventSource && !reconnectTimer) {
			createEventSource();
		}
	}
}

// ── Public API ──────────────────────────────────────────────────────────────

export function connect(): void {
	if (typeof window === 'undefined') return;
	createEventSource();
	document.addEventListener('visibilitychange', handleVisibilityChange);
}

export function disconnect(): void {
	clearTimeout(reconnectTimer);
	clearTimeout(visibilityTimer);
	reconnectTimer = undefined;
	closeEventSource();
	if (typeof document !== 'undefined') {
		document.removeEventListener('visibilitychange', handleVisibilityChange);
	}
	sseState.reconnecting = false;
}
