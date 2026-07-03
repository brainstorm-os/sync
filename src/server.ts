/**
 * Blind relay core — the routing + audit + connection-handler orchestration.
 *
 * The wire protocol is the first-byte-tagged channel: `0x00` = JSON control
 * message (subscribe/unsubscribe/catalog/auth), `0x01` = opaque encrypted frame
 * bytes. The relay never parses past the routing header inside the frame.
 *
 * The HTTP/WS server itself (`Bun.serve(...)`) lives in `main.ts`; everything
 * testable lives here, driven through the `ConnectionHandlers` without a real
 * socket.
 *
 * **Relay-blind.** Zero crypto imports on the route path. The SYNC-4b admission
 * is the one auth surface and it lives in `admission.ts`/`entitlement.ts`
 * (reviewed `relay-blind-exempt`); this file only consults an INJECTED
 * `Admission` through a type-only import and calls its methods — no crypto, no
 * DEK, no ciphertext here. See CLAUDE.md.
 */

// relay-blind-exempt: type-only imports of the auth orchestrator. The Admission
// instance is injected (gated mode); this file performs no crypto itself.
import type { Admission, AdmissionResult, AuthMessage } from "./admission";
// relay-blind-exempt-free: the asset wire is a crypto-free content-address
// router (opaque ciphertext keyed by an opaque hash; no key, no decrypt).
import { type AssetGcHooks, AssetWireKind, handleAssetRequest } from "./asset-wire";
import { AuditLog, type AuditSink } from "./audit-log";
import type { Limits } from "./limits";
import { type MeterEvent, MeterKind, type MeterSink } from "./metering";
import { FrameRouter } from "./router";
import type { AccountCatalog } from "./sync/account-catalog";
import type { AssetCas } from "./sync/asset-cas";
import { type SnapshotStore, persistFrame } from "./sync/snapshot-store";

const CONTROL_CHANNEL_BYTE = 0x00;
const FRAME_CHANNEL_BYTE = 0x01;
/** Asset-B3 — the blob plane: content-addressed chunk PUT/GET/HAS, distinct
 *  from the Y.Doc relay's entity-routed fan-out. */
const ASSET_CHANNEL_BYTE = 0x02;
const DEFAULT_AUTH_TIMEOUT_MS = 10_000;

/** WS close codes for gated rejections (4xxx = application range). */
const CLOSE = {
	connRate: 4290,
	authFailed: 4401,
	authTimeout: 4408,
} as const;

export type RelayServerOptions = {
	auditSink?: AuditSink;
	/** Override the connection-id generator for deterministic tests. */
	mintConnId?: () => string;
	now?: () => number;
	/** SYNC-2 — durable store. Absent ⇒ forward-only (SYNC-1 behaviour). */
	store?: SnapshotStore;
	/** Optional sink for fire-and-forget store-error logging (default: ignore). */
	onStoreError?: (error: Error) => void;
	/** SYNC-4a — account catalog (`sender→entityId`, `catalog` query answer). */
	catalog?: AccountCatalog;
	/** Asset-B3 — the content-addressed chunk store (blob plane). Absent ⇒ the
	 *  node has no asset plane (asset frames are dropped); the Y.Doc plane is
	 *  unaffected. */
	assetCas?: AssetCas;
	/** Asset-B6 — the GC hooks (ownership attribution on Put + the Refs report
	 *  sink). Absent ⇒ no GC plane: Refs requests are dropped, Put/Get/Has are
	 *  unaffected. */
	assetGc?: AssetGcHooks;
	/** SYNC-4b — when present, the node is GATED: a connection must complete the
	 *  token + identity handshake before it can emit / subscribe / query. Absent
	 *  ⇒ open admission (dev / forward node), wire path unchanged. */
	admission?: Admission;
	/** SYNC-4b — usage metering sink (connect / ingress / egress byte counts). */
	meter?: MeterSink;
	/** SYNC-5 — abuse caps, rate limits, quotas. Absent ⇒ unbounded (tests). */
	limits?: Limits;
	/** Gated auth deadline; a connection that doesn't authenticate is closed. */
	authTimeoutMs?: number;
	/** Injectable timer for the auth deadline (default native setTimeout). */
	setTimer?: (cb: () => void, ms: number) => unknown;
	clearTimer?: (handle: unknown) => void;
};

export type SubscribeControl = { op: "subscribe"; entityIds: string[] };
export type UnsubscribeControl = { op: "unsubscribe"; entityIds: string[] };
/** SYNC-4a — "list the entities this account has" (cold-restore enumeration). */
export type CatalogControl = { op: "catalog"; account: string };
export type RelayControlMessage =
	| SubscribeControl
	| UnsubscribeControl
	| CatalogControl
	| AuthMessage;

/** The node's reply to a `catalog` query — sent back on the control channel. */
export type CatalogResultMessage = {
	op: "catalog-result";
	account: string;
	entities: Array<{ entityId: string; version: number }>;
};
/** SYNC-4b — gated handshake replies (server→client, control channel). */
export type ChallengeMessage = { op: "challenge"; nonce: string };
export type AuthOkMessage = { op: "auth-ok"; plan: string };
export type AuthErrorMessage = { op: "auth-error"; reason: string };
export type ControlReply =
	| CatalogResultMessage
	| ChallengeMessage
	| AuthOkMessage
	| AuthErrorMessage;

/** Minimal Bun-ws-shaped interface so the core is testable without a socket. */
export interface ServerWebSocketLike {
	send(data: Uint8Array | string): void;
	close(code?: number, reason?: string): void;
	readonly data?: { connId?: string; ip?: string };
}

export type ConnectionHandlers = {
	onOpen(ws: ServerWebSocketLike): string;
	onMessage(ws: ServerWebSocketLike, raw: Uint8Array | string): void;
	onClose(ws: ServerWebSocketLike): void;
};

/** Per-connection state. In open mode a connection is authenticated at open. */
type ConnState = {
	ip: string;
	authenticated: boolean;
	account: string | null;
	sub: string | null;
	plan: string | null;
	nonce: string | null;
	authTimer: unknown;
};

export type RelayCore = {
	router: FrameRouter;
	audit: AuditLog;
	handlers: ConnectionHandlers;
	/** Active connections keyed by connId. Test-visible. */
	connections: Map<string, ServerWebSocketLike>;
	/** Per-connection auth/identity state. Test-visible. */
	connState: Map<string, ConnState>;
};

/** Build the routing + audit + handler core. */
export function createRelayCore(opts: RelayServerOptions = {}): RelayCore {
	const audit = new AuditLog({
		...(opts.auditSink ? { sink: opts.auditSink } : {}),
		...(opts.now ? { now: opts.now } : {}),
	});
	const router = new FrameRouter(audit);
	const connections = new Map<string, ServerWebSocketLike>();
	const connState = new Map<string, ConnState>();
	const mintConnId = opts.mintConnId ?? defaultMintConnId();
	const now = opts.now ?? Date.now;
	const { store, catalog, admission, meter, limits, assetCas, assetGc } = opts;
	const authTimeoutMs = opts.authTimeoutMs ?? DEFAULT_AUTH_TIMEOUT_MS;
	const setTimer = opts.setTimer ?? ((cb, ms) => setTimeout(cb, ms));
	const clearTimer = opts.clearTimer ?? ((h) => clearTimeout(h as ReturnType<typeof setTimeout>));
	const onStoreError = opts.onStoreError ?? (() => undefined);
	const reportStoreError = (error: unknown): void => {
		try {
			onStoreError(error instanceof Error ? error : new Error(String(error)));
		} catch {
			// A logging sink must never break the route path.
		}
	};
	const emit = (event: Omit<MeterEvent, "ts">): void => {
		if (!meter) return;
		try {
			meter({ ts: now(), ...event });
		} catch {
			// A metering sink must never break the route path.
		}
	};

	function send(toConnId: string, frame: Uint8Array): void {
		const ws = connections.get(toConnId);
		if (!ws) return;
		const wire = new Uint8Array(1 + frame.length);
		wire[0] = FRAME_CHANNEL_BYTE;
		wire.set(frame, 1);
		try {
			ws.send(wire);
		} catch {
			// Already-closed sockets can throw; fan-out continues for siblings.
		}
	}

	function sendControl(toConnId: string, message: ControlReply): void {
		const ws = connections.get(toConnId);
		if (!ws) return;
		const body = new TextEncoder().encode(JSON.stringify(message));
		const wire = new Uint8Array(1 + body.length);
		wire[0] = CONTROL_CHANNEL_BYTE;
		wire.set(body, 1);
		try {
			ws.send(wire);
		} catch {
			// closed socket — drop quietly.
		}
	}

	function sendAsset(toConnId: string, frame: Uint8Array): void {
		const ws = connections.get(toConnId);
		if (!ws) return;
		const wire = new Uint8Array(1 + frame.length);
		wire[0] = ASSET_CHANNEL_BYTE;
		wire.set(frame, 1);
		try {
			ws.send(wire);
		} catch {
			// closed socket — drop quietly.
		}
	}

	/**
	 * Asset-B3/B6 — serve one blob-plane request (HAS / PUT / GET / REFS)
	 * against the CAS + GC hooks and reply point-to-point on the asset channel
	 * (no fan-out — it's request/response, not pub/sub). Gated by the same
	 * admission as frames, and the GC context carries the PROVEN account so a
	 * gated ref report / Put attribution can't be forged. A PUT is metered as
	 * ingress, a served GET as egress. A malformed request is dropped (never
	 * crashes the connection).
	 */
	function handleAsset(connId: string, state: ConnState, body: Uint8Array): void {
		if (limits?.frameTooLarge(body.length)) return;
		if (admission && !state.authenticated) return;
		if (!assetCas) return; // no asset plane configured
		void handleAssetRequest(assetCas, body, {
			account: state.account,
			...(assetGc ? { gc: assetGc } : {}),
		})
			.then(({ kind, response, meteredBytes }) => {
				sendAsset(connId, response);
				if (meteredBytes > 0) {
					emit({
						kind: kind === AssetWireKind.Put ? MeterKind.Ingress : MeterKind.Egress,
						account: state.account,
						sub: state.sub,
						plan: state.plan,
						bytes: meteredBytes,
					});
				}
			})
			.catch(reportStoreError);
	}

	function disarmAuthTimer(state: ConnState): void {
		if (state.authTimer !== null) {
			clearTimer(state.authTimer);
			state.authTimer = null;
		}
	}

	/** Resolve a successful admission onto the connection + meter the connect. */
	function applyAdmission(connId: string, state: ConnState, result: AdmissionResult): void {
		if (!result.admitted) return;
		state.authenticated = true;
		state.account = result.account;
		state.sub = result.sub;
		state.plan = result.plan;
		state.nonce = null;
		disarmAuthTimer(state);
		emit({
			kind: MeterKind.Connect,
			account: result.account,
			sub: result.sub,
			plan: result.plan,
			bytes: 0,
		});
		sendControl(connId, { op: "auth-ok", plan: result.plan });
	}

	const handlers: ConnectionHandlers = {
		onOpen(ws) {
			const connId = mintConnId();
			const ip = (ws as { data?: { ip?: string } }).data?.ip ?? "?";
			(ws as { data?: { connId?: string; ip?: string } }).data = { connId, ip };

			if (limits && !limits.allowConnection(ip)) {
				try {
					ws.close(CLOSE.connRate, "connection rate");
				} catch {
					// already closing
				}
				return connId;
			}

			connections.set(connId, ws);
			const state: ConnState = {
				ip,
				authenticated: !admission,
				account: null,
				sub: null,
				plan: null,
				nonce: null,
				authTimer: null,
			};
			connState.set(connId, state);

			if (admission) {
				const nonce = admission.createChallenge();
				state.nonce = nonce;
				state.authTimer = setTimer(() => {
					const s = connState.get(connId);
					if (s && !s.authenticated) {
						try {
							ws.close(CLOSE.authTimeout, "auth timeout");
						} catch {
							// already closing
						}
					}
				}, authTimeoutMs);
				sendControl(connId, { op: "challenge", nonce });
			}
			return connId;
		},

		onMessage(ws, raw) {
			const connId = (ws as { data?: { connId?: string } }).data?.connId;
			if (!connId) return;
			const state = connState.get(connId);
			if (!state) return;
			const bytes = normalizeIncoming(raw);
			if (!bytes || bytes.length < 1) return;
			if (limits && !limits.allowMessage(connId, bytes.length)) return;

			const channel = bytes[0];
			if (channel === FRAME_CHANNEL_BYTE) {
				handleFrame(connId, state, bytes.subarray(1));
				return;
			}
			if (channel === CONTROL_CHANNEL_BYTE) {
				if (limits?.controlTooLarge(bytes.length - 1)) return;
				handleControl(ws, connId, state, bytes.subarray(1));
				return;
			}
			if (channel === ASSET_CHANNEL_BYTE) {
				handleAsset(connId, state, bytes.subarray(1));
				return;
			}
			// Unknown channel byte — drop silently (forward-compat).
		},

		onClose(ws) {
			const connId = (ws as { data?: { connId?: string } }).data?.connId;
			if (!connId) return;
			const state = connState.get(connId);
			if (state) disarmAuthTimer(state);
			router.dropConnection(connId);
			connections.delete(connId);
			connState.delete(connId);
			limits?.forgetConnection(connId);
		},
	};

	function handleFrame(connId: string, state: ConnState, frame: Uint8Array): void {
		if (limits?.frameTooLarge(frame.length)) return;
		// Gated: only an authenticated connection may emit.
		if (admission && !state.authenticated) return;

		const result = router.route(connId, frame, send, (header) => {
			// Gated: a connection may only emit as the wire account it proved.
			if (admission && header.sender !== state.account) return false;
			// Per-account frame quota (gated; account is the proven sender).
			if (limits && state.account && !limits.allowAccountFrame(state.account)) return false;
			return true;
		});
		if (!result.header || result.dropped !== 0) return;

		emit({
			kind: MeterKind.Ingress,
			account: state.account ?? result.header.sender,
			sub: state.sub,
			plan: state.plan,
			bytes: frame.length,
			entityId: result.header.entityId,
		});

		if (store) {
			const persisted = new Uint8Array(frame);
			void persistFrame(store, result.header.entityId, result.header.kind, persisted).catch(
				reportStoreError,
			);
		}
		if (catalog) {
			void catalog.record(result.header.sender, result.header.entityId).catch(reportStoreError);
		}
	}

	function handleControl(
		ws: ServerWebSocketLike,
		connId: string,
		state: ConnState,
		body: Uint8Array,
	): void {
		const message = parseControl(body);
		if (!message) return;

		// Gated + unauthenticated: ONLY `auth` is honoured.
		if (admission && !state.authenticated) {
			if (message.op !== "auth") return;
			void admission
				.verify(message, state.nonce ?? "")
				.then((result) => {
					if (!connState.has(connId)) return; // closed mid-verify
					if (result.admitted) {
						applyAdmission(connId, state, result);
					} else {
						sendControl(connId, { op: "auth-error", reason: result.reason });
						try {
							ws.close(CLOSE.authFailed, "auth failed");
						} catch {
							// already closing
						}
					}
				})
				.catch(() => {
					try {
						ws.close(CLOSE.authFailed, "auth error");
					} catch {
						// already closing
					}
				});
			return;
		}

		if (message.op === "auth") return; // already authenticated / open mode
		if (message.op === "subscribe") {
			for (const entityId of message.entityIds) {
				if (limits && !limits.subAllowed(router.connectionEntities(connId).length)) break;
				router.subscribe(connId, entityId);
				if (store) backfill(store, entityId, connId, send, emit, state, reportStoreError);
			}
			return;
		}
		if (message.op === "unsubscribe") {
			for (const entityId of message.entityIds) router.unsubscribe(connId, entityId);
			return;
		}
		// catalog — gated: force the proven account (closes the metadata leak).
		if (!catalog) return;
		const account = admission ? (state.account ?? message.account) : message.account;
		answerCatalog(catalog, store, account, connId, sendControl, reportStoreError);
	}

	return { router, audit, handlers, connections, connState };
}

/**
 * SYNC-2 — replay durable `wraps ++ snapshot ++ tail` to one connection, and
 * meter the egress bytes for the connection's account (gated). Fire-and-forget.
 */
function backfill(
	store: SnapshotStore,
	entityId: string,
	connId: string,
	send: (toConnId: string, frame: Uint8Array) => void,
	emit: (event: Omit<MeterEvent, "ts">) => void,
	state: ConnState,
	reportError: (error: unknown) => void,
): void {
	void store.readBackfill(entityId).then(({ frames }) => {
		let bytes = 0;
		for (const frame of frames) {
			try {
				send(connId, frame);
				bytes += frame.length;
			} catch {
				// Recipient socket already closed — stop quietly.
			}
		}
		if (bytes > 0) {
			emit({
				kind: MeterKind.Egress,
				account: state.account,
				sub: state.sub,
				plan: state.plan,
				bytes,
				entityId,
			});
		}
	}, reportError);
}

/** SYNC-4a — answer a `catalog` query on the control channel. Fire-and-forget. */
function answerCatalog(
	catalog: AccountCatalog,
	store: SnapshotStore | undefined,
	account: string,
	connId: string,
	sendControl: (toConnId: string, message: ControlReply) => void,
	reportError: (error: unknown) => void,
): void {
	void (async () => {
		const entityIds = await catalog.list(account);
		const entities = await Promise.all(
			entityIds.map(async (entityId) => ({
				entityId,
				version: (store ? await store.latestVersion(entityId) : null) ?? 0,
			})),
		);
		sendControl(connId, { op: "catalog-result", account, entities });
	})().catch(reportError);
}

function parseControl(body: Uint8Array): RelayControlMessage | null {
	try {
		const parsed = JSON.parse(new TextDecoder().decode(body)) as unknown;
		if (!parsed || typeof parsed !== "object") return null;
		const v = parsed as Record<string, unknown>;
		if (v.op === "auth") {
			return typeof v.token === "string" &&
				v.token.length > 0 &&
				typeof v.account === "string" &&
				v.account.length > 0 &&
				typeof v.sig === "string" &&
				v.sig.length > 0
				? { op: "auth", token: v.token, account: v.account, sig: v.sig }
				: null;
		}
		if (v.op === "catalog") {
			return typeof v.account === "string" && v.account.length > 0
				? { op: "catalog", account: v.account }
				: null;
		}
		if (v.op !== "subscribe" && v.op !== "unsubscribe") return null;
		if (!Array.isArray(v.entityIds)) return null;
		const entityIds = v.entityIds.filter((e): e is string => typeof e === "string" && e.length > 0);
		return { op: v.op, entityIds };
	} catch {
		return null;
	}
}

function normalizeIncoming(raw: Uint8Array | string): Uint8Array | null {
	if (raw instanceof Uint8Array) return raw;
	// A plain string body has no channel prefix — the wire protocol is
	// binary-only; drop it.
	return null;
}

function defaultMintConnId(): () => string {
	let counter = 0;
	return () => {
		counter += 1;
		const random = Math.random().toString(36).slice(2, 8);
		return `c${counter}_${random}`;
	};
}

export const WIRE_CHANNELS = { CONTROL_CHANNEL_BYTE, FRAME_CHANNEL_BYTE } as const;
