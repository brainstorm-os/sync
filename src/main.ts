/**
 * brainstorm-sync node — deployable entrypoint.
 *
 * Wraps the blind relay core (`server.ts`) in a `Bun.serve` WebSocket server:
 *   - `GET /healthz`            → liveness ("ok")
 *   - WebSocket upgrade on `/`  → a relay connection
 *
 * Env config:
 *   PORT             listen port (default 7780)
 *   AUDIT_LOG_PATH   optional NDJSON audit sink (routing metadata only — never
 *                    ciphertext; see audit-log.ts / CLAUDE.md)
 *   LOG_LEVEL        "info" (default) | "debug"
 *   STORAGE_BACKEND  SYNC-3 — "local" | "s3" (else inferred: S3_BUCKET ⇒ s3,
 *                    STORAGE_DIR ⇒ local, neither ⇒ forward-only)
 *   STORAGE_DIR      local durable root · S3_BUCKET / S3_ENDPOINT / S3_REGION /
 *                    S3_ACCESS_KEY_ID / S3_SECRET_ACCESS_KEY / S3_PREFIX
 *   ENTITLEMENT_KEYS SYNC-4b — JSON `{kid: base64url-pubkey}`. PRESENT ⇒ the
 *                    node is GATED (token + identity handshake required).
 *   REQUIRE_FEATURE  SYNC-4b — gate admission on a token `features` flag.
 *   AUTH_TIMEOUT_MS  SYNC-4b — gated auth deadline (default 10000).
 *   METERING_LOG_PATH SYNC-4b — NDJSON usage-metering sink (connect/ingress/egress).
 *   LIMITS_DISABLED  SYNC-5 — "1" turns OFF abuse caps / rate limits (default on).
 *   ASSET_GC_GRACE_MS          Asset-B6 — mark → delete grace window (default 30d).
 *   ASSET_GC_RETENTION_MS      Asset-B6 — device last-seen retention (default 90d).
 *   ASSET_GC_SWEEP_INTERVAL_MS Asset-B6 — periodic sweep interval; unset/0 ⇒ no
 *                              automatic sweep (ref tracking still on; an ops
 *                              runner can invoke `AssetGc.sweep()` explicitly).
 *
 * Graceful shutdown: SIGTERM/SIGINT stop accepting new connections, close the
 * server, and exit.
 */

import { appendFile } from "node:fs/promises";
import { join } from "node:path";
import { Admission } from "./admission";
import { buildVerifierKeySet } from "./entitlement";
import { DEFAULT_LIMITS, Limits, type LimitsConfig } from "./limits";
import type { MeterEvent } from "./metering";
import { type RelayCore, createRelayCore } from "./server";
import type { AccountCatalog } from "./sync/account-catalog";
import type { AssetCas } from "./sync/asset-cas";
import { AssetGc, DEFAULT_GRACE_MS, DEFAULT_RETENTION_MS } from "./sync/asset-gc";
import { BunS3Bucket, type S3BucketConfig } from "./sync/bun-s3-bucket";
import { FileAccountCatalog } from "./sync/file-account-catalog";
import { FileAssetCas } from "./sync/file-asset-cas";
import { FileRefLedger } from "./sync/file-ref-ledger";
import { FileSnapshotStore } from "./sync/file-snapshot-store";
import { ObjectAssetCas } from "./sync/object-asset-cas";
import { ObjectRefLedger } from "./sync/object-ref-ledger";
import { ObjectAccountCatalog, ObjectSnapshotStore } from "./sync/object-store";
import type { RefLedger } from "./sync/ref-ledger";
import type { SnapshotStore } from "./sync/snapshot-store";

type BunServer = { stop(closeActiveConnections?: boolean): void; readonly port: number };
type BunRuntime = {
	serve(opts: unknown): BunServer;
};

/** SYNC-4b — gated-admission config. Null ⇒ open admission (dev / forward). */
export type EntitlementConfig = {
	/** kid → base64url Ed25519 public key (the bundled verifier keyset). */
	keys: Record<string, string>;
	requiredFeature: string | null;
	authTimeoutMs: number;
};

/**
 * SYNC-3 — pluggable storage provider. One wire protocol, swappable backend:
 *   - `none`  — forward-only (SYNC-1): persists nothing, backfills nothing.
 *   - `local` — durable on-disk snapshot+tail (the OQ-SYNC-1 local default /
 *               self-hosted single-box).
 *   - `s3`    — object storage (our managed bucket, or a self-hoster's
 *               bring-your-own S3/R2/MinIO bucket).
 */
export type StorageProvider =
	| { kind: "none" }
	| { kind: "local"; dir: string }
	| { kind: "s3"; s3: S3BucketConfig };

/** Asset-B6 — GC windows + sweep scheduling. Ref tracking is always on when a
 *  durable asset plane exists; only the periodic sweep is opt-in. */
export type AssetGcConfig = {
	graceMs: number;
	retentionMs: number;
	/** Null ⇒ no automatic sweep (explicit `AssetGc.sweep()` only). */
	sweepIntervalMs: number | null;
};

export type Config = {
	port: number;
	auditLogPath: string | null;
	storage: StorageProvider;
	/** SYNC-4b — present ⇒ gated admission. */
	entitlement: EntitlementConfig | null;
	/** SYNC-4b — NDJSON metering sink path, or null. */
	meteringLogPath: string | null;
	/** SYNC-5 — abuse caps / rate limits, or null to disable. */
	limits: LimitsConfig | null;
	/** Asset-B6 — GC windows + sweep interval. */
	assetGc: AssetGcConfig;
	debug: boolean;
};

function readEntitlement(env: Record<string, string | undefined>): EntitlementConfig | null {
	const raw = env.ENTITLEMENT_KEYS;
	if (!raw || raw.length === 0) return null;
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch {
		throw new Error("ENTITLEMENT_KEYS: not valid JSON");
	}
	if (!parsed || typeof parsed !== "object")
		throw new Error("ENTITLEMENT_KEYS: expected an object");
	const keys: Record<string, string> = {};
	for (const [kid, value] of Object.entries(parsed as Record<string, unknown>)) {
		if (typeof value !== "string") throw new Error(`ENTITLEMENT_KEYS: ${kid} must be a string`);
		keys[kid] = value;
	}
	if (Object.keys(keys).length === 0)
		throw new Error("ENTITLEMENT_KEYS: at least one key required");
	const timeout = Number(env.AUTH_TIMEOUT_MS);
	return {
		keys,
		requiredFeature:
			env.REQUIRE_FEATURE && env.REQUIRE_FEATURE.length > 0 ? env.REQUIRE_FEATURE : null,
		authTimeoutMs: Number.isInteger(timeout) && timeout > 0 ? timeout : 10_000,
	};
}

function readStorageProvider(env: Record<string, string | undefined>): StorageProvider {
	const backend = env.STORAGE_BACKEND?.toLowerCase();
	const wantsS3 = backend === "s3" || (!backend && Boolean(env.S3_BUCKET));
	if (wantsS3) {
		const bucket = env.S3_BUCKET;
		const accessKeyId = env.S3_ACCESS_KEY_ID;
		const secretAccessKey = env.S3_SECRET_ACCESS_KEY;
		if (!bucket || !accessKeyId || !secretAccessKey) {
			throw new Error(
				"STORAGE_BACKEND=s3 requires S3_BUCKET, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY",
			);
		}
		return {
			kind: "s3",
			s3: {
				bucket,
				accessKeyId,
				secretAccessKey,
				...(env.S3_ENDPOINT ? { endpoint: env.S3_ENDPOINT } : {}),
				...(env.S3_REGION ? { region: env.S3_REGION } : {}),
				...(env.S3_PREFIX ? { prefix: env.S3_PREFIX } : {}),
			},
		};
	}
	if (env.STORAGE_DIR && env.STORAGE_DIR.length > 0) return { kind: "local", dir: env.STORAGE_DIR };
	return { kind: "none" };
}

function readMs(env: Record<string, string | undefined>, name: string): number | null {
	const raw = env[name];
	if (!raw || raw.length === 0) return null;
	const ms = Number(raw);
	if (!Number.isInteger(ms) || ms < 0) {
		throw new Error(`${name}: expected a non-negative integer (ms)`);
	}
	return ms;
}

function readAssetGc(env: Record<string, string | undefined>): AssetGcConfig {
	const graceMs = readMs(env, "ASSET_GC_GRACE_MS") ?? DEFAULT_GRACE_MS;
	const retentionMs = readMs(env, "ASSET_GC_RETENTION_MS") ?? DEFAULT_RETENTION_MS;
	// The windows are the safety gates — zero would mean "delete instantly" /
	// "trust no device", so both must stay positive.
	if (graceMs <= 0) throw new Error("ASSET_GC_GRACE_MS: must be positive");
	if (retentionMs <= 0) throw new Error("ASSET_GC_RETENTION_MS: must be positive");
	const interval = readMs(env, "ASSET_GC_SWEEP_INTERVAL_MS");
	return { graceMs, retentionMs, sweepIntervalMs: interval && interval > 0 ? interval : null };
}

export function readConfig(env: Record<string, string | undefined>): Config {
	const rawPort = env.PORT ?? "7780";
	const port = Number(rawPort);
	if (!Number.isInteger(port) || port < 1 || port > 65535) {
		throw new Error(`PORT: invalid port ${rawPort}`);
	}
	return {
		port,
		auditLogPath: env.AUDIT_LOG_PATH && env.AUDIT_LOG_PATH.length > 0 ? env.AUDIT_LOG_PATH : null,
		storage: readStorageProvider(env),
		entitlement: readEntitlement(env),
		meteringLogPath:
			env.METERING_LOG_PATH && env.METERING_LOG_PATH.length > 0 ? env.METERING_LOG_PATH : null,
		limits: env.LIMITS_DISABLED === "1" ? null : DEFAULT_LIMITS,
		assetGc: readAssetGc(env),
		debug: env.LOG_LEVEL === "debug",
	};
}

function describeStorage(provider: StorageProvider): string {
	if (provider.kind === "local") return `local ${provider.dir}`;
	if (provider.kind === "s3") return `s3 ${provider.s3.bucket}`;
	return "forward-only";
}

function log(level: "info" | "error", message: string): void {
	const line = JSON.stringify({ ts: Date.now(), level, msg: message });
	if (level === "error") console.error(line);
	else console.info(line);
}

/** Resolve the configured provider into the storage set (or null for
 *  forward-only). The `ObjectBucket` seam means s3/local differ only here; the
 *  blob-plane CAS (Asset-B3) + GC ref ledger (Asset-B6) ride the same choice. */
function buildStorage(provider: StorageProvider): {
	store: SnapshotStore;
	catalog: AccountCatalog;
	assetCas: AssetCas;
	refLedger: RefLedger;
} | null {
	if (provider.kind === "local") {
		return {
			store: new FileSnapshotStore(provider.dir),
			catalog: new FileAccountCatalog(join(provider.dir, "catalog")),
			assetCas: new FileAssetCas(join(provider.dir, "assets")),
			refLedger: new FileRefLedger(join(provider.dir, "asset-gc")),
		};
	}
	if (provider.kind === "s3") {
		const bucket = BunS3Bucket.fromConfig(provider.s3);
		const prefix = provider.s3.prefix ?? "";
		return {
			store: new ObjectSnapshotStore(bucket, prefix),
			catalog: new ObjectAccountCatalog(bucket, prefix),
			assetCas: new ObjectAssetCas(bucket, prefix),
			refLedger: new ObjectRefLedger(bucket, prefix),
		};
	}
	return null;
}

async function buildCore(config: Config): Promise<{ core: RelayCore; assetGc: AssetGc | null }> {
	const storage = buildStorage(config.storage);
	const admission = config.entitlement
		? new Admission({
				keys: await buildVerifierKeySet(config.entitlement.keys),
				...(config.entitlement.requiredFeature
					? { requiredFeature: config.entitlement.requiredFeature }
					: {}),
			})
		: undefined;
	const limits = config.limits ? new Limits(config.limits) : undefined;
	const meter = config.meteringLogPath
		? (event: MeterEvent) => {
				void appendFile(
					config.meteringLogPath as string,
					`${JSON.stringify(event)}\n`,
					"utf8",
				).catch((err) => log("error", `metering append failed: ${(err as Error).message}`));
			}
		: undefined;
	const assetGc = storage
		? new AssetGc({
				cas: storage.assetCas,
				ledger: storage.refLedger,
				graceMs: config.assetGc.graceMs,
				retentionMs: config.assetGc.retentionMs,
				...(meter ? { meter } : {}),
				onLog: (message: string) => log("info", message),
			})
		: null;
	const core = createRelayCore({
		...(config.auditLogPath
			? {
					auditSink: (entry: string) => {
						void appendFile(config.auditLogPath as string, `${entry}\n`, "utf8").catch((err) => {
							log("error", `audit append failed: ${(err as Error).message}`);
						});
					},
				}
			: {}),
		...(storage
			? {
					store: storage.store,
					catalog: storage.catalog,
					assetCas: storage.assetCas,
					onStoreError: (err: Error) => log("error", `store: ${err.message}`),
				}
			: {}),
		...(assetGc ? { assetGc } : {}),
		...(admission && config.entitlement
			? { admission, authTimeoutMs: config.entitlement.authTimeoutMs }
			: {}),
		...(limits ? { limits } : {}),
		...(meter ? { meter } : {}),
	});
	return { core, assetGc };
}

type WsLike = {
	data?: { connId?: string; ip?: string };
	send(d: Uint8Array | string): void;
	close(code?: number, reason?: string): void;
};

type UpgradeServer = {
	upgrade(req: Request, options?: { data?: { ip?: string } }): boolean;
	requestIP(req: Request): { address: string } | null;
};

/**
 * Boot the node on `config.port` and return the live server + core (+ the GC
 * engine and its sweep timer, when a durable asset plane is configured). Async
 * because gated admission imports its Ed25519 verifier keyset (WebCrypto).
 * Exported so a real-WebSocket integration test can start a node, connect WS
 * clients, and `server.stop()`.
 */
export async function startNode(config: Config): Promise<{
	server: BunServer;
	core: RelayCore;
	assetGc: AssetGc | null;
	stopSweep: () => void;
}> {
	const { core, assetGc } = await buildCore(config);
	const BunRT = (globalThis as { Bun?: BunRuntime }).Bun;
	if (!BunRT) {
		throw new Error("brainstorm-sync: must run under Bun (globalThis.Bun missing)");
	}
	const server = BunRT.serve({
		port: config.port,
		websocket: {
			open(ws: WsLike) {
				const connId = core.handlers.onOpen(ws);
				if (config.debug) log("info", `open conn=${connId}`);
			},
			message(ws: WsLike, message: Uint8Array | string) {
				core.handlers.onMessage(ws, message);
				if (config.debug) {
					const connId = ws.data?.connId ?? "?";
					log(
						"info",
						`msg conn=${connId} subs=[${core.router.connectionEntities(connId).join(",")}]`,
					);
				}
			},
			close(ws: WsLike) {
				if (config.debug) log("info", `close conn=${ws.data?.connId ?? "?"}`);
				core.handlers.onClose(ws);
			},
		},
		fetch(req: Request, srv: UpgradeServer): Response | undefined {
			const url = new URL(req.url);
			if (url.pathname === "/healthz") {
				return new Response("ok", { status: 200, headers: { "content-type": "text/plain" } });
			}
			// Stamp the client IP so SYNC-5 per-IP connection rate limiting works.
			const ip = srv.requestIP(req)?.address ?? "?";
			if (srv.upgrade(req, { data: { ip } })) return undefined;
			return new Response("brainstorm-sync relay node v1", { status: 200 });
		},
	});
	let sweepTimer: ReturnType<typeof setInterval> | null = null;
	if (assetGc && config.assetGc.sweepIntervalMs) {
		sweepTimer = setInterval(() => {
			void assetGc
				.sweep()
				.catch((err) => log("error", `asset-gc sweep: ${(err as Error).message}`));
		}, config.assetGc.sweepIntervalMs);
	}
	const stopSweep = (): void => {
		if (sweepTimer !== null) clearInterval(sweepTimer);
		sweepTimer = null;
	};
	return { server, core, assetGc, stopSweep };
}

async function main(): Promise<void> {
	const config = readConfig(process.env);
	const { server, stopSweep } = await startNode(config);

	log(
		"info",
		`listening on :${config.port}${config.auditLogPath ? " (audit on)" : ""} (storage: ${describeStorage(
			config.storage,
		)}${config.entitlement ? ", gated" : ""}${config.limits ? ", limited" : ""})`,
	);

	const shutdown = (signal: string): void => {
		log("info", `${signal} — draining + closing`);
		stopSweep();
		server.stop(true);
		process.exit(0);
	};
	process.on("SIGTERM", () => shutdown("SIGTERM"));
	process.on("SIGINT", () => shutdown("SIGINT"));
}

// Only auto-start when run directly under Bun (not when imported by a test).
if ((globalThis as { Bun?: BunRuntime }).Bun && import.meta.main) {
	void main();
}
