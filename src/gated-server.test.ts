/**
 * SYNC-4b / SYNC-5 — the gated relay core, driven through the connection
 * handlers without a socket: the challenge handshake, frame gating before auth,
 * catalog scoping to the proven account, sender impersonation rejection,
 * metering events, the auth deadline, and the SYNC-5 abuse caps / rate limits.
 */

import { beforeAll, describe, expect, test } from "bun:test";
import { Admission } from "./admission";
import { AssetWireKind, encodeAssetRequest } from "./asset-wire";
import {
	ENTITLEMENT_TOKEN_VERSION,
	type EntitlementClaims,
	PlanTier,
	type VerifierKeySet,
	buildVerifierKeySet,
} from "./entitlement";
import { DEFAULT_LIMITS, Limits, type LimitsConfig } from "./limits";
import { type MeterEvent, MeterKind } from "./metering";
import { type RelayCore, type ServerWebSocketLike, createRelayCore } from "./server";
import { MemoryAccountCatalog } from "./sync/account-catalog";
import { MemoryAssetCas } from "./sync/asset-cas";
import { AssetGc } from "./sync/asset-gc";
import { MemoryRefLedger } from "./sync/ref-ledger";
import { MemorySnapshotStore } from "./sync/snapshot-store";
import { PROTOCOL_VERSION, WireKind } from "./wire";

const FRAME = 0x01;
const CONTROL = 0x00;
const ASSET = 0x02;
const enc = new TextEncoder();
const dec = new TextDecoder();
const b64 = (b: Uint8Array | string) =>
	Buffer.from(typeof b === "string" ? enc.encode(b) : b).toString("base64url");
const data = (s: string): Uint8Array<ArrayBuffer> => {
	const e = enc.encode(s);
	const out = new Uint8Array(e.byteLength);
	out.set(e);
	return out;
};
const genKeypair = async (): Promise<CryptoKeyPair> =>
	(await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
		"sign",
		"verify",
	])) as unknown as CryptoKeyPair;
/** The admission verify is real async WebCrypto — a fixed short sleep flakes
 *  on a loaded box. Poll (bounded) until the async work observably landed. */
const until = async (done: () => boolean): Promise<void> => {
	const deadline = Date.now() + 5_000;
	while (!done() && Date.now() < deadline) await new Promise((r) => setTimeout(r, 5));
};

let billingPriv: CryptoKey;
let keys: VerifierKeySet;
let identity: CryptoKeyPair;
let account: string;

beforeAll(async () => {
	const billing = await genKeypair();
	billingPriv = billing.privateKey;
	keys = await buildVerifierKeySet({
		k1: b64(new Uint8Array(await crypto.subtle.exportKey("raw", billing.publicKey))),
	});
	identity = await genKeypair();
	account = b64(new Uint8Array(await crypto.subtle.exportKey("raw", identity.publicKey)));
});

async function signToken(over: Partial<EntitlementClaims> = {}): Promise<string> {
	const claims: EntitlementClaims = {
		v: ENTITLEMENT_TOKEN_VERSION,
		sub: "acc_7",
		plan: PlanTier.Plus,
		features: ["hosted-relay"],
		iat: 0,
		softExp: 10_000,
		hardExp: 20_000,
		iss: "billing-edge",
		...over,
	};
	const headerB64 = b64(JSON.stringify({ alg: "EdDSA", kid: "k1" }));
	const claimsB64 = b64(JSON.stringify(claims));
	const sig = new Uint8Array(
		await crypto.subtle.sign({ name: "Ed25519" }, billingPriv, data(`${headerB64}.${claimsB64}`)),
	);
	return `${headerB64}.${claimsB64}.${b64(sig)}`;
}

async function signNonce(nonce: string, key = identity.privateKey): Promise<string> {
	const sig = await crypto.subtle.sign(
		{ name: "Ed25519" },
		key,
		new Uint8Array(Buffer.from(nonce, "base64url")),
	);
	return b64(new Uint8Array(sig));
}

function frame(entityId: string, sender: string, kind = WireKind.Update, ct = new Uint8Array([1])) {
	const header = enc.encode(
		JSON.stringify({ v: PROTOCOL_VERSION, kind, entityId, sender, seq: 0, nonce: "n", ts: 1 }),
	);
	const out = new Uint8Array(4 + header.length + 2 + 64 + 4 + ct.length);
	const view = new DataView(out.buffer);
	let o = 0;
	view.setUint32(o, header.length, false);
	o += 4;
	out.set(header, o);
	o += header.length;
	view.setUint16(o, 64, false);
	o += 2 + 64;
	view.setUint32(o, ct.length, false);
	o += 4;
	out.set(ct, o);
	return out;
}

function channel(byte: number, body: Uint8Array): Uint8Array {
	const out = new Uint8Array(1 + body.length);
	out[0] = byte;
	out.set(body, 1);
	return out;
}

type CloseInfo = { code?: number | undefined; reason?: string | undefined };
type FakeWs = ServerWebSocketLike & {
	sent: Uint8Array[];
	closed: CloseInfo | null;
};
function makeWs(ip = "1.2.3.4"): FakeWs {
	const sent: Uint8Array[] = [];
	const ws = {
		data: { ip } as { connId?: string; ip?: string },
		sent,
		closed: null as CloseInfo | null,
		send(d: Uint8Array | string) {
			sent.push(d instanceof Uint8Array ? d : enc.encode(d));
		},
		close(code?: number, reason?: string) {
			(ws as FakeWs).closed = { code, reason };
		},
	};
	return ws as FakeWs;
}

const controls = (ws: FakeWs) =>
	ws.sent.filter((b) => b[0] === CONTROL).map((b) => JSON.parse(dec.decode(b.subarray(1))));
const frames = (ws: FakeWs) => ws.sent.filter((b) => b[0] === FRAME).map((b) => b.subarray(1));

async function authenticate(
	core: RelayCore,
	ws: FakeWs,
	token: string,
	acct = account,
): Promise<string> {
	const connId = core.handlers.onOpen(ws);
	const challenge = controls(ws).find((c) => c.op === "challenge");
	const sig = await signNonce(challenge.nonce);
	core.handlers.onMessage(
		ws,
		channel(CONTROL, enc.encode(JSON.stringify({ op: "auth", token, account: acct, sig }))),
	);
	await until(
		() =>
			controls(ws).some((c) => c.op === "auth-ok" || c.op === "auth-error") || ws.closed !== null,
	);
	return connId;
}

function gatedCore(over: Partial<Parameters<typeof createRelayCore>[0]> = {}) {
	return createRelayCore({
		admission: new Admission({ keys, now: () => 1000 }),
		mintConnId: (() => {
			let n = 0;
			return () => `c${++n}`;
		})(),
		...over,
	});
}

describe("gated relay core (SYNC-4b)", () => {
	test("a challenge is issued on open; a valid auth admits and binds the account", async () => {
		const core = gatedCore();
		const ws = makeWs();
		const connId = await authenticate(core, ws, await signToken());
		const replies = controls(ws).map((c) => c.op);
		expect(replies).toContain("challenge");
		expect(replies).toContain("auth-ok");
		const state = core.connState.get(connId);
		expect(state?.authenticated).toBe(true);
		expect(state?.account).toBe(account);
		expect(state?.sub).toBe("acc_7");
	});

	test("a frame before auth is dropped; after auth it routes", async () => {
		const core = gatedCore();
		const sender = makeWs();
		const receiver = makeWs();
		// receiver authenticates + subscribes.
		await authenticate(core, receiver, await signToken());
		core.handlers.onMessage(
			receiver,
			channel(CONTROL, enc.encode(JSON.stringify({ op: "subscribe", entityIds: ["e1"] }))),
		);

		// sender opens but emits BEFORE authenticating → dropped.
		core.handlers.onOpen(sender);
		core.handlers.onMessage(sender, channel(FRAME, frame("e1", account)));
		expect(frames(receiver)).toEqual([]);

		// sender authenticates, then emits → delivered.
		const challenge = controls(sender).find((c) => c.op === "challenge");
		const sig = await signNonce(challenge.nonce);
		core.handlers.onMessage(
			sender,
			channel(
				CONTROL,
				enc.encode(JSON.stringify({ op: "auth", token: await signToken(), account, sig })),
			),
		);
		await until(() => controls(sender).some((c) => c.op === "auth-ok"));
		core.handlers.onMessage(sender, channel(FRAME, frame("e1", account)));
		expect(frames(receiver).length).toBe(1);
	});

	test("a frame whose sender != the proven account is dropped (no impersonation)", async () => {
		const core = gatedCore();
		const sender = makeWs();
		const receiver = makeWs();
		await authenticate(core, receiver, await signToken());
		core.handlers.onMessage(
			receiver,
			channel(CONTROL, enc.encode(JSON.stringify({ op: "subscribe", entityIds: ["e1"] }))),
		);
		await authenticate(core, sender, await signToken());
		// sender claims a different sender id than its proven account.
		core.handlers.onMessage(sender, channel(FRAME, frame("e1", "someone-else")));
		expect(frames(receiver)).toEqual([]);
	});

	test("a catalog query is scoped to the proven account, ignoring a forged account", async () => {
		const store = new MemorySnapshotStore();
		const catalog = new MemoryAccountCatalog();
		await catalog.record(account, "mine");
		await catalog.record("victim", "secret");
		const core = gatedCore({ store, catalog });
		const ws = makeWs();
		await authenticate(core, ws, await signToken());
		// Ask for the victim's catalog — the node must answer with OUR account.
		core.handlers.onMessage(
			ws,
			channel(CONTROL, enc.encode(JSON.stringify({ op: "catalog", account: "victim" }))),
		);
		await until(() => controls(ws).some((c) => c.op === "catalog-result"));
		const result = controls(ws).find((c) => c.op === "catalog-result");
		expect(result.account).toBe(account);
		expect(result.entities.map((e: { entityId: string }) => e.entityId)).toEqual(["mine"]);
	});

	test("metering emits connect + ingress for an admitted account", async () => {
		const events: MeterEvent[] = [];
		const core = gatedCore({ meter: (e) => events.push(e), now: () => 1000 });
		const sender = makeWs();
		const receiver = makeWs();
		await authenticate(core, receiver, await signToken());
		core.handlers.onMessage(
			receiver,
			channel(CONTROL, enc.encode(JSON.stringify({ op: "subscribe", entityIds: ["e1"] }))),
		);
		await authenticate(core, sender, await signToken());
		core.handlers.onMessage(sender, channel(FRAME, frame("e1", account)));
		expect(events.some((e) => e.kind === MeterKind.Connect && e.sub === "acc_7")).toBe(true);
		const ingress = events.find((e) => e.kind === MeterKind.Ingress);
		expect(ingress?.account).toBe(account);
		expect(ingress?.bytes).toBeGreaterThan(0);
	});

	test("the auth deadline closes a connection that never authenticates", async () => {
		let fired: (() => void) | null = null;
		const core = createRelayCore({
			admission: new Admission({ keys, now: () => 1000 }),
			setTimer: (cb) => {
				fired = cb;
				return 1;
			},
			clearTimer: () => undefined,
		});
		const ws = makeWs();
		core.handlers.onOpen(ws);
		expect(fired).not.toBeNull();
		(fired as unknown as () => void)();
		expect(ws.closed?.code).toBe(4408);
	});

	test("a bad token is rejected and the connection closed", async () => {
		const core = gatedCore();
		const ws = makeWs();
		core.handlers.onOpen(ws);
		const challenge = controls(ws).find((c) => c.op === "challenge");
		const sig = await signNonce(challenge.nonce);
		core.handlers.onMessage(
			ws,
			channel(
				CONTROL,
				enc.encode(JSON.stringify({ op: "auth", token: "not.a.token", account, sig })),
			),
		);
		await until(() => ws.closed !== null);
		expect(controls(ws).some((c) => c.op === "auth-error")).toBe(true);
		expect(ws.closed?.code).toBe(4401);
	});

	test("an unauthenticated ref-report is dropped (Asset-B6)", async () => {
		const cas = new MemoryAssetCas();
		const ledger = new MemoryRefLedger();
		const core = gatedCore({ assetCas: cas, assetGc: new AssetGc({ cas, ledger }) });
		const ws = makeWs();
		core.handlers.onOpen(ws); // challenged, NOT authenticated
		core.handlers.onMessage(
			ws,
			channel(
				ASSET,
				encodeAssetRequest({
					kind: AssetWireKind.Refs,
					account,
					device: "laptop",
					hashes: ["a".repeat(64)],
				}),
			),
		);
		await new Promise((r) => setTimeout(r, 20));
		expect(ws.sent.filter((b) => b[0] === ASSET)).toEqual([]);
		expect(await ledger.accounts()).toEqual([]);
	});

	test("a ref-report is scoped to the PROVEN account, ignoring a forged header (Asset-B6)", async () => {
		const cas = new MemoryAssetCas();
		const ledger = new MemoryRefLedger();
		const core = gatedCore({ assetCas: cas, assetGc: new AssetGc({ cas, ledger }) });
		const ws = makeWs();
		await authenticate(core, ws, await signToken());
		core.handlers.onMessage(
			ws,
			channel(
				ASSET,
				encodeAssetRequest({
					kind: AssetWireKind.Refs,
					account: "victim",
					device: "laptop",
					hashes: ["a".repeat(64)],
				}),
			),
		);
		await until(() => ws.sent.some((b) => b[0] === ASSET));
		expect(await ledger.accounts()).toEqual([account]); // never "victim"
		const state = await ledger.read(account);
		expect(state.devices.laptop?.refs).toEqual(["a".repeat(64)]);
	});
});

describe("SYNC-5 limits in the relay core", () => {
	const tight: LimitsConfig = {
		...DEFAULT_LIMITS,
		maxFrameBytes: 80,
		connPerIpPerSec: 1,
		connPerIpBurst: 1,
		maxSubsPerConn: 1,
	};

	test("an oversize frame is dropped before fan-out", () => {
		const core = createRelayCore({ limits: new Limits(tight, () => 0) });
		const sender = makeWs();
		const receiver = makeWs();
		core.handlers.onOpen(receiver);
		core.handlers.onMessage(
			receiver,
			channel(CONTROL, enc.encode(JSON.stringify({ op: "subscribe", entityIds: ["e1"] }))),
		);
		core.handlers.onOpen(sender);
		const big = frame("e1", account, WireKind.Update, new Uint8Array(200));
		core.handlers.onMessage(sender, channel(FRAME, big));
		expect(frames(receiver)).toEqual([]);
	});

	test("the per-IP connection rate limit closes the over-rate connection", () => {
		const core = createRelayCore({ limits: new Limits(tight, () => 0) });
		const first = makeWs("9.9.9.9");
		const second = makeWs("9.9.9.9");
		core.handlers.onOpen(first);
		core.handlers.onOpen(second);
		expect(first.closed).toBeNull();
		expect(second.closed?.code).toBe(4290);
		expect(core.connState.has((second.data as { connId?: string }).connId ?? "")).toBe(false);
	});

	test("the subscription cap stops extra subscriptions", () => {
		const core = createRelayCore({ limits: new Limits(tight, () => 0) });
		const ws = makeWs();
		const connId = core.handlers.onOpen(ws);
		core.handlers.onMessage(
			ws,
			channel(CONTROL, enc.encode(JSON.stringify({ op: "subscribe", entityIds: ["a", "b", "c"] }))),
		);
		expect(core.router.connectionEntities(connId).length).toBe(1);
	});
});
