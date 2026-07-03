/**
 * 10.11 routing-token rotation (OQ-197) — the relay-core protocol surface:
 * the `rotate` control verb, the dual-token grace alias, canonical-key
 * persistence, restore-catalog continuity, authorization on the gated node,
 * fail-closed denial paths, and wire-parse rejects. The storage re-home
 * itself is covered per backend in `sync/migrate.test.ts`.
 */

import { describe, expect, test } from "bun:test";
import type { Admission } from "./admission";
import { EntitlementStatus, PlanTier } from "./entitlement";
import {
	type RelayCore,
	RotateDenyReason,
	type ServerWebSocketLike,
	createRelayCore,
} from "./server";
import { MemoryAccountCatalog } from "./sync/account-catalog";
import { MemorySnapshotStore, type SnapshotStore } from "./sync/snapshot-store";
import { PROTOCOL_VERSION, WireKind } from "./wire";

const FRAME = 0x01;
const CONTROL = 0x00;
const enc = new TextEncoder();
const dec = new TextDecoder();

const T1 = "route-token-1";
const T2 = "route-token-2";
const T3 = "route-token-3";
const SENDER = "device-a";

function fakeWs(): ServerWebSocketLike & { sent: Uint8Array[] } {
	const sent: Uint8Array[] = [];
	return {
		sent,
		data: {},
		send(d: Uint8Array | string) {
			sent.push(d instanceof Uint8Array ? d : enc.encode(d));
		},
		close() {},
	};
}

function frame(header: Record<string, unknown>, ciphertext: Uint8Array): Uint8Array {
	const headerBytes = enc.encode(JSON.stringify(header));
	const out = new Uint8Array(4 + headerBytes.length + 2 + 64 + 4 + ciphertext.length);
	const view = new DataView(out.buffer);
	let o = 0;
	view.setUint32(o, headerBytes.length, false);
	o += 4;
	out.set(headerBytes, o);
	o += headerBytes.length;
	view.setUint16(o, 64, false);
	o += 2 + 64;
	view.setUint32(o, ciphertext.length, false);
	o += 4;
	out.set(ciphertext, o);
	return out;
}

function channel(byte: number, body: Uint8Array): Uint8Array {
	const out = new Uint8Array(1 + body.length);
	out[0] = byte;
	out.set(body, 1);
	return out;
}

function control(message: Record<string, unknown>): Uint8Array {
	return channel(CONTROL, enc.encode(JSON.stringify(message)));
}

function header(entityId: string, sender = SENDER, kind: WireKind = WireKind.Update) {
	return { v: PROTOCOL_VERSION, kind, entityId, sender, seq: 0, nonce: "n", ts: 1 };
}

/** Control replies (channel 0x00) the relay sent to this socket, parsed. */
function controlReplies(ws: { sent: Uint8Array[] }): Array<Record<string, unknown>> {
	return ws.sent
		.filter((w) => w[0] === CONTROL)
		.map((w) => JSON.parse(dec.decode(w.subarray(1))) as Record<string, unknown>);
}

/** Data frames (channel 0x01) delivered to this socket, as ciphertext strings. */
function deliveredCiphertexts(ws: { sent: Uint8Array[] }): string[] {
	return ws.sent
		.filter((w) => w[0] === FRAME)
		.map((w) => {
			const f = w.subarray(1);
			const view = new DataView(f.buffer, f.byteOffset, f.byteLength);
			const headerLen = view.getUint32(0, false);
			const sigLen = view.getUint16(4 + headerLen, false);
			const ctOff = 4 + headerLen + 2 + sigLen + 4;
			return dec.decode(f.subarray(ctOff));
		});
}

const tick = () => new Promise((r) => setTimeout(r, 5));

let connCounter = 0;
const mintConnId = () => `c${++connCounter}`;

type Harness = {
	core: RelayCore;
	store: MemorySnapshotStore;
	catalog: MemoryAccountCatalog;
	clock: { now: number };
};

function makeNode(opts: { graceMs?: number; store?: SnapshotStore } = {}): Harness {
	const clock = { now: 1_000 };
	const store = (opts.store as MemorySnapshotStore) ?? new MemorySnapshotStore();
	const catalog = new MemoryAccountCatalog();
	const core = createRelayCore({
		mintConnId,
		now: () => clock.now,
		store,
		catalog,
		rotateGraceMs: opts.graceMs ?? 60_000,
	});
	return { core, store, catalog, clock };
}

async function open(core: RelayCore): Promise<ServerWebSocketLike & { sent: Uint8Array[] }> {
	const ws = fakeWs();
	core.handlers.onOpen(ws);
	return ws;
}

describe("rotate control — wire parse", () => {
	test("malformed rotate messages are ignored (no reply, no state change)", async () => {
		const { core } = makeNode();
		const ws = await open(core);
		for (const bad of [
			{ op: "rotate" },
			{ op: "rotate", from: T1 },
			{ op: "rotate", to: T2 },
			{ op: "rotate", from: "", to: T2 },
			{ op: "rotate", from: T1, to: "" },
			{ op: "rotate", from: T1, to: T1 },
			{ op: "rotate", from: 7, to: T2 },
			{ op: "rotate", from: T1, to: ["x"] },
		]) {
			core.handlers.onMessage(ws, control(bad));
		}
		await tick();
		expect(controlReplies(ws)).toEqual([]);
	});

	test("an unknown control op is ignored — a pre-10.11 client is unaffected", async () => {
		const { core } = makeNode();
		const ws = await open(core);
		core.handlers.onMessage(ws, control({ op: "rotate-someday", from: T1, to: T2 }));
		core.handlers.onMessage(ws, control({ op: "subscribe", entityIds: [T1] }));
		await tick();
		expect(controlReplies(ws)).toEqual([]);
		expect(core.router.subscriberCount(T1)).toBe(1);
	});
});

describe("rotation happy path (open node)", () => {
	test("rotated ack, storage re-homed, frames under the new token round-trip", async () => {
		const { core, store } = makeNode();
		const a = await open(core);
		const b = await open(core);
		core.handlers.onMessage(a, control({ op: "subscribe", entityIds: [T1] }));
		core.handlers.onMessage(b, control({ op: "subscribe", entityIds: [T1] }));
		core.handlers.onMessage(a, channel(FRAME, frame(header(T1), enc.encode("ct-pre"))));
		await tick();
		expect(deliveredCiphertexts(b)).toEqual(["ct-pre"]);

		core.handlers.onMessage(a, control({ op: "rotate", from: T1, to: T2, account: SENDER }));
		await tick();
		expect(controlReplies(a)).toEqual([{ op: "rotated", from: T1, to: T2 }]);
		// Storage lives under the new token now.
		expect((await store.readBackfill(T2)).frames.length).toBe(1);
		expect((await store.readBackfill(T1)).frames.length).toBe(0);

		// Frames under the NEW token reach the in-flight peer that subscribed
		// under the OLD token (its subscription was moved by the rotation).
		core.handlers.onMessage(a, channel(FRAME, frame(header(T2), enc.encode("ct-post"))));
		await tick();
		expect(deliveredCiphertexts(b)).toEqual(["ct-pre", "ct-post"]);
	});

	test("restore catalog serves under the new token after rotation", async () => {
		const { core, catalog } = makeNode();
		const a = await open(core);
		core.handlers.onMessage(a, control({ op: "subscribe", entityIds: [T1] }));
		core.handlers.onMessage(a, channel(FRAME, frame(header(T1), enc.encode("ct"))));
		await tick();
		expect(await catalog.list(SENDER)).toEqual([T1]);
		core.handlers.onMessage(a, control({ op: "rotate", from: T1, to: T2, account: SENDER }));
		await tick();
		// The new token is recorded for the rotating account; a cold device's
		// catalog query finds T2 and its backfill serves the re-homed data.
		expect(await catalog.list(SENDER)).toContain(T2);
		const cold = await open(core);
		core.handlers.onMessage(cold, control({ op: "catalog", account: SENDER }));
		await tick();
		const replies = controlReplies(cold);
		expect(replies.length).toBe(1);
		const entities = replies[0]?.entities as Array<{ entityId: string }>;
		expect(entities.map((e) => e.entityId)).toContain(T2);
		core.handlers.onMessage(cold, control({ op: "subscribe", entityIds: [T2] }));
		await tick();
		expect(deliveredCiphertexts(cold)).toEqual(["ct"]);
	});

	test("rotation with no durable data (forward-only) still acks and aliases", async () => {
		const { core } = makeNode();
		const a = await open(core);
		const b = await open(core);
		core.handlers.onMessage(b, control({ op: "subscribe", entityIds: [T1] }));
		core.handlers.onMessage(a, control({ op: "rotate", from: T1, to: T2 }));
		await tick();
		expect(controlReplies(a)).toEqual([{ op: "rotated", from: T1, to: T2 }]);
		core.handlers.onMessage(a, channel(FRAME, frame(header(T2), enc.encode("live"))));
		await tick();
		expect(deliveredCiphertexts(b)).toEqual(["live"]);
	});

	test("rotate is idempotent — a crash-retry re-sends and gets a second ack", async () => {
		const { core, store } = makeNode();
		const a = await open(core);
		core.handlers.onMessage(a, control({ op: "subscribe", entityIds: [T1] }));
		core.handlers.onMessage(a, channel(FRAME, frame(header(T1), enc.encode("ct"))));
		await tick();
		core.handlers.onMessage(a, control({ op: "rotate", from: T1, to: T2, account: SENDER }));
		core.handlers.onMessage(a, control({ op: "rotate", from: T1, to: T2, account: SENDER }));
		await tick();
		expect(controlReplies(a)).toEqual([
			{ op: "rotated", from: T1, to: T2 },
			{ op: "rotated", from: T1, to: T2 },
		]);
		expect((await store.readBackfill(T2)).frames.length).toBe(1);
	});
});

describe("dual-token grace window", () => {
	test("during grace: old-token subscribe lands on the new channel with backfill", async () => {
		const { core } = makeNode();
		const a = await open(core);
		core.handlers.onMessage(a, control({ op: "subscribe", entityIds: [T1] }));
		core.handlers.onMessage(a, channel(FRAME, frame(header(T1), enc.encode("ct"))));
		await tick();
		core.handlers.onMessage(a, control({ op: "rotate", from: T1, to: T2, account: SENDER }));
		await tick();
		// A laggard peer that hasn't flipped yet subscribes under the OLD token.
		const laggard = await open(core);
		core.handlers.onMessage(laggard, control({ op: "subscribe", entityIds: [T1] }));
		await tick();
		expect(deliveredCiphertexts(laggard)).toEqual(["ct"]); // re-homed backfill
		core.handlers.onMessage(a, channel(FRAME, frame(header(T2), enc.encode("post"))));
		await tick();
		expect(deliveredCiphertexts(laggard)).toEqual(["ct", "post"]);
	});

	test("during grace: a frame emitted under the OLD token fans out and persists under the NEW token (no orphaned ciphertext)", async () => {
		const { core, store } = makeNode();
		const a = await open(core);
		const b = await open(core);
		core.handlers.onMessage(b, control({ op: "subscribe", entityIds: [T1] }));
		core.handlers.onMessage(a, control({ op: "rotate", from: T1, to: T2 }));
		await tick();
		core.handlers.onMessage(a, channel(FRAME, frame(header(T1), enc.encode("late"))));
		await tick();
		expect(deliveredCiphertexts(b)).toEqual(["late"]);
		expect((await store.readBackfill(T2)).frames.length).toBe(1);
		expect((await store.readBackfill(T1)).frames.length).toBe(0);
	});

	test("after grace expiry the old token is an unknown key", async () => {
		const { core, clock } = makeNode({ graceMs: 60_000 });
		const a = await open(core);
		const b = await open(core);
		core.handlers.onMessage(b, control({ op: "subscribe", entityIds: [T1] }));
		core.handlers.onMessage(a, control({ op: "rotate", from: T1, to: T2 }));
		await tick();
		clock.now += 60_001;
		// A post-grace subscribe under the old token creates a dead channel…
		const late = await open(core);
		core.handlers.onMessage(late, control({ op: "subscribe", entityIds: [T1] }));
		core.handlers.onMessage(a, channel(FRAME, frame(header(T2), enc.encode("post"))));
		await tick();
		expect(deliveredCiphertexts(late)).toEqual([]);
		// …and a post-grace frame under the old token no longer reaches T2 peers.
		core.handlers.onMessage(a, channel(FRAME, frame(header(T1), enc.encode("stale"))));
		await tick();
		expect(deliveredCiphertexts(b)).toEqual(["post"]);
	});

	test("chained rotation within one grace window resolves through both hops", async () => {
		const { core, store } = makeNode();
		const a = await open(core);
		core.handlers.onMessage(a, control({ op: "subscribe", entityIds: [T1] }));
		core.handlers.onMessage(a, channel(FRAME, frame(header(T1), enc.encode("ct"))));
		await tick();
		core.handlers.onMessage(a, control({ op: "rotate", from: T1, to: T2, account: SENDER }));
		await tick();
		core.handlers.onMessage(a, control({ op: "rotate", from: T2, to: T3, account: SENDER }));
		await tick();
		expect((await store.readBackfill(T3)).frames.length).toBe(1);
		const cold = await open(core);
		core.handlers.onMessage(cold, control({ op: "subscribe", entityIds: [T1] }));
		await tick();
		expect(deliveredCiphertexts(cold)).toEqual(["ct"]);
	});
});

describe("fail-closed denials", () => {
	test("occupied target denies with conflict and the old token stays fully live", async () => {
		const { core, store } = makeNode();
		const a = await open(core);
		const b = await open(core);
		core.handlers.onMessage(a, control({ op: "subscribe", entityIds: [T1] }));
		core.handlers.onMessage(b, control({ op: "subscribe", entityIds: [T1] }));
		core.handlers.onMessage(a, channel(FRAME, frame(header(T1), enc.encode("mine"))));
		core.handlers.onMessage(a, channel(FRAME, frame(header(T2), enc.encode("other"))));
		await tick();
		core.handlers.onMessage(a, control({ op: "rotate", from: T1, to: T2 }));
		await tick();
		expect(controlReplies(a)).toEqual([
			{ op: "rotate-denied", from: T1, to: T2, reason: RotateDenyReason.Conflict },
		]);
		// Old token still routes AND still persists — nothing moved, no alias.
		core.handlers.onMessage(a, channel(FRAME, frame(header(T1), enc.encode("still"))));
		await tick();
		expect(deliveredCiphertexts(b)).toEqual(["mine", "still"]);
		expect((await store.readBackfill(T1)).frames.length).toBe(2);
	});

	test("a store failure denies with store-error and installs no alias", async () => {
		const failing = new MemorySnapshotStore();
		failing.migrate = async () => {
			throw new Error("disk on fire");
		};
		const errors: Error[] = [];
		const clock = { now: 1_000 };
		const core = createRelayCore({
			mintConnId,
			now: () => clock.now,
			store: failing,
			onStoreError: (e) => errors.push(e),
		});
		const a = await open(core);
		const b = await open(core);
		core.handlers.onMessage(b, control({ op: "subscribe", entityIds: [T1] }));
		core.handlers.onMessage(a, control({ op: "rotate", from: T1, to: T2 }));
		await tick();
		expect(controlReplies(a)).toEqual([
			{ op: "rotate-denied", from: T1, to: T2, reason: RotateDenyReason.StoreError },
		]);
		expect(errors.length).toBe(1);
		// No alias: a frame under T2 does NOT reach the T1 subscriber.
		core.handlers.onMessage(a, channel(FRAME, frame(header(T2), enc.encode("x"))));
		await tick();
		expect(deliveredCiphertexts(b)).toEqual([]);
	});
});

describe("gated node authorization", () => {
	function fakeAdmission(): Admission {
		return {
			createChallenge: () => "nonce-1",
			verify: async (msg: { account: string }) => ({
				admitted: true as const,
				account: msg.account,
				sub: "billing-1",
				plan: PlanTier.Pro,
				status: EntitlementStatus.Active,
				features: [],
			}),
		} as unknown as Admission;
	}

	async function openAuthed(
		core: RelayCore,
		account: string,
	): Promise<ServerWebSocketLike & { sent: Uint8Array[] }> {
		const ws = fakeWs();
		core.handlers.onOpen(ws);
		core.handlers.onMessage(ws, control({ op: "auth", token: "t", account, sig: "s" }));
		await tick();
		return ws;
	}

	function makeGated(): Harness {
		const clock = { now: 1_000 };
		const store = new MemorySnapshotStore();
		const catalog = new MemoryAccountCatalog();
		const core = createRelayCore({
			mintConnId,
			now: () => clock.now,
			store,
			catalog,
			admission: fakeAdmission(),
			setTimer: () => null,
			clearTimer: () => {},
		});
		return { core, store, catalog, clock };
	}

	test("an unauthenticated connection's rotate is ignored", async () => {
		const { core } = makeGated();
		const ws = fakeWs();
		core.handlers.onOpen(ws);
		core.handlers.onMessage(ws, control({ op: "rotate", from: T1, to: T2 }));
		await tick();
		// Only the challenge — no rotated / rotate-denied.
		expect(controlReplies(ws).map((r) => r.op)).toEqual(["challenge"]);
	});

	test("rotating a token the proven account never emitted for is not-authorized", async () => {
		const { core, catalog } = makeGated();
		await catalog.record("someone-else", T1);
		const ws = await openAuthed(core, SENDER);
		core.handlers.onMessage(ws, control({ op: "rotate", from: T1, to: T2 }));
		await tick();
		const replies = controlReplies(ws).filter((r) => r.op !== "challenge" && r.op !== "auth-ok");
		expect(replies).toEqual([
			{ op: "rotate-denied", from: T1, to: T2, reason: RotateDenyReason.NotAuthorized },
		]);
	});

	test("the owning account rotates; the catalog records the new token under the PROVEN account", async () => {
		const { core, store, catalog } = makeGated();
		const ws = await openAuthed(core, SENDER);
		core.handlers.onMessage(ws, control({ op: "subscribe", entityIds: [T1] }));
		core.handlers.onMessage(ws, channel(FRAME, frame(header(T1), enc.encode("ct"))));
		await tick();
		// Attempt to spoof the catalog account: the node must use the proven one.
		core.handlers.onMessage(
			ws,
			control({ op: "rotate", from: T1, to: T2, account: "someone-else" }),
		);
		await tick();
		const replies = controlReplies(ws).filter((r) => r.op === "rotated");
		expect(replies).toEqual([{ op: "rotated", from: T1, to: T2 }]);
		expect(await catalog.list(SENDER)).toContain(T2);
		expect(await catalog.list("someone-else")).toEqual([]);
		expect((await store.readBackfill(T2)).frames.length).toBe(1);
	});
});
