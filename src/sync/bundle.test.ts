/**
 * 10.10 — bundled backfill (wrap+snapshot bundling on fresh-device bootstrap).
 *
 * Covers the bundle payload codec (round-trip + strict malformed rejects) and
 * the server wiring: a `subscribe` carrying `bundle:true` gets its backfill as
 * `0x03` bundle messages whose sub-frames are byte-identical to the per-frame
 * stream, chunked under the build caps, metered per entity; a client that
 * doesn't ask (old client) keeps the per-frame `0x01` path unchanged.
 */

import { describe, expect, test } from "bun:test";
import { type MeterEvent, MeterKind } from "../metering";
import { BUNDLE_LIMITS, type ServerWebSocketLike, WIRE_CHANNELS, createRelayCore } from "../server";
import { PROTOCOL_VERSION, WireKind, decodeBundlePayload, encodeBundlePayload } from "../wire";
import { MemorySnapshotStore } from "./snapshot-store";

const { CONTROL_CHANNEL_BYTE, FRAME_CHANNEL_BYTE, BUNDLE_CHANNEL_BYTE } = WIRE_CHANNELS;
const enc = new TextEncoder();
const dec = new TextDecoder();

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

function header(entityId: string, kind: WireKind = WireKind.Update, sender = "s") {
	return { v: PROTOCOL_VERSION, kind, entityId, sender, seq: 0, nonce: "n", ts: 1 };
}

function channel(byte: number, body: Uint8Array): Uint8Array {
	const out = new Uint8Array(1 + body.length);
	out[0] = byte;
	out.set(body, 1);
	return out;
}

const controlBody = (message: Record<string, unknown>) => enc.encode(JSON.stringify(message));
const flush = () => new Promise((r) => setTimeout(r, 20));

/** Frames delivered per-message on the `0x01` channel (channel byte stripped). */
function deliveredFrames(ws: { sent: Uint8Array[] }): Uint8Array[] {
	return ws.sent.filter((m) => m[0] === FRAME_CHANNEL_BYTE).map((m) => m.subarray(1));
}

/** Bundle messages on the `0x03` channel (channel byte stripped). */
function deliveredBundles(ws: { sent: Uint8Array[] }): Uint8Array[] {
	return ws.sent.filter((m) => m[0] === BUNDLE_CHANNEL_BYTE).map((m) => m.subarray(1));
}

/** All sub-frames across every delivered bundle, in delivery order. */
function bundledFrames(ws: { sent: Uint8Array[] }): Uint8Array[] {
	return deliveredBundles(ws).flatMap((b) => decodeBundlePayload(b));
}

/** Seed a store with wraps ++ snapshot ++ tail for each entity id. */
async function seedStore(store: MemorySnapshotStore, entityIds: string[]): Promise<void> {
	for (const id of entityIds) {
		await store.appendWrap(id, frame(header(id, WireKind.WrapBootstrap), enc.encode(`W:${id}`)));
		await store.putSnapshot(id, frame(header(id, WireKind.Snapshot), enc.encode(`S:${id}`)));
		await store.appendTail(id, frame(header(id, WireKind.Update), enc.encode(`u1${id}`)));
		await store.appendTail(id, frame(header(id, WireKind.Update), enc.encode(`u2${id}`)));
	}
}

describe("bundle payload codec (10.10)", () => {
	test("round-trips frames byte-identically", () => {
		const frames = [enc.encode("alpha"), enc.encode("b"), new Uint8Array(1024).fill(7)];
		const decoded = decodeBundlePayload(encodeBundlePayload(frames));
		expect(decoded.length).toBe(3);
		for (let i = 0; i < frames.length; i++) {
			expect(decoded[i]).toEqual(frames[i] as Uint8Array);
		}
	});

	test("decoded sub-frames are copies (mutating one leaves the payload intact)", () => {
		const payload = encodeBundlePayload([enc.encode("aa"), enc.encode("bb")]);
		const first = decodeBundlePayload(payload)[0] as Uint8Array;
		first[0] = 0;
		expect(dec.decode(decodeBundlePayload(payload)[0])).toBe("aa");
	});

	test("rejects an empty payload", () => {
		expect(() => decodeBundlePayload(new Uint8Array(0))).toThrow(/empty payload/);
	});

	test("rejects a truncated length prefix", () => {
		expect(() => decodeBundlePayload(new Uint8Array([0, 0, 1]))).toThrow(/truncated/);
	});

	test("rejects a zero-length sub-frame", () => {
		expect(() => decodeBundlePayload(new Uint8Array([0, 0, 0, 0]))).toThrow(/zero-length/);
	});

	test("rejects a sub-frame length that overruns the payload", () => {
		expect(() => decodeBundlePayload(new Uint8Array([0, 0, 0, 5, 1, 2]))).toThrow(/overruns/);
	});

	test("rejects trailing garbage after the last sub-frame", () => {
		const good = encodeBundlePayload([enc.encode("xy")]);
		const trailing = new Uint8Array(good.length + 2);
		trailing.set(good, 0);
		trailing.set([9, 9], good.length);
		expect(() => decodeBundlePayload(trailing)).toThrow(/truncated|overruns/);
	});

	test("refuses to encode an empty bundle or an empty sub-frame", () => {
		expect(() => encodeBundlePayload([])).toThrow(/empty bundle/);
		expect(() => encodeBundlePayload([new Uint8Array(0)])).toThrow(/empty sub-frame/);
	});
});

describe("server bundled backfill (10.10)", () => {
	test("bundle sub-frames are byte-identical to the per-frame backfill stream", async () => {
		const store = new MemorySnapshotStore();
		const ids = ["e1", "e2", "e3"];
		await seedStore(store, ids);
		const core = createRelayCore({ store });

		const plain = fakeWs();
		core.handlers.onOpen(plain);
		core.handlers.onMessage(
			plain,
			channel(CONTROL_CHANNEL_BYTE, controlBody({ op: "subscribe", entityIds: ids })),
		);
		await flush();

		const bundled = fakeWs();
		core.handlers.onOpen(bundled);
		core.handlers.onMessage(
			bundled,
			channel(CONTROL_CHANNEL_BYTE, controlBody({ op: "subscribe", entityIds: ids, bundle: true })),
		);
		await flush();

		const plainFrames = deliveredFrames(plain);
		const subFrames = bundledFrames(bundled);
		expect(deliveredFrames(bundled).length).toBe(0); // nothing rode 0x01
		expect(subFrames.length).toBe(plainFrames.length);
		for (let i = 0; i < plainFrames.length; i++) {
			expect(subFrames[i]).toEqual(plainFrames[i] as Uint8Array);
		}
		// Per-entity order preserved: wraps first, then snapshot, then tail.
		const tails = subFrames.map((f) => dec.decode(f.subarray(-4)));
		expect(tails.slice(0, 4)).toEqual(["W:e1", "S:e1", "u1e1", "u2e1"]);
	});

	test("a 20-entity restore collapses 80 frame messages into 1 bundle message", async () => {
		const store = new MemorySnapshotStore();
		const ids = Array.from({ length: 20 }, (_, i) => `ent_${i}`);
		await seedStore(store, ids);
		const core = createRelayCore({ store });

		const plain = fakeWs();
		core.handlers.onOpen(plain);
		core.handlers.onMessage(
			plain,
			channel(CONTROL_CHANNEL_BYTE, controlBody({ op: "subscribe", entityIds: ids })),
		);
		await flush();

		const bundled = fakeWs();
		core.handlers.onOpen(bundled);
		core.handlers.onMessage(
			bundled,
			channel(CONTROL_CHANNEL_BYTE, controlBody({ op: "subscribe", entityIds: ids, bundle: true })),
		);
		await flush();

		const plainMessages = deliveredFrames(plain).length;
		const bundleMessages = deliveredBundles(bundled).length;
		expect(plainMessages).toBe(80); // 20 × (wrap + snapshot + 2 tail)
		expect(bundleMessages).toBe(1);
		expect(bundledFrames(bundled).length).toBe(80);
		console.log(
			`[10.10] restore of ${ids.length} entities: ${plainMessages} frame messages → ${bundleMessages} bundle message(s)`,
		);
	});

	test("chunks a large backfill under BUNDLE_MAX_FRAMES, preserving order", async () => {
		const store = new MemorySnapshotStore();
		const perEntity = 60;
		const ids = ["a", "b", "c", "d", "e", "f"]; // 360 frames > 256 cap
		for (const id of ids) {
			for (let i = 0; i < perEntity; i++) {
				await store.appendTail(
					id,
					frame(header(id), enc.encode(`${id}#${String(i).padStart(3, "0")}`)),
				);
			}
		}
		const core = createRelayCore({ store });
		const ws = fakeWs();
		core.handlers.onOpen(ws);
		core.handlers.onMessage(
			ws,
			channel(CONTROL_CHANNEL_BYTE, controlBody({ op: "subscribe", entityIds: ids, bundle: true })),
		);
		await flush();

		const bundles = deliveredBundles(ws);
		expect(bundles.length).toBe(
			Math.ceil((ids.length * perEntity) / BUNDLE_LIMITS.BUNDLE_MAX_FRAMES),
		);
		for (const b of bundles) {
			expect(decodeBundlePayload(b).length).toBeLessThanOrEqual(BUNDLE_LIMITS.BUNDLE_MAX_FRAMES);
		}
		const tags = bundledFrames(ws).map((f) => dec.decode(f.subarray(-5)));
		const expected = ids.flatMap((id) =>
			Array.from({ length: perEntity }, (_, i) => `${id}#${String(i).padStart(3, "0")}`),
		);
		expect(tags).toEqual(expected);
	});

	test("flushes early when a bundle would exceed BUNDLE_MAX_BYTES", async () => {
		const store = new MemorySnapshotStore();
		const big = new Uint8Array(300 << 10).fill(1); // 300 KiB each; 2 don't fit in 512 KiB
		await store.appendTail("e1", frame(header("e1"), big));
		await store.appendTail("e1", frame(header("e1"), big));
		const core = createRelayCore({ store });
		const ws = fakeWs();
		core.handlers.onOpen(ws);
		core.handlers.onMessage(
			ws,
			channel(
				CONTROL_CHANNEL_BYTE,
				controlBody({ op: "subscribe", entityIds: ["e1"], bundle: true }),
			),
		);
		await flush();
		const bundles = deliveredBundles(ws);
		expect(bundles.length).toBe(2);
		expect(bundledFrames(ws).length).toBe(2);
	});

	test("an old client (no bundle flag) keeps the per-frame path — zero 0x03 messages", async () => {
		const store = new MemorySnapshotStore();
		await seedStore(store, ["e1"]);
		const core = createRelayCore({ store });
		const ws = fakeWs();
		core.handlers.onOpen(ws);
		core.handlers.onMessage(
			ws,
			channel(CONTROL_CHANNEL_BYTE, controlBody({ op: "subscribe", entityIds: ["e1"] })),
		);
		await flush();
		expect(deliveredFrames(ws).length).toBe(4);
		expect(deliveredBundles(ws).length).toBe(0);
	});

	test("a non-boolean / false bundle flag falls back to the per-frame path", async () => {
		const store = new MemorySnapshotStore();
		await seedStore(store, ["e1"]);
		const core = createRelayCore({ store });
		for (const bundle of [false, "yes", 1]) {
			const ws = fakeWs();
			core.handlers.onOpen(ws);
			core.handlers.onMessage(
				ws,
				channel(CONTROL_CHANNEL_BYTE, controlBody({ op: "subscribe", entityIds: ["e1"], bundle })),
			);
			await flush();
			expect(deliveredFrames(ws).length).toBe(4);
			expect(deliveredBundles(ws).length).toBe(0);
		}
	});

	test("a store-less (forward-only) node ignores bundle subscribes quietly", async () => {
		const core = createRelayCore();
		const ws = fakeWs();
		core.handlers.onOpen(ws);
		core.handlers.onMessage(
			ws,
			channel(
				CONTROL_CHANNEL_BYTE,
				controlBody({ op: "subscribe", entityIds: ["e1"], bundle: true }),
			),
		);
		await flush();
		expect(ws.sent.length).toBe(0);
		// The subscription itself still registered — live fan-out works.
		expect(core.router.connectionEntities((ws.data as { connId: string }).connId)).toEqual(["e1"]);
	});

	test("bundled backfill meters egress per entity with the same bytes as the per-frame path", async () => {
		const store = new MemorySnapshotStore();
		const ids = ["e1", "e2"];
		await seedStore(store, ids);

		const meterPlain: MeterEvent[] = [];
		const corePlain = createRelayCore({ store, meter: (e) => meterPlain.push(e) });
		const plain = fakeWs();
		corePlain.handlers.onOpen(plain);
		corePlain.handlers.onMessage(
			plain,
			channel(CONTROL_CHANNEL_BYTE, controlBody({ op: "subscribe", entityIds: ids })),
		);
		await flush();

		const meterBundled: MeterEvent[] = [];
		const coreBundled = createRelayCore({ store, meter: (e) => meterBundled.push(e) });
		const bundled = fakeWs();
		coreBundled.handlers.onOpen(bundled);
		coreBundled.handlers.onMessage(
			bundled,
			channel(CONTROL_CHANNEL_BYTE, controlBody({ op: "subscribe", entityIds: ids, bundle: true })),
		);
		await flush();

		const egress = (events: MeterEvent[]) =>
			events
				.filter((e) => e.kind === MeterKind.Egress)
				.map(({ entityId, bytes }) => ({ entityId, bytes }));
		expect(egress(meterBundled)).toEqual(egress(meterPlain));
		expect(egress(meterBundled).length).toBe(2);
	});

	test("live fan-out after a bundle subscribe still rides single 0x01 frames", async () => {
		const store = new MemorySnapshotStore();
		const core = createRelayCore({ store });
		const sub = fakeWs();
		core.handlers.onOpen(sub);
		core.handlers.onMessage(
			sub,
			channel(
				CONTROL_CHANNEL_BYTE,
				controlBody({ op: "subscribe", entityIds: ["e1"], bundle: true }),
			),
		);
		await flush();
		const producer = fakeWs();
		core.handlers.onOpen(producer);
		const live = frame(header("e1"), enc.encode("live1"));
		core.handlers.onMessage(producer, channel(FRAME_CHANNEL_BYTE, live));
		await flush();
		const frames = deliveredFrames(sub);
		expect(frames.length).toBe(1);
		expect(frames[0]).toEqual(live);
		expect(deliveredBundles(sub).length).toBe(0);
	});
});
