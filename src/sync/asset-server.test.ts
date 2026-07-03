/**
 * Asset-B3/B6 — the asset channel wired through `createRelayCore` (socket-free,
 * mirrors `durable.test.ts`). A client PUT/GET/HAS/REFS on channel `0x02`
 * reaches the CAS + GC and replies point-to-point, ingress/egress is metered,
 * and a node with no asset plane (or, gated, an unauthenticated connection)
 * drops the frame.
 */

import { describe, expect, test } from "bun:test";
import { AssetWireKind, encodeAssetRequest } from "../asset-wire";
import { MeterKind } from "../metering";
import { type ServerWebSocketLike, createRelayCore } from "../server";
import { MemoryAssetCas } from "./asset-cas";
import { AssetGc } from "./asset-gc";
import { MemoryRefLedger } from "./ref-ledger";

const ASSET_BYTE = 0x02;
const enc = new TextEncoder();
const HASH = "a1b2c3d4".repeat(8);

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

function channel(byte: number, body: Uint8Array): Uint8Array {
	const out = new Uint8Array(1 + body.length);
	out[0] = byte;
	out.set(body, 1);
	return out;
}

/** Asset responses delivered on the asset channel, header + trailing chunk. */
function assetReplies(ws: { sent: Uint8Array[] }): Array<{
	header: Record<string, unknown>;
	chunk: Uint8Array;
}> {
	return ws.sent
		.filter((m) => m[0] === ASSET_BYTE)
		.map((m) => {
			const body = m.subarray(1);
			const len = new DataView(body.buffer, body.byteOffset, body.byteLength).getUint32(0, false);
			return {
				header: JSON.parse(new TextDecoder().decode(body.subarray(4, 4 + len))),
				chunk: body.subarray(4 + len),
			};
		});
}

const flush = () => new Promise((r) => setTimeout(r, 10));

describe("asset channel through createRelayCore", () => {
	test("PUT → GET → HAS round-trips and meters ingress/egress", async () => {
		const events: Array<{ kind: MeterKind; bytes: number }> = [];
		const cas = new MemoryAssetCas();
		const core = createRelayCore({
			assetCas: cas,
			meter: (e) => events.push({ kind: e.kind, bytes: e.bytes }),
		});
		const ws = fakeWs();
		core.handlers.onOpen(ws);

		const chunk = crypto.getRandomValues(new Uint8Array(3000));
		core.handlers.onMessage(
			ws,
			channel(ASSET_BYTE, encodeAssetRequest({ kind: AssetWireKind.Put, hash: HASH, chunk })),
		);
		await flush();
		expect(await cas.has(HASH)).toBe(true);
		let replies = assetReplies(ws);
		expect(replies.at(-1)?.header).toEqual({ k: AssetWireKind.Put, ok: true });
		expect(events.some((e) => e.kind === MeterKind.Ingress && e.bytes === chunk.length)).toBe(true);

		core.handlers.onMessage(
			ws,
			channel(ASSET_BYTE, encodeAssetRequest({ kind: AssetWireKind.Get, hash: HASH })),
		);
		await flush();
		replies = assetReplies(ws);
		const got = replies.at(-1);
		expect(got?.header).toEqual({ k: AssetWireKind.Get, found: true });
		expect(Buffer.from(got?.chunk ?? new Uint8Array()).equals(Buffer.from(chunk))).toBe(true);
		expect(events.some((e) => e.kind === MeterKind.Egress && e.bytes === chunk.length)).toBe(true);

		core.handlers.onMessage(
			ws,
			channel(ASSET_BYTE, encodeAssetRequest({ kind: AssetWireKind.Has, hash: HASH })),
		);
		await flush();
		expect(assetReplies(ws).at(-1)?.header).toEqual({ k: AssetWireKind.Has, present: true });
	});

	test("GET of an absent chunk replies not-found", async () => {
		const core = createRelayCore({ assetCas: new MemoryAssetCas() });
		const ws = fakeWs();
		core.handlers.onOpen(ws);
		core.handlers.onMessage(
			ws,
			channel(ASSET_BYTE, encodeAssetRequest({ kind: AssetWireKind.Get, hash: "f".repeat(64) })),
		);
		await flush();
		expect(assetReplies(ws).at(-1)?.header).toEqual({ k: AssetWireKind.Get, found: false });
	});

	test("a node with no asset plane drops asset frames (no reply)", async () => {
		const core = createRelayCore({}); // no assetCas
		const ws = fakeWs();
		core.handlers.onOpen(ws);
		core.handlers.onMessage(
			ws,
			channel(ASSET_BYTE, encodeAssetRequest({ kind: AssetWireKind.Has, hash: HASH })),
		);
		await flush();
		expect(assetReplies(ws).length).toBe(0);
	});

	test("a Refs report on an open node lands in the ledger, keyed by the header account", async () => {
		const cas = new MemoryAssetCas();
		const ledger = new MemoryRefLedger();
		const gc = new AssetGc({ cas, ledger, now: () => 1234 });
		const core = createRelayCore({ assetCas: cas, assetGc: gc });
		const ws = fakeWs();
		core.handlers.onOpen(ws);
		core.handlers.onMessage(
			ws,
			channel(
				ASSET_BYTE,
				encodeAssetRequest({
					kind: AssetWireKind.Refs,
					account: "acct",
					device: "laptop",
					hashes: [HASH],
				}),
			),
		);
		await flush();
		expect(assetReplies(ws).at(-1)?.header).toEqual({ k: AssetWireKind.Refs, ok: true, count: 1 });
		const state = await ledger.read("acct");
		expect(state.devices.laptop).toEqual({ lastReportAt: 1234, refs: [HASH] });
	});

	test("a Refs report on a node with no GC plane is dropped (no reply)", async () => {
		const core = createRelayCore({ assetCas: new MemoryAssetCas() }); // no assetGc
		const ws = fakeWs();
		core.handlers.onOpen(ws);
		core.handlers.onMessage(
			ws,
			channel(
				ASSET_BYTE,
				encodeAssetRequest({ kind: AssetWireKind.Refs, account: "a", device: "d", hashes: [] }),
			),
		);
		await flush();
		expect(assetReplies(ws).length).toBe(0);
	});

	test("a malformed asset request is dropped, not crashed", async () => {
		const core = createRelayCore({ assetCas: new MemoryAssetCas() });
		const ws = fakeWs();
		core.handlers.onOpen(ws);
		// Bad address (not 64-hex) → decode throws → handler drops it.
		core.handlers.onMessage(
			ws,
			channel(ASSET_BYTE, encodeAssetRequest({ kind: AssetWireKind.Get, hash: "nope" })),
		);
		await flush();
		expect(assetReplies(ws).length).toBe(0);
	});
});
