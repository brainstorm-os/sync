/**
 * SYNC-2 — real-WebSocket end-to-end: the durable node, booted under
 * `Bun.serve`, persists what one client sends and **backfills a cold client**
 * that connects later. This exercises the full deployed path (WS upgrade,
 * binary frames, the `STORAGE_DIR` FileSnapshotStore) — the socket-free
 * `durable.test.ts` covers the routing logic; this proves it over the wire.
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Config, startNode } from "../main";
import { PROTOCOL_VERSION, WireKind } from "../wire";

const FRAME_BYTE = 0x01;
const CONTROL_BYTE = 0x00;
const enc = new TextEncoder();
const dec = new TextDecoder();

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

function header(entityId: string, kind: WireKind, sender = "s") {
	return { v: PROTOCOL_VERSION, kind, entityId, sender, seq: 0, nonce: "n", ts: 1 };
}

function channel(byte: number, body: Uint8Array): Uint8Array {
	const out = new Uint8Array(1 + body.length);
	out[0] = byte;
	out.set(body, 1);
	return out;
}

const subBody = (entityIds: string[]) => enc.encode(JSON.stringify({ op: "subscribe", entityIds }));
const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

function connect(port: number): Promise<WebSocket & { inbox: Uint8Array[] }> {
	return new Promise((resolve, reject) => {
		const ws = new WebSocket(`ws://127.0.0.1:${port}`) as WebSocket & { inbox: Uint8Array[] };
		ws.binaryType = "arraybuffer";
		ws.inbox = [];
		ws.addEventListener("message", (e) => {
			if (e.data instanceof ArrayBuffer) ws.inbox.push(new Uint8Array(e.data));
		});
		ws.addEventListener("open", () => resolve(ws));
		ws.addEventListener("error", () => reject(new Error("ws connect failed")));
	});
}

function testConfig(port: number, storageDir: string): Config {
	return {
		port,
		auditLogPath: null,
		storage: { kind: "local", dir: storageDir },
		entitlement: null,
		meteringLogPath: null,
		limits: null,
		assetGc: { graceMs: 1000, retentionMs: 10_000, sweepIntervalMs: null },
		debug: false,
	};
}

describe("durable node — real WebSocket E2E (SYNC-2)", () => {
	let dir: string;
	beforeEach(async () => {
		dir = await mkdtemp(join(tmpdir(), "bs-sync-e2e-"));
	});
	afterEach(async () => {
		await rm(dir, { recursive: true, force: true });
	});

	test("a cold client that connects after the fact is backfilled snapshot ++ tail", async () => {
		const { server } = await startNode(testConfig(0, dir));
		try {
			// Producer connects, subscribes, uploads a snapshot + a tail update.
			const a = await connect(server.port);
			a.send(channel(CONTROL_BYTE, subBody(["ent_1"])));
			a.send(channel(FRAME_BYTE, frame(header("ent_1", WireKind.Snapshot), enc.encode("S1"))));
			a.send(channel(FRAME_BYTE, frame(header("ent_1", WireKind.Update), enc.encode("u1"))));
			await delay(80); // let the FileSnapshotStore persist
			a.close();
			await delay(40);

			// A cold device connects later + subscribes — the node replays state.
			const b = await connect(server.port);
			b.send(channel(CONTROL_BYTE, subBody(["ent_1"])));
			await delay(120);

			const frames = b.inbox.filter((m) => m[0] === FRAME_BYTE).map((m) => m.subarray(1));
			expect(frames.length).toBe(2);
			// Each delivered frame ends with its 2-byte ciphertext.
			expect(frames.map((f) => dec.decode(f.subarray(-2)))).toEqual(["S1", "u1"]);
			b.close();
		} finally {
			server.stop(true);
		}
	});

	test("a cold device can enumerate its account's entities via a catalog query (SYNC-4a)", async () => {
		const { server } = await startNode(testConfig(0, dir));
		try {
			// One device emits doc-state for two entities under account "acct-X".
			const a = await connect(server.port);
			a.send(channel(CONTROL_BYTE, subBody(["ent_a", "ent_b"])));
			a.send(
				channel(FRAME_BYTE, frame(header("ent_a", WireKind.Snapshot, "acct-X"), enc.encode("A"))),
			);
			a.send(
				channel(FRAME_BYTE, frame(header("ent_b", WireKind.Update, "acct-X"), enc.encode("B"))),
			);
			await delay(80);
			a.close();
			await delay(40);

			// A fresh device (recovered identity = same account) asks the node
			// which entities the account has — the cold-restore enumeration.
			const b = await connect(server.port);
			b.send(
				channel(CONTROL_BYTE, enc.encode(JSON.stringify({ op: "catalog", account: "acct-X" }))),
			);
			await delay(120);

			const reply = b.inbox
				.filter((m) => m[0] === CONTROL_BYTE)
				.map((m) => JSON.parse(dec.decode(m.subarray(1))) as Record<string, unknown>)
				.find((r) => r.op === "catalog-result") as
				| { account: string; entities: Array<{ entityId: string; version: number }> }
				| undefined;
			expect(reply?.account).toBe("acct-X");
			expect((reply?.entities ?? []).map((e) => e.entityId).sort()).toEqual(["ent_a", "ent_b"]);
			b.close();
		} finally {
			server.stop(true);
		}
	});

	test("durability survives a node restart (snapshot+tail read from disk)", async () => {
		const first = await startNode(testConfig(0, dir));
		try {
			const a = await connect(first.server.port);
			a.send(channel(CONTROL_BYTE, subBody(["ent_2"])));
			a.send(channel(FRAME_BYTE, frame(header("ent_2", WireKind.Snapshot), enc.encode("SS"))));
			await delay(80);
			a.close();
			await delay(40);
		} finally {
			first.server.stop(true);
		}
		await delay(40);

		// A brand-new node process over the SAME storage dir still has it.
		const second = await startNode(testConfig(0, dir));
		try {
			const b = await connect(second.server.port);
			b.send(channel(CONTROL_BYTE, subBody(["ent_2"])));
			await delay(120);
			const frames = b.inbox.filter((m) => m[0] === FRAME_BYTE).map((m) => m.subarray(1));
			expect(frames.map((f) => dec.decode(f.subarray(-2)))).toEqual(["SS"]);
			b.close();
		} finally {
			second.server.stop(true);
		}
	});
});
