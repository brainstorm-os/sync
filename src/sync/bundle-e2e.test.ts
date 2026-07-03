/**
 * 10.10 — real-WebSocket end-to-end for bundled bootstrap backfill: a cold
 * client that subscribes its whole catalog with `bundle:true` receives the
 * same `wraps ++ snapshot ++ tail` bytes as a plain client, in a fraction of
 * the WebSocket messages. Proves the framing over the deployed path (WS
 * upgrade, binary frames, `STORAGE_DIR` FileSnapshotStore).
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Config, startNode } from "../main";
import { PROTOCOL_VERSION, WireKind, decodeBundlePayload } from "../wire";

const CONTROL_BYTE = 0x00;
const FRAME_BYTE = 0x01;
const BUNDLE_BYTE = 0x03;
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
		debug: false,
	};
}

describe("bundled bootstrap backfill — real WebSocket E2E (10.10)", () => {
	let dir: string;
	beforeEach(async () => {
		dir = await mkdtemp(join(tmpdir(), "bs-sync-bundle-e2e-"));
	});
	afterEach(async () => {
		await rm(dir, { recursive: true, force: true });
	});

	test("a bundled cold restore converges with the same bytes in far fewer messages", async () => {
		const { server } = await startNode(testConfig(0, dir));
		try {
			const ids = Array.from({ length: 12 }, (_, i) => `ent_${i}`);
			// Producer uploads wrap + snapshot + tail update per entity.
			const producer = await connect(server.port);
			producer.send(
				channel(CONTROL_BYTE, enc.encode(JSON.stringify({ op: "subscribe", entityIds: ids }))),
			);
			for (const id of ids) {
				producer.send(
					channel(FRAME_BYTE, frame(header(id, WireKind.WrapBootstrap), enc.encode(`W:${id}`))),
				);
				producer.send(
					channel(FRAME_BYTE, frame(header(id, WireKind.Snapshot), enc.encode(`S:${id}`))),
				);
				producer.send(
					channel(FRAME_BYTE, frame(header(id, WireKind.Update), enc.encode(`u:${id}`))),
				);
			}
			await delay(150); // let the FileSnapshotStore persist
			producer.close();
			await delay(50);

			// Old-style cold device: plain subscribe → one message per frame.
			const plain = await connect(server.port);
			plain.send(
				channel(CONTROL_BYTE, enc.encode(JSON.stringify({ op: "subscribe", entityIds: ids }))),
			);
			await delay(200);
			const plainFrames = plain.inbox.filter((m) => m[0] === FRAME_BYTE).map((m) => m.subarray(1));
			plain.close();

			// New-style cold device: ONE subscribe with bundle:true → bundle frames.
			const bundled = await connect(server.port);
			bundled.send(
				channel(
					CONTROL_BYTE,
					enc.encode(JSON.stringify({ op: "subscribe", entityIds: ids, bundle: true })),
				),
			);
			await delay(200);
			const bundleMessages = bundled.inbox.filter((m) => m[0] === BUNDLE_BYTE);
			const strayFrames = bundled.inbox.filter((m) => m[0] === FRAME_BYTE);
			bundled.close();

			const subFrames = bundleMessages.flatMap((m) => decodeBundlePayload(m.subarray(1)));
			expect(plainFrames.length).toBe(ids.length * 3); // 36 messages the old way
			expect(strayFrames.length).toBe(0);
			expect(bundleMessages.length).toBe(1); // one message the new way
			expect(subFrames.length).toBe(plainFrames.length);
			// The per-frame path backfills entities concurrently, so cross-entity
			// order is nondeterministic — compare the two streams as sets. The
			// deterministic per-entity + cross-entity ordering of the bundled path
			// is pinned socket-free in bundle.test.ts.
			const asSortedHex = (frames: Uint8Array[]) =>
				frames.map((f) => Buffer.from(f).toString("hex")).sort();
			expect(asSortedHex(subFrames)).toEqual(asSortedHex(plainFrames));
			// Wrap-first per entity survives the wire.
			expect(dec.decode((subFrames[0] as Uint8Array).subarray(-7))).toBe("W:ent_0");
			console.log(
				`[10.10 e2e] ${ids.length}-entity restore: ${plainFrames.length} messages → ${bundleMessages.length}`,
			);
		} finally {
			server.stop(true);
		}
	});
});
