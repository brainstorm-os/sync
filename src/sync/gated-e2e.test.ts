/**
 * SYNC-4b — real-WebSocket end-to-end for the GATED node: a node booted with an
 * entitlement keyset challenges every connection; a client that completes the
 * token + identity handshake can co-edit, and an unauthenticated client's
 * frames are dropped. Proves the `Bun.serve` upgrade + async `startNode` +
 * IP-stamping wiring the socket-free `gated-server.test.ts` can't.
 */

import { afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ENTITLEMENT_TOKEN_VERSION, type EntitlementClaims, PlanTier } from "../entitlement";
import { type Config, startNode } from "../main";
import { PROTOCOL_VERSION, WireKind } from "../wire";

const FRAME_BYTE = 0x01;
const CONTROL_BYTE = 0x00;
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
const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

let billingPriv: CryptoKey;
let pubB64: string;
let identity: CryptoKeyPair;
let account: string;

beforeAll(async () => {
	const billing = await genKeypair();
	billingPriv = billing.privateKey;
	pubB64 = b64(new Uint8Array(await crypto.subtle.exportKey("raw", billing.publicKey)));
	identity = await genKeypair();
	account = b64(new Uint8Array(await crypto.subtle.exportKey("raw", identity.publicKey)));
});

async function signToken(): Promise<string> {
	const claims: EntitlementClaims = {
		v: ENTITLEMENT_TOKEN_VERSION,
		sub: "acc_e2e",
		plan: PlanTier.Plus,
		features: ["hosted-relay"],
		iat: 0,
		softExp: 9_999_999_999,
		hardExp: 9_999_999_999,
		iss: "billing-edge",
	};
	const h = b64(JSON.stringify({ alg: "EdDSA", kid: "k1" }));
	const c = b64(JSON.stringify(claims));
	const sig = new Uint8Array(
		await crypto.subtle.sign({ name: "Ed25519" }, billingPriv, data(`${h}.${c}`)),
	);
	return `${h}.${c}.${b64(sig)}`;
}

async function signNonce(nonce: string): Promise<string> {
	const sig = await crypto.subtle.sign(
		{ name: "Ed25519" },
		identity.privateKey,
		new Uint8Array(Buffer.from(nonce, "base64url")),
	);
	return b64(new Uint8Array(sig));
}

function frame(entityId: string, kind: WireKind, sender: string, ct: Uint8Array): Uint8Array {
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

function controlReplies(ws: { inbox: Uint8Array[] }): Array<Record<string, unknown>> {
	return ws.inbox
		.filter((m) => m[0] === CONTROL_BYTE)
		.map((m) => JSON.parse(dec.decode(m.subarray(1))) as Record<string, unknown>);
}

/** Drive the gated handshake on a freshly-connected client. */
async function handshake(ws: {
	inbox: Uint8Array[];
	send: (d: Uint8Array) => void;
}): Promise<void> {
	let challenge: string | undefined;
	for (let i = 0; i < 40 && !challenge; i++) {
		const c = controlReplies(ws).find((r) => r.op === "challenge");
		if (c) challenge = c.nonce as string;
		else await delay(10);
	}
	if (!challenge) throw new Error("no challenge received");
	const sig = await signNonce(challenge);
	ws.send(
		channel(
			CONTROL_BYTE,
			enc.encode(JSON.stringify({ op: "auth", token: await signToken(), account, sig })),
		),
	);
	await delay(40);
}

function gatedConfig(port: number, dir: string): Config {
	return {
		port,
		auditLogPath: null,
		storage: { kind: "local", dir },
		entitlement: { keys: { k1: pubB64 }, requiredFeature: null, authTimeoutMs: 10_000 },
		meteringLogPath: null,
		limits: null,
		assetGc: { graceMs: 1000, retentionMs: 10_000, sweepIntervalMs: null },
		debug: false,
	};
}

describe("gated node — real WebSocket E2E (SYNC-4b)", () => {
	let dir: string;
	beforeEach(async () => {
		dir = await mkdtemp(join(tmpdir(), "bs-sync-gated-"));
	});
	afterEach(async () => {
		await rm(dir, { recursive: true, force: true });
	});

	test("authenticated clients co-edit; an unauthenticated client cannot emit", async () => {
		const { server } = await startNode(gatedConfig(0, dir));
		try {
			const a = await connect(server.port);
			const b = await connect(server.port);
			await handshake(a);
			await handshake(b);
			expect(controlReplies(a).some((r) => r.op === "auth-ok")).toBe(true);

			b.send(
				channel(
					CONTROL_BYTE,
					enc.encode(JSON.stringify({ op: "subscribe", entityIds: ["ent_1"] })),
				),
			);
			await delay(30);
			a.send(channel(FRAME_BYTE, frame("ent_1", WireKind.Update, account, enc.encode("hi"))));
			await delay(80);

			const got = b.inbox.filter((m) => m[0] === FRAME_BYTE).map((m) => dec.decode(m.subarray(-2)));
			expect(got).toEqual(["hi"]);

			// An unauthenticated client's frame is dropped (never reaches b).
			const c = await connect(server.port);
			c.send(channel(FRAME_BYTE, frame("ent_1", WireKind.Update, account, enc.encode("no"))));
			await delay(60);
			const after = b.inbox.filter((m) => m[0] === FRAME_BYTE).length;
			expect(after).toBe(1);
			a.close();
			b.close();
			c.close();
		} finally {
			server.stop(true);
		}
	});
});
