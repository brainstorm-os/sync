/**
 * Asset-B3 — the node's copy of the blob-plane wire protocol (`WireKind.Asset`,
 * Asset-B2). Mirrors the shell's `packages/shell/src/main/assets/asset-wire.ts`
 * byte-for-byte (kept in lockstep, the way the relay duplicates `wire.ts`) so a
 * shell `WireAssetCas` talks to this node unchanged. This file is the
 * **responder** side: decode a request, apply it to a local `AssetCas`, encode
 * the response.
 *
 * The verbs are `Has` (skip already-present), `Put` (store a sealed chunk),
 * `Get` (fetch one) keyed by the ciphertext-hash, and `Refs` (Asset-B6 — a
 * device posts the FULL set of chunk hashes its converged vault state still
 * references, feeding the node-side GC ref ledger). Framing:
 * `u32-be(headerLen) || JSON header || trailing chunk` (chunk present on a Put
 * request and a found Get response; on a Refs request the trailing chunk is
 * the ref-set itself — concatenated 64-hex ASCII addresses, so a large report
 * never bloats the JSON header).
 *
 * **Relay-blind.** The hash is an opaque address (the node never computes it —
 * the client content-addresses + verifies). It is, however, VALIDATED here as
 * `[0-9a-f]{64}` at this untrusted wire edge so a hostile "hash" can't smuggle
 * a non-address into the store (path-traversal defense). No crypto. See
 * CLAUDE.md.
 */

import { type AssetCas, isAssetHash } from "./sync/asset-cas";

export enum AssetWireKind {
	Has = "has",
	Put = "put",
	Get = "get",
	/** Asset-B6 — a device's full-set ref report (idempotent replace). */
	Refs = "refs",
}

/** Bounds on the untrusted Refs identity strings (the account is a base64url
 *  pubkey ≤ ~64 chars; the device id is a client-minted opaque id). */
const MAX_ACCOUNT_CHARS = 256;
const MAX_DEVICE_CHARS = 128;
const HEX_HASH_CHARS = 64;

/**
 * Asset-B6 — the GC surface the wire hands a decoded report to. Structural
 * (implemented by `sync/asset-gc.ts` `AssetGc`) so this file stays a
 * standalone protocol mirror with zero engine coupling.
 */
export interface AssetGcHooks {
	/** A stored chunk is attributed to the (proven) uploader; re-PUT un-marks. */
	onPut(account: string | null, hash: string, bytes: number): Promise<void>;
	/** A device's full converged ref-set (idempotent replace). */
	onReport(account: string, device: string, hashes: string[]): Promise<void>;
}

/** Per-request context the server injects: the GC hooks (absent ⇒ the node has
 *  no GC plane; Refs is unsupported) and the connection's PROVEN account (a
 *  gated node forces it, like the catalog — a client can't report or attribute
 *  as someone else). Null account = open node (report header account is used;
 *  same trust posture as the open-admission catalog, OQ-SYNC-2). */
export type AssetRequestContext = {
	gc?: AssetGcHooks;
	account?: string | null;
};

function invalid(message: string): Error {
	const err = new Error(message);
	err.name = "Invalid";
	return err;
}

/** `u32-be(headerLen) || headerJSON || trailingChunk`. */
function frame(header: unknown, chunk?: Uint8Array): Uint8Array {
	const headerBytes = new TextEncoder().encode(JSON.stringify(header));
	const tail = chunk ?? new Uint8Array(0);
	const out = new Uint8Array(4 + headerBytes.length + tail.length);
	new DataView(out.buffer).setUint32(0, headerBytes.length, false);
	out.set(headerBytes, 4);
	out.set(tail, 4 + headerBytes.length);
	return out;
}

function unframe(bytes: Uint8Array): { header: Record<string, unknown>; chunk: Uint8Array } {
	if (!(bytes instanceof Uint8Array) || bytes.length < 4) {
		throw invalid("asset frame: too short for a length prefix");
	}
	const headerLen = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(
		0,
		false,
	);
	if (headerLen <= 0 || 4 + headerLen > bytes.length) {
		throw invalid("asset frame: header length out of range");
	}
	let header: unknown;
	try {
		header = JSON.parse(new TextDecoder().decode(bytes.subarray(4, 4 + headerLen)));
	} catch {
		throw invalid("asset frame: header is not valid JSON");
	}
	if (!header || typeof header !== "object" || Array.isArray(header)) {
		throw invalid("asset frame: header is not an object");
	}
	return { header: header as Record<string, unknown>, chunk: bytes.subarray(4 + headerLen) };
}

export type AssetRequest =
	| { kind: AssetWireKind.Has; hash: string }
	| { kind: AssetWireKind.Put; hash: string; chunk: Uint8Array }
	| { kind: AssetWireKind.Get; hash: string }
	| { kind: AssetWireKind.Refs; account: string; device: string; hashes: string[] };

/** Encode a request (symmetric with {@link decodeAssetRequest}) — used by the
 *  node's tests + any node-side client. The shell builds these in production. */
export function encodeAssetRequest(req: AssetRequest): Uint8Array {
	if (req.kind === AssetWireKind.Put) return frame({ k: req.kind, hash: req.hash }, req.chunk);
	if (req.kind === AssetWireKind.Refs) {
		return frame(
			{ k: req.kind, account: req.account, device: req.device },
			new TextEncoder().encode(req.hashes.join("")),
		);
	}
	return frame({ k: req.kind, hash: req.hash });
}

const KINDS = new Set<string>([
	AssetWireKind.Has,
	AssetWireKind.Put,
	AssetWireKind.Get,
	AssetWireKind.Refs,
]);

function nonEmptyString(value: unknown, max: number): value is string {
	return typeof value === "string" && value.length > 0 && value.length <= max;
}

/** Split a Refs trailing chunk (concatenated 64-hex ASCII addresses) into
 *  validated hashes. Throws `Invalid` on a ragged length or a non-address. */
function decodeRefSet(chunk: Uint8Array): string[] {
	if (chunk.length % HEX_HASH_CHARS !== 0) {
		throw invalid("asset request: ref-set length must be a multiple of 64");
	}
	const text = new TextDecoder().decode(chunk);
	const hashes: string[] = [];
	for (let i = 0; i < text.length; i += HEX_HASH_CHARS) {
		const hash = text.slice(i, i + HEX_HASH_CHARS);
		if (!isAssetHash(hash)) throw invalid("asset request: ref-set entry must be 64-hex");
		hashes.push(hash);
	}
	return hashes;
}

/** Decode + VALIDATE an untrusted client request. Throws `Invalid` on a bad
 *  kind, a non-`[0-9a-f]{64}` address, or a malformed ref report. */
export function decodeAssetRequest(bytes: Uint8Array): AssetRequest {
	const { header, chunk } = unframe(bytes);
	const k = header.k;
	if (typeof k !== "string" || !KINDS.has(k)) throw invalid(`asset request: bad kind ${String(k)}`);
	if (k === AssetWireKind.Refs) {
		if (!nonEmptyString(header.account, MAX_ACCOUNT_CHARS)) {
			throw invalid("asset request: refs needs an account");
		}
		if (!nonEmptyString(header.device, MAX_DEVICE_CHARS)) {
			throw invalid("asset request: refs needs a device id");
		}
		return {
			kind: AssetWireKind.Refs,
			account: header.account,
			device: header.device,
			hashes: decodeRefSet(chunk),
		};
	}
	if (!isAssetHash(header.hash)) throw invalid("asset request: address must be 64-hex");
	const hash = header.hash;
	if (k === AssetWireKind.Put)
		return { kind: AssetWireKind.Put, hash, chunk: new Uint8Array(chunk) };
	if (k === AssetWireKind.Get) return { kind: AssetWireKind.Get, hash };
	return { kind: AssetWireKind.Has, hash };
}

export function encodeHasResponse(present: boolean): Uint8Array {
	return frame({ k: AssetWireKind.Has, present });
}
export function encodePutResponse(ok: boolean): Uint8Array {
	return frame({ k: AssetWireKind.Put, ok });
}
export function encodeGetResponse(chunk: Uint8Array | null): Uint8Array {
	return chunk
		? frame({ k: AssetWireKind.Get, found: true }, chunk)
		: frame({ k: AssetWireKind.Get, found: false });
}
export function encodeRefsResponse(count: number): Uint8Array {
	return frame({ k: AssetWireKind.Refs, ok: true, count });
}

/** The result of serving one asset request: the verb (so the caller meters a
 *  `Put` as ingress vs a `Get` as egress), the response frame to send back to
 *  the requesting connection, and the chunk byte count to meter (the chunk size
 *  on a Put / a found Get; 0 for Has / a miss). */
export type AssetServeResult = { kind: AssetWireKind; response: Uint8Array; meteredBytes: number };

/**
 * Decode a request, apply it to `cas` (and, for Put/Refs, the GC hooks), and
 * return the verb + response frame + metered byte count. Pure routing — never
 * touches a key. The node-side counterpart to the shell's `serveAssetRequest`.
 * Throws `Invalid` on a malformed request or a Refs report on a node with no
 * GC plane (the caller drops it).
 */
export async function handleAssetRequest(
	cas: AssetCas,
	request: Uint8Array,
	ctx?: AssetRequestContext,
): Promise<AssetServeResult> {
	const req = decodeAssetRequest(request);
	if (req.kind === AssetWireKind.Refs) {
		if (!ctx?.gc) throw invalid("asset request: refs unsupported (no GC plane)");
		// Gated: the report is scoped to the PROVEN account — a forged header
		// account is ignored, mirroring the catalog-query forcing.
		const account = ctx.account ?? req.account;
		await ctx.gc.onReport(account, req.device, req.hashes);
		return { kind: req.kind, response: encodeRefsResponse(req.hashes.length), meteredBytes: 0 };
	}
	if (req.kind === AssetWireKind.Has) {
		return {
			kind: req.kind,
			response: encodeHasResponse(await cas.has(req.hash)),
			meteredBytes: 0,
		};
	}
	if (req.kind === AssetWireKind.Put) {
		await cas.put(req.hash, req.chunk);
		if (ctx?.gc) await ctx.gc.onPut(ctx.account ?? null, req.hash, req.chunk.length);
		return { kind: req.kind, response: encodePutResponse(true), meteredBytes: req.chunk.length };
	}
	const chunk = await cas.get(req.hash);
	return { kind: req.kind, response: encodeGetResponse(chunk), meteredBytes: chunk?.length ?? 0 };
}
