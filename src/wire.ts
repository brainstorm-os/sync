/**
 * Wire decoder — the routing header the relay peeks at.
 *
 * **Cross-plane contract.** This is the sync plane's half of the wire format
 * the Brainstorm client speaks (the product's `packages/shell/src/main/sync`
 * envelope codec is the canonical source). It is deliberately a standalone copy
 * — this repo imports NOTHING from the product, exactly as the product's own
 * `packages/relay-server` keeps its own copy. The two move in lockstep on the
 * wire format only; that format is the contract (the sync analog of the
 * control plane's `api-client`).
 *
 * **Relay-blind invariant.** This module — and every module on the route path —
 * must not import any crypto / credential / envelope-seal code. The node reads
 * the routing header for fan-out + the audit log and forwards the ciphertext
 * body untouched; it can NEVER decode it (it holds no key). See CLAUDE.md.
 *
 * Wire layout (matches the client's envelope codec):
 *
 *   u32-be(headerLen) || canonicalHeaderBytes
 *     || u16-be(sigLen=64) || sig
 *     || u32-be(ctLen) || ciphertext
 *
 * The relay reads `headerLen` + the canonical header bytes; parses the header
 * (entity-id + sender for the audit log + kind for routing) and forwards the
 * entire untouched frame to subscribers. The ciphertext after the header is
 * opaque — the relay never decodes it.
 */

export const PROTOCOL_VERSION = 1 as const;
export const ED25519_SIG_BYTES = 64;

export enum WireKind {
	Update = "update",
	Snapshot = "snapshot",
	WrapBootstrap = "wrap-bootstrap",
	/** Pairing handshake transport (routed by `pairingChannelId` as the
	 *  `entityId`). The relay never inspects the body — same as every kind. */
	Pairing = "pairing",
	/** Transient awareness updates (cursor / presence). Body is sealed under
	 *  the entity DEK, opaque to the relay just like `Update` frames. */
	Awareness = "awareness",
}

export type RoutingHeader = {
	v: number;
	kind: WireKind;
	entityId: string;
	sender: string;
	seq: number;
	nonce: string;
	ts: number;
};

const KIND_SET = new Set<string>(Object.values(WireKind));
const DECODER = new TextDecoder();

/**
 * Strict-shape parse of canonical routing-header bytes. Throws `Invalid`
 * (named Error, kind="Invalid") on any deviation — wrong protocol version,
 * missing field, wrong type, unknown `kind`.
 */
export function parseRoutingHeaderJson(bytes: Uint8Array): RoutingHeader {
	let parsed: unknown;
	try {
		parsed = JSON.parse(DECODER.decode(bytes));
	} catch (error) {
		throw invalid(`routing header: malformed JSON (${(error as Error).message})`);
	}
	return assertHeader(parsed);
}

/**
 * Peek the routing header of a wire-framed envelope. Throws `Invalid` on any
 * structural deviation. Does NOT decode the ciphertext (it cannot — no key)
 * and does NOT verify the signature (the recipient is the last line of
 * defense). Returns `{ header, byteLength }` so the relay can log `byteLength`
 * without re-measuring the buffer.
 */
export function peekRoutingHeader(frame: Uint8Array): {
	header: RoutingHeader;
	byteLength: number;
} {
	if (frame.length < 4) throw invalid("peekRoutingHeader: truncated header length");
	const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
	const headerLen = view.getUint32(0, false);
	if (headerLen <= 0 || 4 + headerLen > frame.length) {
		throw invalid("peekRoutingHeader: truncated header bytes");
	}
	const headerBytes = frame.subarray(4, 4 + headerLen);
	const header = parseRoutingHeaderJson(headerBytes);
	return { header, byteLength: frame.length };
}

function assertHeader(value: unknown): RoutingHeader {
	if (!value || typeof value !== "object") {
		throw invalid("routing header: not an object");
	}
	const h = value as Record<string, unknown>;
	if (h.v !== PROTOCOL_VERSION) {
		throw invalid(`routing header: unsupported v=${String(h.v)} (expected ${PROTOCOL_VERSION})`);
	}
	if (typeof h.kind !== "string" || !KIND_SET.has(h.kind)) {
		throw invalid(`routing header: unknown kind=${String(h.kind)}`);
	}
	if (typeof h.entityId !== "string" || h.entityId === "") {
		throw invalid("routing header: entityId must be a non-empty string");
	}
	if (typeof h.sender !== "string" || h.sender === "") {
		throw invalid("routing header: sender must be a non-empty string");
	}
	if (typeof h.seq !== "number" || !Number.isFinite(h.seq)) {
		throw invalid("routing header: seq must be a finite number");
	}
	if (typeof h.nonce !== "string" || h.nonce === "") {
		throw invalid("routing header: nonce must be a non-empty string");
	}
	if (typeof h.ts !== "number" || !Number.isFinite(h.ts)) {
		throw invalid("routing header: ts must be a finite number");
	}
	return {
		v: h.v,
		kind: h.kind as WireKind,
		entityId: h.entityId,
		sender: h.sender,
		seq: h.seq,
		nonce: h.nonce,
		ts: h.ts,
	};
}

function invalid(message: string): Error {
	const err = new Error(message);
	err.name = "Invalid";
	return err;
}

/**
 * 10.10 — bundled-backfill payload framing (server→client, channel `0x03`).
 *
 * A bundle packs many wire frames into ONE WebSocket message so a fresh-device
 * bootstrap (10.14 restore) doesn't pay a message per `wrap/snapshot/tail`
 * frame. It is pure FRAMING: each sub-frame is byte-identical to the frame
 * that would have ridden its own `0x01` message — still an opaque ciphertext
 * envelope the node never decodes (relay-blind preserved).
 *
 * Layout: repeated `u32-be(subFrameLen) || subFrameBytes`, no count prefix —
 * the lengths must consume the payload exactly.
 */
export function encodeBundlePayload(frames: readonly Uint8Array[]): Uint8Array {
	if (frames.length === 0) throw invalid("bundle: refusing to encode an empty bundle");
	let total = 0;
	for (const frame of frames) {
		if (frame.length === 0) throw invalid("bundle: refusing to encode an empty sub-frame");
		total += 4 + frame.length;
	}
	const out = new Uint8Array(total);
	const view = new DataView(out.buffer);
	let offset = 0;
	for (const frame of frames) {
		view.setUint32(offset, frame.length, false);
		offset += 4;
		out.set(frame, offset);
		offset += frame.length;
	}
	return out;
}

/**
 * Strict decode of a bundle payload (the bytes after the `0x03` channel byte).
 * Throws `Invalid` on any deviation — empty payload, truncated length prefix,
 * zero-length sub-frame, or a length that overruns / underruns the payload.
 * Each returned sub-frame is a copy (safe to retain past the message buffer).
 */
export function decodeBundlePayload(payload: Uint8Array): Uint8Array[] {
	if (payload.length === 0) throw invalid("bundle: empty payload");
	const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
	const frames: Uint8Array[] = [];
	let offset = 0;
	while (offset < payload.length) {
		if (offset + 4 > payload.length) throw invalid("bundle: truncated sub-frame length");
		const len = view.getUint32(offset, false);
		offset += 4;
		if (len === 0) throw invalid("bundle: zero-length sub-frame");
		if (offset + len > payload.length) throw invalid("bundle: sub-frame overruns payload");
		frames.push(new Uint8Array(payload.subarray(offset, offset + len)));
		offset += len;
	}
	return frames;
}
