/**
 * SYNC-4b — usage metering.
 *
 * On a gated node every admitted connection carries a verified billing account
 * (`sub`) and a proven wire account. The node emits metering events the
 * commercial plane (`brainstorm-cloud` billing-edge) ingests to bill hosted
 * storage / egress. This module is just the event shape + sink type; the node
 * fans events to a sink (an NDJSON file in `main.ts`, a network push later).
 *
 * **Relay-blind.** Events carry byte COUNTS + plaintext routing ids (entity,
 * account) — the same metadata the audit log already holds. Never ciphertext,
 * never a key. No crypto. See CLAUDE.md.
 */

export enum MeterKind {
	/** A connection was admitted (gated handshake completed). */
	Connect = "connect",
	/** Bytes the node accepted + routed for an account (uploads). */
	Ingress = "ingress",
	/** Bytes the node served to a subscriber (backfill / fan-out downloads). */
	Egress = "egress",
	/** Asset-B6 — stored chunk bytes the GC sweep reclaimed for an account
	 *  (billing sees hosted storage shrink; the byte count is ciphertext size,
	 *  never content). */
	Reclaim = "reclaim",
}

export type MeterEvent = {
	ts: number;
	kind: MeterKind;
	/** Wire account (sender / identity pubkey), when known. */
	account: string | null;
	/** Billing account (entitlement token `sub`), when admitted. */
	sub: string | null;
	plan: string | null;
	bytes: number;
	entityId?: string;
};

export type MeterSink = (event: MeterEvent) => void;
