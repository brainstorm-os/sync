/**
 * SYNC-2 — durable snapshot+tail store (the storage abstraction).
 *
 * Per OQ-SYNC-3 (resolved): the node stores the **same snapshot+tail shape the
 * client already produces**, as OPAQUE ciphertext blobs. It keeps a per-entity
 * latest-snapshot + an append-only tail of update frames since that snapshot;
 * a client-uploaded `Snapshot` frame is **client-driven compaction** — it bumps
 * the version and resets the tail. On (re)connect the node replays
 * `snapshot ++ tail` to the subscriber (offline backfill); the client's CRDT
 * merges idempotently, so the node never needs to know what the client already
 * has (it couldn't — it's blind).
 *
 * **Relay-blind.** This module is on the route path: it handles frame bytes as
 * opaque blobs and imports ZERO crypto. It reads only the `WireKind` enum from
 * `./wire` (a routing discriminant, not content). See CLAUDE.md.
 *
 * The interface is deliberately storage-agnostic so SYNC-3 can swap the backend
 * (local filesystem ↔ managed object storage ↔ self-hosted bucket) without
 * touching the server. `MemorySnapshotStore` here backs the tests + an
 * ephemeral run; `FileSnapshotStore` (file-snapshot-store.ts) is the durable
 * local backend.
 *
 * Account scoping `(account, entityId, version)` from OQ-SYNC-3 lands with the
 * verified-identity admission of SYNC-4; at SYNC-2 the key is `entityId` in a
 * single namespace (the connection isn't authenticated yet).
 */

import { WireKind } from "../wire";

export type BackfillData = {
	/** Latest snapshot version (0 if no snapshot has been uploaded yet). */
	version: number;
	/** Frames to replay in apply order: the snapshot (if any) followed by the
	 *  tail of updates since it. Each is a raw wire frame (no channel byte). */
	frames: Uint8Array[];
};

/** Cap on retained wraps per entity (bounds storage). A wrap is HPKE-sealed per
 *  recipient device; the node can't dedup by recipient (it's inside the sealed
 *  payload), so it keeps the most-recent N. N comfortably covers a personal /
 *  small-team entity's member×device set; a higher-churn entity falls back to
 *  the owner re-emitting a live wrap. */
export const WRAP_RETENTION = 64;

/**
 * 10.11 routing-token rotation — outcome of a client-driven storage re-home
 * (`migrate(from, to)`). The protocol is idempotent by construction: a client
 * that crashed mid-rotation re-sends the same `rotate {from, to}` and the store
 * converges — the entity's ciphertext is recoverable under at least one of the
 * two routing ids at every instant, and under exactly `to` once the migration
 * completes.
 */
export enum MigrateOutcome {
	/** Data moved `from → to`. */
	Moved = "moved",
	/** Nothing under `from`, data under `to` — a completed migration re-sent
	 *  (idempotent retry) — or a resumed journal with the source already gone. */
	AlreadyDone = "already-done",
	/** Neither id has data — nothing durable to move (forward-only rotation).
	 *  Still a success: the caller installs the routing alias regardless. */
	Nothing = "nothing",
	/** `to` is already occupied by a DIFFERENT migration/entity (or `from` has a
	 *  journal pointing elsewhere). Refused — a rotate must never overwrite
	 *  ciphertext it did not migrate itself. The caller denies the rotation and
	 *  the old routing id stays fully live (fail-closed). */
	Conflict = "conflict",
}

export interface SnapshotStore {
	/** Append one update frame to the entity's tail (since the last snapshot). */
	appendTail(entityId: string, frame: Uint8Array): Promise<void>;
	/** Store a client-uploaded full snapshot: bump the version and RESET the
	 *  tail (the snapshot subsumes every prior update). Returns the new version. */
	putSnapshot(entityId: string, frame: Uint8Array): Promise<number>;
	/** Retain a `WrapBootstrap` frame so a reconnecting device with its keystore
	 *  intact can recover the per-entity DEK from backfill (10.14 restore).
	 *  Survives compaction — the DEK is still needed after a snapshot. The node
	 *  holds only the HPKE-sealed wrap (it has no X25519 key — relay-blind). */
	appendWrap(entityId: string, frame: Uint8Array): Promise<void>;
	/** Wraps ++ snapshot ++ tail, in apply order, for offline backfill. Wraps
	 *  come FIRST so the device installs the DEK before applying the state. */
	readBackfill(entityId: string): Promise<BackfillData>;
	/** Latest snapshot version, or null if the entity has none. */
	latestVersion(entityId: string): Promise<number | null>;
	/** 10.11 routing-token rotation — re-home everything stored under `fromId`
	 *  (snapshot + meta + tail + wraps) to `toId`. Idempotent; never leaves a
	 *  state where the data is unreachable under BOTH ids (see `MigrateOutcome`).
	 *  The ids are opaque routing tokens to the node — no crypto, no content. */
	migrate(fromId: string, toId: string): Promise<MigrateOutcome>;
}

/**
 * The OQ-SYNC-3 persistence policy in one place: the durable node keeps
 * **doc-state** frames (`Update`→tail, `Snapshot`→compaction) **plus
 * `WrapBootstrap` frames** (the HPKE-sealed per-entity DEK wraps a reconnecting
 * device needs to decrypt the backfill — 10.14 restore; relay-blind, the node
 * can't open them). `Awareness` is transient and `Pairing` is a live handshake
 * — neither is persisted. Called fire-and-forget after a successful fan-out.
 */
export async function persistFrame(
	store: SnapshotStore,
	entityId: string,
	kind: WireKind,
	frame: Uint8Array,
): Promise<void> {
	if (kind === WireKind.Update) {
		await store.appendTail(entityId, frame);
	} else if (kind === WireKind.Snapshot) {
		await store.putSnapshot(entityId, frame);
	} else if (kind === WireKind.WrapBootstrap) {
		await store.appendWrap(entityId, frame);
	}
	// Awareness / Pairing: never persisted.
}

/** Defensive copy — the server hands us a view into a reused message buffer. */
function copy(frame: Uint8Array): Uint8Array {
	return new Uint8Array(frame);
}

/** In-memory store — tests + ephemeral (no-durability) runs. */
export class MemorySnapshotStore implements SnapshotStore {
	readonly #snapshots = new Map<string, { version: number; frame: Uint8Array }>();
	readonly #tails = new Map<string, Uint8Array[]>();
	readonly #wraps = new Map<string, Uint8Array[]>();

	async appendTail(entityId: string, frame: Uint8Array): Promise<void> {
		let tail = this.#tails.get(entityId);
		if (!tail) {
			tail = [];
			this.#tails.set(entityId, tail);
		}
		tail.push(copy(frame));
	}

	async putSnapshot(entityId: string, frame: Uint8Array): Promise<number> {
		const version = (this.#snapshots.get(entityId)?.version ?? 0) + 1;
		this.#snapshots.set(entityId, { version, frame: copy(frame) });
		this.#tails.set(entityId, []);
		return version;
	}

	async appendWrap(entityId: string, frame: Uint8Array): Promise<void> {
		let wraps = this.#wraps.get(entityId);
		if (!wraps) {
			wraps = [];
			this.#wraps.set(entityId, wraps);
		}
		wraps.push(copy(frame));
		if (wraps.length > WRAP_RETENTION) wraps.splice(0, wraps.length - WRAP_RETENTION);
	}

	async readBackfill(entityId: string): Promise<BackfillData> {
		const snap = this.#snapshots.get(entityId);
		const tail = this.#tails.get(entityId) ?? [];
		const wraps = this.#wraps.get(entityId) ?? [];
		// Wraps FIRST (the device needs the DEK before it can apply the state).
		const frames: Uint8Array[] = [];
		for (const w of wraps) frames.push(copy(w));
		if (snap) frames.push(copy(snap.frame));
		for (const f of tail) frames.push(copy(f));
		return { version: snap?.version ?? 0, frames };
	}

	async latestVersion(entityId: string): Promise<number | null> {
		return this.#snapshots.get(entityId)?.version ?? null;
	}

	async migrate(fromId: string, toId: string): Promise<MigrateOutcome> {
		if (fromId === toId) return MigrateOutcome.Conflict;
		const fromExists = this.#has(fromId);
		const toExists = this.#has(toId);
		if (!fromExists && !toExists) return MigrateOutcome.Nothing;
		if (!fromExists) return MigrateOutcome.AlreadyDone;
		if (toExists) return MigrateOutcome.Conflict;
		const snap = this.#snapshots.get(fromId);
		if (snap) this.#snapshots.set(toId, snap);
		const tail = this.#tails.get(fromId);
		if (tail) this.#tails.set(toId, tail);
		const wraps = this.#wraps.get(fromId);
		if (wraps) this.#wraps.set(toId, wraps);
		this.#snapshots.delete(fromId);
		this.#tails.delete(fromId);
		this.#wraps.delete(fromId);
		return MigrateOutcome.Moved;
	}

	#has(entityId: string): boolean {
		return (
			this.#snapshots.has(entityId) ||
			(this.#tails.get(entityId)?.length ?? 0) > 0 ||
			(this.#wraps.get(entityId)?.length ?? 0) > 0
		);
	}
}
