/**
 * SYNC-3 — object-storage-backed `SnapshotStore` + `AccountCatalog` (the
 * managed / self-hosted provider).
 *
 * Same snapshot+tail shape as the local `FileSnapshotStore`, but laid out as
 * objects in a bucket so the node can point at our managed object storage
 * (metered) or a self-hoster's bring-your-own bucket — one wire protocol,
 * swappable backend (OQ-SYNC-1). The storage primitive is the tiny
 * `ObjectBucket` seam (get / put / delete / list); `BunS3Bucket`
 * (bun-s3-bucket.ts) is the S3/R2/MinIO adapter, and `MemoryBucket` here backs
 * the tests — so the snapshot+tail layout logic is provable without a live
 * bucket.
 *
 * Object layout (keys; `<safe> = base64url(entityId)`, traversal-safe for the
 * untrusted wire id, exactly like FileSnapshotStore):
 *
 *   <prefix><safe>/snapshot.bin          latest full snapshot frame (opaque)
 *   <prefix><safe>/meta.json             { version }
 *   <prefix><safe>/tail/<seq12>.bin      one update frame per object
 *   <prefix><safe>/wraps/<seq12>.bin     one WrapBootstrap frame per object
 *   <prefix>catalog/<base64url(acct)>.json   account → entity-id list
 *
 * `<seq12>` is a 12-digit zero-padded counter so lexical list order == apply
 * order (object listing is lexical). A `Snapshot` upload is client-driven
 * compaction: it bumps the version and DELETES the tail objects (the snapshot
 * subsumes them). Wraps survive compaction (the DEK is still needed) and are
 * bounded at `WRAP_RETENTION` (oldest evicted) since the node can't dedup a
 * per-recipient sealed wrap.
 *
 * **Per-entity / per-account serialization.** All mutations for one key-space
 * run through a promise chain so concurrent appends can't race the seq counter
 * or the snapshot reset; different entities proceed in parallel.
 *
 * **Relay-blind.** Opaque blobs only; zero crypto imports. Reads only the
 * `WireKind` routing discriminant (via `persistFrame`). See CLAUDE.md.
 */

import type { AccountCatalog } from "./account-catalog";
import {
	type BackfillData,
	MigrateOutcome,
	type SnapshotStore,
	WRAP_RETENTION,
} from "./snapshot-store";

/**
 * The storage seam SYNC-3 swaps. Keys are opaque strings; values opaque bytes.
 * `list` returns the full keys under a prefix (used to enumerate tail / wrap
 * objects). Intentionally tiny so any object store (S3, R2, MinIO, a test
 * fake) can back it without leaking provider specifics into the store logic.
 */
export interface ObjectBucket {
	/** Read an object, or null if it does not exist. */
	get(key: string): Promise<Uint8Array | null>;
	/** Write (overwrite) an object. */
	put(key: string, bytes: Uint8Array): Promise<void>;
	/** Delete an object (a no-op if absent). */
	delete(key: string): Promise<void>;
	/** Full keys under `prefix`, in lexical order. */
	list(prefix: string): Promise<string[]>;
}

const SEQ_PAD = 12;
const TEXT = { enc: new TextEncoder(), dec: new TextDecoder() };

function padSeq(n: number): string {
	return String(n).padStart(SEQ_PAD, "0");
}

function safeName(id: string): string {
	return Buffer.from(id, "utf8").toString("base64url");
}

/** Object-storage `SnapshotStore`. Backed by any `ObjectBucket`. */
export class ObjectSnapshotStore implements SnapshotStore {
	readonly #bucket: ObjectBucket;
	readonly #prefix: string;
	readonly #queues = new Map<string, Promise<unknown>>();
	/** Cached next-seq counters, lazily seeded from the bucket per entity. */
	readonly #nextTail = new Map<string, number>();
	readonly #nextWrap = new Map<string, number>();

	constructor(bucket: ObjectBucket, prefix = "") {
		this.#bucket = bucket;
		this.#prefix = prefix;
	}

	appendTail(entityId: string, frame: Uint8Array): Promise<void> {
		const bytes = new Uint8Array(frame);
		return this.#serial(entityId, async () => {
			const seq = await this.#seq(this.#nextTail, entityId, this.#tailPrefix(entityId));
			await this.#bucket.put(`${this.#tailPrefix(entityId)}${padSeq(seq)}.bin`, bytes);
			this.#nextTail.set(entityId, seq + 1);
		});
	}

	putSnapshot(entityId: string, frame: Uint8Array): Promise<number> {
		const bytes = new Uint8Array(frame);
		return this.#serial(entityId, async () => {
			const version = ((await this.#readVersion(entityId)) ?? 0) + 1;
			await this.#bucket.put(this.#key(entityId, "snapshot.bin"), bytes);
			await this.#bucket.put(
				this.#key(entityId, "meta.json"),
				TEXT.enc.encode(JSON.stringify({ version })),
			);
			// Compaction: the snapshot subsumes the tail — drop every tail object.
			const tailKeys = await this.#bucket.list(this.#tailPrefix(entityId));
			for (const key of tailKeys) await this.#bucket.delete(key);
			this.#nextTail.set(entityId, 0);
			return version;
		});
	}

	appendWrap(entityId: string, frame: Uint8Array): Promise<void> {
		const bytes = new Uint8Array(frame);
		return this.#serial(entityId, async () => {
			const seq = await this.#seq(this.#nextWrap, entityId, this.#wrapPrefix(entityId));
			await this.#bucket.put(`${this.#wrapPrefix(entityId)}${padSeq(seq)}.bin`, bytes);
			this.#nextWrap.set(entityId, seq + 1);
			// Bound retention: evict the oldest wraps beyond the cap.
			const keys = (await this.#bucket.list(this.#wrapPrefix(entityId))).sort();
			if (keys.length > WRAP_RETENTION) {
				for (const key of keys.slice(0, keys.length - WRAP_RETENTION)) {
					await this.#bucket.delete(key);
				}
			}
		});
	}

	readBackfill(entityId: string): Promise<BackfillData> {
		return this.#serial(entityId, async () => {
			const frames: Uint8Array[] = [];
			// Wraps FIRST so the device installs the DEK before applying state.
			for (const key of (await this.#bucket.list(this.#wrapPrefix(entityId))).sort()) {
				const w = await this.#bucket.get(key);
				if (w) frames.push(w);
			}
			const snapshot = await this.#bucket.get(this.#key(entityId, "snapshot.bin"));
			if (snapshot) frames.push(snapshot);
			for (const key of (await this.#bucket.list(this.#tailPrefix(entityId))).sort()) {
				const f = await this.#bucket.get(key);
				if (f) frames.push(f);
			}
			return { version: (await this.#readVersion(entityId)) ?? 0, frames };
		});
	}

	latestVersion(entityId: string): Promise<number | null> {
		return this.#serial(entityId, () => this.#readVersion(entityId));
	}

	/**
	 * 10.11 rotation re-home. Object stores have no atomic directory rename, so
	 * the migration is journaled: `<prefix>migrations/<safe(from)>.json = {to}`
	 * is written BEFORE the copy, the copy runs `from → to` (overwrite-safe),
	 * `from` objects are deleted only after every copy landed, and the journal
	 * is deleted last. A crash at any point leaves `from` complete (pre-copy /
	 * mid-copy) or `to` complete (post-copy), and the client's idempotent
	 * `rotate` retry resumes from the journal. `to` occupied WITHOUT a matching
	 * journal ⇒ `Conflict` — a rotate never overwrites ciphertext it did not
	 * migrate itself.
	 */
	migrate(fromId: string, toId: string): Promise<MigrateOutcome> {
		if (fromId === toId) return Promise.resolve(MigrateOutcome.Conflict);
		return this.#serial2(fromId, toId, async () => {
			const journalKey = `${this.#prefix}migrations/${safeName(fromId)}.json`;
			const fromPrefix = `${this.#prefix}${safeName(fromId)}/`;
			const toPrefix = `${this.#prefix}${safeName(toId)}/`;
			const journalTo = await this.#readJournal(journalKey);
			const fromKeys = await this.#bucket.list(fromPrefix);
			const toKeys = await this.#bucket.list(toPrefix);
			const resuming = journalTo === toId;
			if (!resuming) {
				if (journalTo !== null) return MigrateOutcome.Conflict;
				if (fromKeys.length === 0 && toKeys.length === 0) return MigrateOutcome.Nothing;
				if (fromKeys.length === 0) return MigrateOutcome.AlreadyDone;
				if (toKeys.length > 0) return MigrateOutcome.Conflict;
				await this.#bucket.put(journalKey, TEXT.enc.encode(JSON.stringify({ to: toId })));
			}
			for (const key of fromKeys) {
				const bytes = await this.#bucket.get(key);
				if (bytes) await this.#bucket.put(`${toPrefix}${key.slice(fromPrefix.length)}`, bytes);
			}
			// Source objects go only after every copy landed; journal goes last.
			for (const key of fromKeys) await this.#bucket.delete(key);
			await this.#bucket.delete(journalKey);
			this.#nextTail.delete(fromId);
			this.#nextTail.delete(toId);
			this.#nextWrap.delete(fromId);
			this.#nextWrap.delete(toId);
			return fromKeys.length > 0 ? MigrateOutcome.Moved : MigrateOutcome.AlreadyDone;
		});
	}

	async #readJournal(journalKey: string): Promise<string | null> {
		const raw = await this.#bucket.get(journalKey);
		if (!raw) return null;
		try {
			const parsed = JSON.parse(TEXT.dec.decode(raw)) as { to?: unknown };
			return typeof parsed.to === "string" && parsed.to.length > 0 ? parsed.to : null;
		} catch {
			return null;
		}
	}

	async #readVersion(entityId: string): Promise<number | null> {
		const raw = await this.#bucket.get(this.#key(entityId, "meta.json"));
		if (!raw) return null;
		try {
			const parsed = JSON.parse(TEXT.dec.decode(raw)) as { version?: unknown };
			return typeof parsed.version === "number" && Number.isInteger(parsed.version)
				? parsed.version
				: null;
		} catch {
			return null;
		}
	}

	/** Next seq for a sub-prefix: cached, else seeded from max-existing + 1. */
	async #seq(cache: Map<string, number>, entityId: string, prefix: string): Promise<number> {
		const cached = cache.get(entityId);
		if (cached !== undefined) return cached;
		let max = -1;
		for (const key of await this.#bucket.list(prefix)) {
			const n = Number.parseInt(key.slice(prefix.length, prefix.length + SEQ_PAD), 10);
			if (Number.isInteger(n) && n > max) max = n;
		}
		const next = max + 1;
		cache.set(entityId, next);
		return next;
	}

	#key(entityId: string, leaf: string): string {
		return `${this.#prefix}${safeName(entityId)}/${leaf}`;
	}

	#tailPrefix(entityId: string): string {
		return `${this.#prefix}${safeName(entityId)}/tail/`;
	}

	#wrapPrefix(entityId: string): string {
		return `${this.#prefix}${safeName(entityId)}/wraps/`;
	}

	#serial<T>(entityId: string, op: () => Promise<T>): Promise<T> {
		const prior = this.#queues.get(entityId) ?? Promise.resolve();
		const next = prior.then(op, op);
		this.#queues.set(
			entityId,
			next.then(
				() => undefined,
				() => undefined,
			),
		);
		return next;
	}

	/** Serialize `op` behind BOTH entities' write chains (migrate touches two). */
	#serial2<T>(a: string, b: string, op: () => Promise<T>): Promise<T> {
		const priorA = this.#queues.get(a) ?? Promise.resolve();
		const priorB = this.#queues.get(b) ?? Promise.resolve();
		const next = Promise.allSettled([priorA, priorB]).then(op);
		const settled = next.then(
			() => undefined,
			() => undefined,
		);
		this.#queues.set(a, settled);
		this.#queues.set(b, settled);
		return next;
	}
}

/** Object-storage `AccountCatalog`. One JSON array object per account. */
export class ObjectAccountCatalog implements AccountCatalog {
	readonly #bucket: ObjectBucket;
	readonly #prefix: string;
	readonly #cache = new Map<string, Set<string>>();
	readonly #queues = new Map<string, Promise<unknown>>();

	constructor(bucket: ObjectBucket, prefix = "") {
		this.#bucket = bucket;
		this.#prefix = `${prefix}catalog/`;
	}

	record(account: string, entityId: string): Promise<void> {
		return this.#serial(account, async () => {
			const set = await this.#load(account);
			if (set.has(entityId)) return;
			set.add(entityId);
			await this.#bucket.put(this.#key(account), TEXT.enc.encode(JSON.stringify([...set])));
		});
	}

	list(account: string): Promise<string[]> {
		return this.#serial(account, async () => [...(await this.#load(account))]);
	}

	async #load(account: string): Promise<Set<string>> {
		const cached = this.#cache.get(account);
		if (cached) return cached;
		let set = new Set<string>();
		const raw = await this.#bucket.get(this.#key(account));
		if (raw) {
			try {
				const parsed = JSON.parse(TEXT.dec.decode(raw));
				if (Array.isArray(parsed)) {
					set = new Set(parsed.filter((e): e is string => typeof e === "string"));
				}
			} catch {
				// malformed → empty (default-on-corrupt)
			}
		}
		this.#cache.set(account, set);
		return set;
	}

	#key(account: string): string {
		return `${this.#prefix}${safeName(account)}.json`;
	}

	#serial<T>(account: string, op: () => Promise<T>): Promise<T> {
		const prior = this.#queues.get(account) ?? Promise.resolve();
		const next = prior.then(op, op);
		this.#queues.set(
			account,
			next.then(
				() => undefined,
				() => undefined,
			),
		);
		return next;
	}
}

/** In-memory `ObjectBucket` — tests + an ephemeral object-backed run. */
export class MemoryBucket implements ObjectBucket {
	readonly #objects = new Map<string, Uint8Array>();

	async get(key: string): Promise<Uint8Array | null> {
		const v = this.#objects.get(key);
		return v ? new Uint8Array(v) : null;
	}

	async put(key: string, bytes: Uint8Array): Promise<void> {
		this.#objects.set(key, new Uint8Array(bytes));
	}

	async delete(key: string): Promise<void> {
		this.#objects.delete(key);
	}

	async list(prefix: string): Promise<string[]> {
		const out: string[] = [];
		for (const key of this.#objects.keys()) if (key.startsWith(prefix)) out.push(key);
		return out.sort();
	}

	/** Test helper — total object count (e.g. assert tail compaction). */
	size(): number {
		return this.#objects.size;
	}
}
