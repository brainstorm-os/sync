/**
 * SYNC-2 — filesystem-backed durable `SnapshotStore` (the local provider).
 *
 * Per OQ-SYNC-1 (local-only-first) this is the v1 durable backend; SYNC-3
 * slots a managed object-storage backend behind the same interface without a
 * server change. Layout under `<root>`:
 *
 *   <root>/<aa>/<safeName>/snapshot.bin   latest full snapshot frame (opaque)
 *   <root>/<aa>/<safeName>/meta.json      { version }
 *   <root>/<aa>/<safeName>/tail.log       length-prefixed update frames
 *
 * `safeName = base64url(entityId)` — a deterministic, reversible name whose
 * charset is `[A-Za-z0-9_-]`, so a hostile entityId (the wire is untrusted)
 * can NEVER traverse the storage root. `<aa>` is the first two chars of
 * `safeName`, sharding so one busy vault doesn't make a million-entry dir.
 *
 * `tail.log` framing: `u32-be(len) || frame`, repeated. A snapshot upload
 * truncates it (the snapshot subsumes the prior tail — client-driven
 * compaction, OQ-SYNC-3).
 *
 * **Per-entity serialization.** Writes for one entity run through a promise
 * chain so concurrent appends can't interleave bytes or race the snapshot
 * truncation. Different entities proceed in parallel.
 *
 * **Relay-blind.** Opaque bytes only; zero crypto imports. See CLAUDE.md.
 */

import { Buffer } from "node:buffer";
import { mkdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import {
	type BackfillData,
	MigrateOutcome,
	type SnapshotStore,
	WRAP_RETENTION,
} from "./snapshot-store";

type Paths = { dir: string; snapshot: string; meta: string; tail: string; wraps: string };

export class FileSnapshotStore implements SnapshotStore {
	readonly #root: string;
	readonly #queues = new Map<string, Promise<unknown>>();

	constructor(root: string) {
		this.#root = root;
	}

	appendTail(entityId: string, frame: Uint8Array): Promise<void> {
		const bytes = new Uint8Array(frame);
		return this.#serial(entityId, async () => {
			const p = this.#pathsFor(entityId);
			await mkdir(p.dir, { recursive: true });
			const framed = frameBytes(bytes);
			await appendBytes(p.tail, framed);
		});
	}

	putSnapshot(entityId: string, frame: Uint8Array): Promise<number> {
		const bytes = new Uint8Array(frame);
		return this.#serial(entityId, async () => {
			const p = this.#pathsFor(entityId);
			await mkdir(p.dir, { recursive: true });
			const version = (await readVersion(p.meta)) + 1;
			// Snapshot first, then meta, then reset the tail. Order matters for a
			// crash mid-write: a snapshot without a bumped version is re-served as
			// the older version (safe); a stale tail re-applied over a newer
			// snapshot is idempotent in the client CRDT.
			await writeFileAtomic(p.snapshot, bytes);
			await writeFileAtomic(p.meta, Buffer.from(JSON.stringify({ version }), "utf8"));
			await rm(p.tail, { force: true });
			return version;
		});
	}

	appendWrap(entityId: string, frame: Uint8Array): Promise<void> {
		const bytes = new Uint8Array(frame);
		return this.#serial(entityId, async () => {
			const p = this.#pathsFor(entityId);
			await mkdir(p.dir, { recursive: true });
			// Read-modify-write capped at WRAP_RETENTION so the file stays bounded
			// despite re-emissions (the node can't dedup by sealed recipient).
			const existing = await readOptional(p.wraps);
			const kept = existing ? parseTail(existing) : [];
			kept.push(bytes);
			if (kept.length > WRAP_RETENTION) kept.splice(0, kept.length - WRAP_RETENTION);
			const out = concatFrames(kept.map(frameBytes));
			await writeFileAtomic(p.wraps, out);
		});
	}

	readBackfill(entityId: string): Promise<BackfillData> {
		return this.#serial(entityId, async () => {
			const p = this.#pathsFor(entityId);
			const frames: Uint8Array[] = [];
			// Wraps FIRST so the device has the DEK before applying the state.
			const wraps = await readOptional(p.wraps);
			if (wraps) for (const w of parseTail(wraps)) frames.push(w);
			const snapshot = await readOptional(p.snapshot);
			if (snapshot) frames.push(snapshot);
			const tail = await readOptional(p.tail);
			if (tail) for (const f of parseTail(tail)) frames.push(f);
			const version = await readVersion(p.meta);
			return { version, frames };
		});
	}

	latestVersion(entityId: string): Promise<number | null> {
		return this.#serial(entityId, async () => {
			const v = await readVersion(this.#pathsFor(entityId).meta);
			return v > 0 ? v : null;
		});
	}

	/**
	 * 10.11 rotation re-home — the whole per-entity directory moves in ONE
	 * atomic `rename` (same filesystem: `from` and `to` are both under the
	 * store root). There is no torn state: a crash leaves the directory under
	 * exactly one of the two ids, complete, and the client's idempotent
	 * `rotate` retry converges (`from` gone + `to` present ⇒ `AlreadyDone`).
	 */
	migrate(fromId: string, toId: string): Promise<MigrateOutcome> {
		if (fromId === toId) return Promise.resolve(MigrateOutcome.Conflict);
		return this.#serial2(fromId, toId, async () => {
			const fromDir = this.#pathsFor(fromId).dir;
			const toDir = this.#pathsFor(toId).dir;
			const fromExists = await dirExists(fromDir);
			const toExists = await dirExists(toDir);
			if (!fromExists && !toExists) return MigrateOutcome.Nothing;
			if (!fromExists) return MigrateOutcome.AlreadyDone;
			if (toExists) return MigrateOutcome.Conflict;
			await mkdir(dirname(toDir), { recursive: true });
			await rename(fromDir, toDir);
			return MigrateOutcome.Moved;
		});
	}

	#pathsFor(entityId: string): Paths {
		const safe = Buffer.from(entityId, "utf8").toString("base64url");
		const shard = safe.slice(0, 2) || "_";
		const dir = join(this.#root, shard, safe);
		return {
			dir,
			snapshot: join(dir, "snapshot.bin"),
			meta: join(dir, "meta.json"),
			tail: join(dir, "tail.log"),
			wraps: join(dir, "wraps.log"),
		};
	}

	/** Run `op` after any in-flight op for the same entity, serializing writes. */
	#serial<T>(entityId: string, op: () => Promise<T>): Promise<T> {
		const prior = this.#queues.get(entityId) ?? Promise.resolve();
		const next = prior.then(op, op);
		// Keep the chain alive but swallow errors for the NEXT waiter's gate.
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
		const gate = Promise.allSettled([priorA, priorB]);
		const next = gate.then(op);
		const settled = next.then(
			() => undefined,
			() => undefined,
		);
		this.#queues.set(a, settled);
		this.#queues.set(b, settled);
		return next;
	}
}

async function dirExists(path: string): Promise<boolean> {
	try {
		return (await stat(path)).isDirectory();
	} catch {
		return false;
	}
}

function frameBytes(frame: Uint8Array): Uint8Array {
	const out = new Uint8Array(4 + frame.length);
	new DataView(out.buffer).setUint32(0, frame.length, false);
	out.set(frame, 4);
	return out;
}

function concatFrames(framed: Uint8Array[]): Uint8Array {
	const total = framed.reduce((n, f) => n + f.length, 0);
	const out = new Uint8Array(total);
	let off = 0;
	for (const f of framed) {
		out.set(f, off);
		off += f.length;
	}
	return out;
}

function parseTail(buf: Uint8Array): Uint8Array[] {
	const frames: Uint8Array[] = [];
	const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
	let off = 0;
	while (off + 4 <= buf.length) {
		const len = view.getUint32(off, false);
		off += 4;
		// A truncated final record (crash mid-append) is dropped, not fatal.
		if (off + len > buf.length) break;
		frames.push(buf.subarray(off, off + len));
		off += len;
	}
	return frames;
}

async function readVersion(metaPath: string): Promise<number> {
	const raw = await readOptional(metaPath);
	if (!raw) return 0;
	try {
		const parsed = JSON.parse(Buffer.from(raw).toString("utf8")) as { version?: unknown };
		return typeof parsed.version === "number" && Number.isInteger(parsed.version)
			? parsed.version
			: 0;
	} catch {
		return 0;
	}
}

async function readOptional(path: string): Promise<Uint8Array | null> {
	try {
		return new Uint8Array(await readFile(path));
	} catch {
		return null;
	}
}

async function appendBytes(path: string, bytes: Uint8Array): Promise<void> {
	const { appendFile } = await import("node:fs/promises");
	await appendFile(path, bytes);
}

async function writeFileAtomic(path: string, bytes: Uint8Array): Promise<void> {
	const tmp = `${path}.tmp`;
	await mkdir(dirname(path), { recursive: true });
	await writeFile(tmp, bytes);
	await rename(tmp, path);
}
