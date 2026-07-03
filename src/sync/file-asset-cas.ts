/**
 * Asset-B3 — filesystem-backed durable `AssetCas` (the local provider), the
 * byte-plane analogue of `FileSnapshotStore`. Layout under `<root>`:
 *
 *   <root>/<aa>/<hash>.bin    the sealed ciphertext chunk (opaque, immutable)
 *
 * The key is the 64-hex ciphertext-hash; `<aa>` is its first two chars
 * (sharding so one busy vault doesn't make a million-entry dir). The hash is
 * validated `[0-9a-f]{64}` at the wire edge before it reaches here, but this
 * store re-checks it defensively — a hostile address can NEVER traverse the
 * storage root.
 *
 * Chunks are immutable, so a PUT whose target already exists is a no-op
 * (skip the write). Writes for one hash run through a promise chain so two
 * concurrent PUTs of the same address can't race; different hashes proceed in
 * parallel.
 *
 * **Relay-blind.** Opaque bytes only; zero crypto imports. See CLAUDE.md.
 */

import { access, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { type AssetCas, isAssetHash } from "./asset-cas";

export class FileAssetCas implements AssetCas {
	readonly #root: string;
	readonly #queues = new Map<string, Promise<unknown>>();

	constructor(root: string) {
		this.#root = root;
	}

	async has(hash: string): Promise<boolean> {
		if (!isAssetHash(hash)) return false;
		try {
			await access(this.#pathFor(hash));
			return true;
		} catch {
			return false;
		}
	}

	put(hash: string, chunk: Uint8Array): Promise<void> {
		if (!isAssetHash(hash)) return Promise.reject(new Error("FileAssetCas.put: invalid hash"));
		const bytes = new Uint8Array(chunk);
		return this.#serial(hash, async () => {
			const path = this.#pathFor(hash);
			if (await exists(path)) return; // immutable — already stored
			await mkdir(this.#shardDir(hash), { recursive: true });
			// Atomic: write a temp then rename, so a crash mid-write never leaves a
			// truncated chunk at the content address.
			const tmp = `${path}.tmp`;
			await writeFile(tmp, bytes);
			await rename(tmp, path);
		});
	}

	async get(hash: string): Promise<Uint8Array | null> {
		if (!isAssetHash(hash)) return null;
		try {
			return new Uint8Array(await readFile(this.#pathFor(hash)));
		} catch {
			return null;
		}
	}

	delete(hash: string): Promise<void> {
		if (!isAssetHash(hash)) return Promise.resolve(); // never traverses the root
		return this.#serial(hash, () => rm(this.#pathFor(hash), { force: true }));
	}

	#shardDir(hash: string): string {
		return join(this.#root, hash.slice(0, 2));
	}

	#pathFor(hash: string): string {
		return join(this.#shardDir(hash), `${hash}.bin`);
	}

	#serial<T>(hash: string, op: () => Promise<T>): Promise<T> {
		const prior = this.#queues.get(hash) ?? Promise.resolve();
		const next = prior.then(op, op);
		this.#queues.set(
			hash,
			next.then(
				() => undefined,
				() => undefined,
			),
		);
		return next;
	}
}

async function exists(path: string): Promise<boolean> {
	try {
		await access(path);
		return true;
	} catch {
		return false;
	}
}
