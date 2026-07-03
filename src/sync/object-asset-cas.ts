/**
 * Asset-B3 — object-store-backed `AssetCas` (the managed / self-hosted cloud
 * tier), the byte-plane analogue of `ObjectSnapshotStore`. Reuses the same
 * `ObjectBucket` adapter (`bun-s3-bucket.ts`) the Y.Doc plane uses, so the
 * backend is selected once in `main.ts`.
 *
 * Key layout: `<prefix>assets/<hash>.bin` — one immutable object per sealed
 * chunk, keyed by its 64-hex ciphertext-hash (validated at the wire edge,
 * re-checked here defensively).
 *
 * **Relay-blind.** Opaque ciphertext keyed by an opaque hash; zero crypto.
 * See CLAUDE.md.
 */

import { type AssetCas, isAssetHash } from "./asset-cas";
import type { ObjectBucket } from "./object-store";

export class ObjectAssetCas implements AssetCas {
	readonly #bucket: ObjectBucket;
	readonly #prefix: string;

	constructor(bucket: ObjectBucket, prefix = "") {
		this.#bucket = bucket;
		this.#prefix = prefix;
	}

	async has(hash: string): Promise<boolean> {
		if (!isAssetHash(hash)) return false;
		return (await this.#bucket.get(this.#key(hash))) !== null;
	}

	async put(hash: string, chunk: Uint8Array): Promise<void> {
		if (!isAssetHash(hash)) throw new Error("ObjectAssetCas.put: invalid hash");
		// Immutable content — skip the PUT if the address is already present so a
		// re-upload doesn't re-bill object writes.
		const key = this.#key(hash);
		if ((await this.#bucket.get(key)) !== null) return;
		await this.#bucket.put(key, new Uint8Array(chunk));
	}

	async get(hash: string): Promise<Uint8Array | null> {
		if (!isAssetHash(hash)) return null;
		return this.#bucket.get(this.#key(hash));
	}

	async delete(hash: string): Promise<void> {
		if (!isAssetHash(hash)) return; // never a hostile key
		await this.#bucket.delete(this.#key(hash));
	}

	#key(hash: string): string {
		return `${this.#prefix}assets/${hash}.bin`;
	}
}
