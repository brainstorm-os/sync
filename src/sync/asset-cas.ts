/**
 * Asset-B3 — the durable node's content-addressed store (CAS) for encrypted
 * attachment chunks. The byte-plane analogue of `SnapshotStore`: where the
 * Y.Doc plane keys per-entity snapshot+tail, the asset plane keys opaque
 * ciphertext chunks by their **ciphertext-hash** (PUT / GET / HAS), next to it
 * on the same node, same admission, same relay-blind invariant.
 *
 * **Relay-blind.** This module stores and serves OPAQUE bytes keyed by an
 * opaque hash string; it imports ZERO crypto and never computes the hash — the
 * address is the CLIENT's content-address, the client verifies integrity on
 * download (the ciphertext-hash is per-vault-DEK-unique, so a chunk can't be
 * poisoned across vaults), and the node is a dumb byte cache that cannot
 * decrypt. See CLAUDE.md.
 *
 * Chunks are **immutable** — a PUT of an address already present is a no-op
 * (the content can't differ, the address is the hash of the content).
 *
 * The interface is storage-agnostic so `main.ts` can select the backend
 * (in-memory ↔ filesystem ↔ object bucket) the same way it selects the
 * `SnapshotStore`. `MemoryAssetCas` here backs the tests + an ephemeral run.
 */

export interface AssetCas {
	/** True if a chunk with this ciphertext-hash is already stored. */
	has(hash: string): Promise<boolean>;
	/** Store a sealed chunk under its ciphertext-hash. Idempotent (immutable
	 *  content) — a re-PUT of a present address is a no-op. */
	put(hash: string, chunk: Uint8Array): Promise<void>;
	/** Fetch a sealed chunk by ciphertext-hash, or null if absent. */
	get(hash: string): Promise<Uint8Array | null>;
	/** Remove a chunk (Asset-B6 GC reclaim). A no-op when absent. Only the
	 *  grace-and-retention-gated sweep may call this — never a client verb. */
	delete(hash: string): Promise<void>;
}

/** A ciphertext-hash address is a 64-char lowercase-hex sha256. Validated at
 *  the wire edge (untrusted client) so a hostile "hash" can never traverse the
 *  storage root or smuggle a non-address. */
const HASH_RE = /^[0-9a-f]{64}$/;

export function isAssetHash(hash: unknown): hash is string {
	return typeof hash === "string" && HASH_RE.test(hash);
}

/** In-memory CAS — tests + ephemeral (no-durability) runs. */
export class MemoryAssetCas implements AssetCas {
	readonly #chunks = new Map<string, Uint8Array>();

	async has(hash: string): Promise<boolean> {
		return this.#chunks.has(hash);
	}

	async put(hash: string, chunk: Uint8Array): Promise<void> {
		if (!this.#chunks.has(hash)) this.#chunks.set(hash, new Uint8Array(chunk));
	}

	async get(hash: string): Promise<Uint8Array | null> {
		const stored = this.#chunks.get(hash);
		return stored ? new Uint8Array(stored) : null;
	}

	async delete(hash: string): Promise<void> {
		this.#chunks.delete(hash);
	}

	/** Test/diagnostic: distinct chunks held. */
	get size(): number {
		return this.#chunks.size;
	}
}
