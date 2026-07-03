/**
 * Asset-B6 — object-store-backed `RefLedger` (the managed / self-hosted cloud
 * tier), over the same `ObjectBucket` seam as `ObjectAssetCas` so the backend
 * is selected once in `main.ts`.
 *
 * Key layout: `<prefix>asset-gc/<base64url(account)>.json` — one
 * `AccountGcState` object per account (traversal-safe for the untrusted
 * account string, exactly like the catalog).
 *
 * **Relay-blind.** Opaque hashes + timestamps only; zero crypto. See CLAUDE.md.
 */

import { Buffer } from "node:buffer";
import type { ObjectBucket } from "./object-store";
import { type AccountGcState, type RefLedger, sanitizeGcState } from "./ref-ledger";

const TEXT = { enc: new TextEncoder(), dec: new TextDecoder() };

export class ObjectRefLedger implements RefLedger {
	readonly #bucket: ObjectBucket;
	readonly #prefix: string;
	readonly #cache = new Map<string, AccountGcState>();
	readonly #queues = new Map<string, Promise<unknown>>();

	constructor(bucket: ObjectBucket, prefix = "") {
		this.#bucket = bucket;
		this.#prefix = `${prefix}asset-gc/`;
	}

	async accounts(): Promise<string[]> {
		const out: string[] = [];
		for (const key of await this.#bucket.list(this.#prefix)) {
			if (!key.endsWith(".json")) continue;
			const name = key.slice(this.#prefix.length, -".json".length);
			try {
				out.push(Buffer.from(name, "base64url").toString("utf8"));
			} catch {
				// not one of ours — skip
			}
		}
		return out;
	}

	read(account: string): Promise<AccountGcState> {
		return this.#serial(account, async () => structuredClone(await this.#load(account)));
	}

	update(account: string, mutate: (state: AccountGcState) => void): Promise<void> {
		return this.#serial(account, async () => {
			const state = await this.#load(account);
			mutate(state);
			await this.#bucket.put(this.#key(account), TEXT.enc.encode(JSON.stringify(state)));
		});
	}

	async #load(account: string): Promise<AccountGcState> {
		const cached = this.#cache.get(account);
		if (cached) return cached;
		let state: AccountGcState;
		const raw = await this.#bucket.get(this.#key(account));
		try {
			state = sanitizeGcState(raw ? JSON.parse(TEXT.dec.decode(raw)) : null);
		} catch {
			state = sanitizeGcState(null); // malformed → empty (conservative)
		}
		this.#cache.set(account, state);
		return state;
	}

	#key(account: string): string {
		const safe = Buffer.from(account, "utf8").toString("base64url");
		return `${this.#prefix}${safe}.json`;
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
