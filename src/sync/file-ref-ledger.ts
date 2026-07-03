/**
 * Asset-B6 — filesystem-backed `RefLedger` (the local provider), next to
 * `FileAssetCas` on the same `STORAGE_DIR`. Layout:
 *
 *   <root>/<base64url(account)>.json    one AccountGcState per account
 *
 * `base64url` keeps a hostile account string from traversing the root (the
 * wire is untrusted), exactly like `FileAccountCatalog`. A per-account
 * in-memory cache fronts the file; writes are per-account serialized and
 * temp+rename atomic so a crash mid-write never leaves a truncated ledger
 * (a corrupt file degrades to empty state, which is GC-conservative).
 *
 * **Relay-blind.** Opaque hashes + timestamps only; zero crypto. See CLAUDE.md.
 */

import { Buffer } from "node:buffer";
import { mkdir, readFile, readdir, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { type AccountGcState, type RefLedger, sanitizeGcState } from "./ref-ledger";

export class FileRefLedger implements RefLedger {
	readonly #root: string;
	readonly #cache = new Map<string, AccountGcState>();
	readonly #queues = new Map<string, Promise<unknown>>();

	constructor(root: string) {
		this.#root = root;
	}

	async accounts(): Promise<string[]> {
		let files: string[];
		try {
			files = await readdir(this.#root);
		} catch {
			return [];
		}
		const out: string[] = [];
		for (const file of files.sort()) {
			if (!file.endsWith(".json")) continue;
			try {
				out.push(Buffer.from(file.slice(0, -".json".length), "base64url").toString("utf8"));
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
			await this.#persist(account, state);
		});
	}

	async #load(account: string): Promise<AccountGcState> {
		const cached = this.#cache.get(account);
		if (cached) return cached;
		let state: AccountGcState;
		try {
			state = sanitizeGcState(JSON.parse(await readFile(this.#pathFor(account), "utf8")));
		} catch {
			state = sanitizeGcState(null); // missing / malformed → empty (conservative)
		}
		this.#cache.set(account, state);
		return state;
	}

	async #persist(account: string, state: AccountGcState): Promise<void> {
		const path = this.#pathFor(account);
		const tmp = `${path}.tmp`;
		await mkdir(dirname(path), { recursive: true });
		await writeFile(tmp, JSON.stringify(state), "utf8");
		await rename(tmp, path);
	}

	#pathFor(account: string): string {
		const safe = Buffer.from(account, "utf8").toString("base64url");
		return join(this.#root, `${safe}.json`);
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
