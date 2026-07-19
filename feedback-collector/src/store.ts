/**
 * Append-only JSONL retention — the collector's source of truth. GitHub
 * piping is best-effort on top; a piping failure loses nothing because the
 * record is already on disk here.
 *
 * Layout: `<dataDir>/feedback-YYYY-MM.jsonl` / `<dataDir>/crash-YYYY-MM.jsonl`
 * (month-keyed so rotation is `rm` on old files / external archiving; no
 * in-process rotation machinery). One JSON object per line. Per doc-48 data
 * minimisation the stored record is receivedAt + the (already redacted)
 * payload — deliberately NO client IP.
 */

import { appendFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import type { StoredRecord } from "./ingest";

export class JsonlStore {
	readonly #dataDir: string;
	#dirReady: Promise<void> | null = null;

	constructor(dataDir: string) {
		this.#dataDir = dataDir;
	}

	filePathFor(record: StoredRecord): string {
		const d = new Date(record.receivedAt);
		const month = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
		return join(this.#dataDir, `${record.recordKind}-${month}.jsonl`);
	}

	async append(record: StoredRecord): Promise<void> {
		if (!this.#dirReady) this.#dirReady = mkdir(this.#dataDir, { recursive: true }).then(() => {});
		await this.#dirReady;
		await appendFile(this.filePathFor(record), `${JSON.stringify(record)}\n`, "utf8");
	}
}
