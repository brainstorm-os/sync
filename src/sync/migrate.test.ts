/**
 * 10.11 routing-token rotation — the storage re-home (`SnapshotStore.migrate`)
 * across all three backends, plus the crash-window / idempotency contract:
 * at every instant the entity's ciphertext is recoverable under at least one
 * of the two routing ids, a retry converges, and a rotate never overwrites
 * data it did not migrate itself (`Conflict`).
 */

import { afterAll, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FileSnapshotStore } from "./file-snapshot-store";
import { MemoryBucket, ObjectSnapshotStore } from "./object-store";
import { MemorySnapshotStore, MigrateOutcome, type SnapshotStore } from "./snapshot-store";

const enc = new TextEncoder();
const bytes = (s: string) => enc.encode(s);

const FROM = "token-old";
const TO = "token-new";
const OTHER = "token-other";

const tempDirs: string[] = [];
afterAll(async () => {
	for (const dir of tempDirs) await rm(dir, { recursive: true, force: true });
});

async function fileStore(): Promise<FileSnapshotStore> {
	const dir = await mkdtemp(join(tmpdir(), "bs-migrate-"));
	tempDirs.push(dir);
	return new FileSnapshotStore(dir);
}

async function seed(store: SnapshotStore, id: string): Promise<void> {
	await store.putSnapshot(id, bytes(`snap:${id}`));
	await store.appendTail(id, bytes(`tail1:${id}`));
	await store.appendTail(id, bytes(`tail2:${id}`));
	await store.appendWrap(id, bytes(`wrap:${id}`));
}

async function backfillStrings(store: SnapshotStore, id: string): Promise<string[]> {
	const { frames } = await store.readBackfill(id);
	return frames.map((f) => new TextDecoder().decode(f));
}

const backends: Array<[string, () => Promise<SnapshotStore>]> = [
	["memory", async () => new MemorySnapshotStore()],
	["file", fileStore],
	["object", async () => new ObjectSnapshotStore(new MemoryBucket(), "p/")],
];

for (const [name, make] of backends) {
	describe(`migrate (${name} backend)`, () => {
		test("moves snapshot + tail + wraps; backfill serves under the new id only", async () => {
			const store = await make();
			await seed(store, FROM);
			expect(await store.migrate(FROM, TO)).toBe(MigrateOutcome.Moved);
			expect(await backfillStrings(store, TO)).toEqual([
				`wrap:${FROM}`,
				`snap:${FROM}`,
				`tail1:${FROM}`,
				`tail2:${FROM}`,
			]);
			expect(await backfillStrings(store, FROM)).toEqual([]);
			expect(await store.latestVersion(TO)).toBe(1);
			expect(await store.latestVersion(FROM)).toBeNull();
		});

		test("retry after completion is AlreadyDone and does not disturb the data", async () => {
			const store = await make();
			await seed(store, FROM);
			await store.migrate(FROM, TO);
			expect(await store.migrate(FROM, TO)).toBe(MigrateOutcome.AlreadyDone);
			expect((await backfillStrings(store, TO)).length).toBe(4);
		});

		test("nothing durable under either id is Nothing (alias-only rotation)", async () => {
			const store = await make();
			expect(await store.migrate(FROM, TO)).toBe(MigrateOutcome.Nothing);
		});

		test("occupied target is Conflict and both ids keep their own data", async () => {
			const store = await make();
			await seed(store, FROM);
			await store.putSnapshot(TO, bytes("victim"));
			expect(await store.migrate(FROM, TO)).toBe(MigrateOutcome.Conflict);
			expect(await backfillStrings(store, FROM)).toContain(`snap:${FROM}`);
			expect(await backfillStrings(store, TO)).toEqual(["victim"]);
		});

		test("from === to is Conflict", async () => {
			const store = await make();
			await seed(store, FROM);
			expect(await store.migrate(FROM, FROM)).toBe(MigrateOutcome.Conflict);
		});

		test("post-migration writes land under the new id", async () => {
			const store = await make();
			await seed(store, FROM);
			await store.migrate(FROM, TO);
			await store.appendTail(TO, bytes("tail3"));
			expect(await backfillStrings(store, TO)).toContain("tail3");
			expect(await backfillStrings(store, FROM)).toEqual([]);
		});
	});
}

describe("migrate crash windows (object backend journal)", () => {
	test("resume after crash mid-copy: journal present, source complete → converges", async () => {
		const bucket = new MemoryBucket();
		const store = new ObjectSnapshotStore(bucket, "p/");
		await seed(store, FROM);
		// Simulate the crash state: journal written + a PARTIAL copy under `to`
		// (one object), source untouched — exactly what a crash mid-copy leaves.
		const safeFrom = Buffer.from(FROM, "utf8").toString("base64url");
		const safeTo = Buffer.from(TO, "utf8").toString("base64url");
		await bucket.put(`p/migrations/${safeFrom}.json`, bytes(JSON.stringify({ to: TO })));
		await bucket.put(`p/${safeTo}/snapshot.bin`, bytes("partial"));
		// The retry resumes: full re-copy from the intact source, delete, journal gone.
		expect(await store.migrate(FROM, TO)).toBe(MigrateOutcome.Moved);
		expect(await backfillStrings(store, TO)).toEqual([
			`wrap:${FROM}`,
			`snap:${FROM}`,
			`tail1:${FROM}`,
			`tail2:${FROM}`,
		]);
		// No orphaned ciphertext: nothing left under the old id, no journal.
		expect(await bucket.list(`p/${safeFrom}/`)).toEqual([]);
		expect(await bucket.get(`p/migrations/${safeFrom}.json`)).toBeNull();
	});

	test("resume after crash mid-delete: journal present, source already gone → AlreadyDone", async () => {
		const bucket = new MemoryBucket();
		const store = new ObjectSnapshotStore(bucket, "p/");
		await seed(store, FROM);
		await store.migrate(FROM, TO);
		// Crash before the journal delete: re-plant the journal by hand.
		const safeFrom = Buffer.from(FROM, "utf8").toString("base64url");
		await bucket.put(`p/migrations/${safeFrom}.json`, bytes(JSON.stringify({ to: TO })));
		expect(await store.migrate(FROM, TO)).toBe(MigrateOutcome.AlreadyDone);
		expect((await backfillStrings(store, TO)).length).toBe(4);
		expect(await bucket.get(`p/migrations/${safeFrom}.json`)).toBeNull();
	});

	test("a journal pointing at a DIFFERENT target denies the rotate", async () => {
		const bucket = new MemoryBucket();
		const store = new ObjectSnapshotStore(bucket, "p/");
		await seed(store, FROM);
		const safeFrom = Buffer.from(FROM, "utf8").toString("base64url");
		await bucket.put(`p/migrations/${safeFrom}.json`, bytes(JSON.stringify({ to: OTHER })));
		expect(await store.migrate(FROM, TO)).toBe(MigrateOutcome.Conflict);
		// The source is untouched — recoverable under the old id.
		expect(await backfillStrings(store, FROM)).toContain(`snap:${FROM}`);
	});
});

describe("migrate crash windows (file backend rename atomicity)", () => {
	test("every reachable crash state serves the FULL data under exactly one id", async () => {
		// The file backend re-homes with ONE atomic directory rename, so the only
		// reachable states are pre-rename (all under `from`) and post-rename (all
		// under `to`). Assert both states are complete and the retry converges.
		const store = await fileStore();
		await seed(store, FROM);
		// Pre-rename state: everything under `from`.
		expect((await backfillStrings(store, FROM)).length).toBe(4);
		expect(await backfillStrings(store, TO)).toEqual([]);
		// Post-rename state: everything under `to`; retry is AlreadyDone.
		expect(await store.migrate(FROM, TO)).toBe(MigrateOutcome.Moved);
		expect((await backfillStrings(store, TO)).length).toBe(4);
		expect(await backfillStrings(store, FROM)).toEqual([]);
		expect(await store.migrate(FROM, TO)).toBe(MigrateOutcome.AlreadyDone);
	});
});
