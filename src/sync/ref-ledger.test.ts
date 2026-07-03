/**
 * Asset-B6 — the GC ref ledger. Zero-dep `bun test`. One contract suite over
 * the in-memory / filesystem / object backends (report state round-trip,
 * serialized updates, account enumeration), plus file/object durability across
 * a reopen and default-on-corrupt.
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FileRefLedger } from "./file-ref-ledger";
import { ObjectRefLedger } from "./object-ref-ledger";
import { MemoryBucket } from "./object-store";
import { MemoryRefLedger, type RefLedger, sanitizeGcState } from "./ref-ledger";

const H1 = "1".repeat(64);
const H2 = "2".repeat(64);
const ACCOUNT = "acct/pubkey+specials"; // exercises the base64url path mapping

function ledgerContract(make: () => RefLedger) {
	test("read of an unknown account is the empty default", async () => {
		const ledger = make();
		expect(await ledger.read("nobody")).toEqual({ devices: {}, owned: {}, marked: {} });
		expect(await ledger.accounts()).toEqual([]);
	});

	test("update persists devices / owned / marked and accounts() lists it", async () => {
		const ledger = make();
		await ledger.update(ACCOUNT, (s) => {
			s.devices.d1 = { lastReportAt: 111, refs: [H1] };
			s.owned[H1] = 1024;
			s.marked[H2] = 222;
		});
		const state = await ledger.read(ACCOUNT);
		expect(state.devices.d1).toEqual({ lastReportAt: 111, refs: [H1] });
		expect(state.owned[H1]).toBe(1024);
		expect(state.marked[H2]).toBe(222);
		expect(await ledger.accounts()).toEqual([ACCOUNT]);
	});

	test("read returns a copy — mutating it does not leak into the ledger", async () => {
		const ledger = make();
		await ledger.update(ACCOUNT, (s) => {
			s.owned[H1] = 5;
		});
		const state = await ledger.read(ACCOUNT);
		state.owned[H2] = 99;
		expect((await ledger.read(ACCOUNT)).owned[H2]).toBeUndefined();
	});

	test("concurrent updates to one account serialize (no lost writes)", async () => {
		const ledger = make();
		await Promise.all(
			Array.from({ length: 10 }, (_, i) =>
				ledger.update(ACCOUNT, (s) => {
					s.marked[`${String(i).repeat(64).slice(0, 64)}`] = i;
				}),
			),
		);
		expect(Object.keys((await ledger.read(ACCOUNT)).marked).length).toBe(10);
	});
}

describe("MemoryRefLedger", () => {
	ledgerContract(() => new MemoryRefLedger());
});

describe("FileRefLedger", () => {
	let dir: string;
	beforeEach(async () => {
		dir = await mkdtemp(join(tmpdir(), "ref-ledger-"));
	});
	afterEach(async () => {
		await rm(dir, { recursive: true, force: true });
	});

	ledgerContract(() => new FileRefLedger(dir));

	test("state survives a reopen (durable)", async () => {
		await new FileRefLedger(dir).update(ACCOUNT, (s) => {
			s.devices.d1 = { lastReportAt: 7, refs: [H1, H2] };
			s.owned[H1] = 3;
		});
		const reopened = new FileRefLedger(dir);
		expect(await reopened.accounts()).toEqual([ACCOUNT]);
		expect((await reopened.read(ACCOUNT)).devices.d1?.refs).toEqual([H1, H2]);
	});

	test("a corrupt ledger file degrades to empty state (GC-conservative)", async () => {
		const safe = Buffer.from(ACCOUNT, "utf8").toString("base64url");
		await writeFile(join(dir, `${safe}.json`), "{not json", "utf8");
		expect(await new FileRefLedger(dir).read(ACCOUNT)).toEqual({
			devices: {},
			owned: {},
			marked: {},
		});
	});
});

describe("ObjectRefLedger", () => {
	ledgerContract(() => new ObjectRefLedger(new MemoryBucket(), "node1/"));

	test("state survives a reopen over the same bucket, under the gc prefix", async () => {
		const bucket = new MemoryBucket();
		await new ObjectRefLedger(bucket, "node1/").update(ACCOUNT, (s) => {
			s.owned[H1] = 9;
		});
		const keys = await bucket.list("node1/asset-gc/");
		expect(keys.length).toBe(1);
		const reopened = new ObjectRefLedger(bucket, "node1/");
		expect((await reopened.read(ACCOUNT)).owned[H1]).toBe(9);
		expect(await reopened.accounts()).toEqual([ACCOUNT]);
	});
});

describe("sanitizeGcState", () => {
	test("drops malformed devices / non-hash keys / negative sizes", () => {
		const state = sanitizeGcState({
			devices: {
				ok: { lastReportAt: 1, refs: [H1, "nope", 42] },
				bad: { refs: [H1] },
				worse: "x",
			},
			owned: { [H1]: 10, "../etc": 1, [H2]: -5 },
			marked: { [H2]: 3, short: 1 },
		});
		expect(state.devices.ok).toEqual({ lastReportAt: 1, refs: [H1] });
		expect(state.devices.bad).toBeUndefined();
		expect(state.owned).toEqual({ [H1]: 10 });
		expect(state.marked).toEqual({ [H2]: 3 });
	});
});
