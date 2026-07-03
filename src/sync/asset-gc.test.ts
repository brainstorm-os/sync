/**
 * Asset-B6 — conservative mark-and-sweep semantics. Zero-dep `bun test` over
 * the in-memory CAS + ledger with an injected clock: the grace gate (mark →
 * reversible → delete), the last-seen retention guard (stale-but-within
 * protects, beyond stops counting, no-fresh-report skips the account), union
 * semantics across devices and accounts, ownership attribution, idempotent
 * re-reports, and the reclaimed-bytes metering surface.
 */

import { describe, expect, test } from "bun:test";
import { type MeterEvent, MeterKind } from "../metering";
import { MemoryAssetCas } from "./asset-cas";
import { AssetGc, MAX_DEVICES_PER_ACCOUNT } from "./asset-gc";
import { MemoryRefLedger } from "./ref-ledger";

const H1 = "a".repeat(64);
const H2 = "b".repeat(64);
const H3 = "c".repeat(64);

const GRACE = 1_000;
const RETENTION = 10_000;

function rig() {
	const cas = new MemoryAssetCas();
	const ledger = new MemoryRefLedger();
	const clock = { t: 0 };
	const events: MeterEvent[] = [];
	const gc = new AssetGc({
		cas,
		ledger,
		graceMs: GRACE,
		retentionMs: RETENTION,
		now: () => clock.t,
		meter: (e) => events.push(e),
	});
	return { cas, ledger, clock, events, gc };
}

async function putOwned(r: ReturnType<typeof rig>, account: string, hash: string, size = 8) {
	const chunk = new Uint8Array(size);
	await r.cas.put(hash, chunk);
	await r.gc.onPut(account, hash, chunk.length);
}

describe("AssetGc — grace gate", () => {
	test("unreferenced owned chunk: marked, kept through grace, deleted after", async () => {
		const r = rig();
		await putOwned(r, "A", H1, 100);
		await r.gc.onReport("A", "d1", [H1]);

		// Referenced — sweep marks nothing.
		let res = await r.gc.sweep();
		expect(res.marked).toBe(0);

		// The device's converged state drops the ref (full-set replace).
		await r.gc.onReport("A", "d1", []);
		res = await r.gc.sweep();
		expect(res.marked).toBe(1);
		expect(res.deleted).toBe(0);
		expect(await r.cas.has(H1)).toBe(true); // marked, NOT deleted

		// Inside the grace window — still there.
		r.clock.t += GRACE - 1;
		res = await r.gc.sweep();
		expect(res.deleted).toBe(0);
		expect(await r.cas.has(H1)).toBe(true);

		// Grace expired — deleted, ledger cleaned, bytes metered.
		r.clock.t += 1;
		res = await r.gc.sweep();
		expect(res.deleted).toBe(1);
		expect(res.reclaimedBytes).toBe(100);
		expect(await r.cas.has(H1)).toBe(false);
		const state = await r.ledger.read("A");
		expect(state.owned[H1]).toBeUndefined();
		expect(state.marked[H1]).toBeUndefined();
		const reclaim = r.events.find((e) => e.kind === MeterKind.Reclaim);
		expect(reclaim?.account).toBe("A");
		expect(reclaim?.bytes).toBe(100);
	});

	test("a re-reference (report) during grace un-marks — reversible", async () => {
		const r = rig();
		await putOwned(r, "A", H1);
		await r.gc.onReport("A", "d1", []);
		await r.gc.sweep(); // marked at t=0
		expect((await r.ledger.read("A")).marked[H1]).toBe(0);

		await r.gc.onReport("A", "d1", [H1]); // the offline edit re-referenced it
		r.clock.t += GRACE * 5;
		const res = await r.gc.sweep();
		expect(res.deleted).toBe(0);
		expect(await r.cas.has(H1)).toBe(true);
		expect((await r.ledger.read("A")).marked[H1]).toBeUndefined();
	});

	test("a re-PUT during grace un-marks and grace restarts on the next mark", async () => {
		const r = rig();
		await putOwned(r, "A", H1);
		await r.gc.onReport("A", "d1", []);
		await r.gc.sweep(); // marked at t=0
		r.clock.t = GRACE - 1;
		await putOwned(r, "A", H1); // re-upload rescues it
		r.clock.t = GRACE + 1; // past the ORIGINAL mark's grace
		const res = await r.gc.sweep(); // re-marks now (still unreferenced)
		expect(res.deleted).toBe(0);
		expect(res.marked).toBe(1);
		expect(await r.cas.has(H1)).toBe(true);
	});

	test("idempotent re-reports: same full-set twice changes nothing", async () => {
		const r = rig();
		await putOwned(r, "A", H1);
		await r.gc.onReport("A", "d1", [H1, H1]); // dup entries collapse too
		const first = await r.ledger.read("A");
		await r.gc.onReport("A", "d1", [H1]);
		expect(await r.ledger.read("A")).toEqual(first);
		const res = await r.gc.sweep();
		expect(res.marked).toBe(0);
		expect(res.deleted).toBe(0);
	});
});

describe("AssetGc — last-seen retention guard", () => {
	test("union across devices: only chunks no device references are marked", async () => {
		const r = rig();
		await putOwned(r, "A", H1);
		await putOwned(r, "A", H2);
		await putOwned(r, "A", H3);
		await r.gc.onReport("A", "laptop", [H1]);
		await r.gc.onReport("A", "phone", [H2]);
		const res = await r.gc.sweep();
		expect(res.marked).toBe(1);
		const state = await r.ledger.read("A");
		expect(state.marked[H3]).toBeDefined();
		expect(state.marked[H1]).toBeUndefined();
		expect(state.marked[H2]).toBeUndefined();
	});

	test("a stale-but-within-retention device still protects its last report", async () => {
		const r = rig();
		await putOwned(r, "A", H1);
		await r.gc.onReport("A", "laptop", [H1]); // t=0, then the laptop goes offline
		r.clock.t = RETENTION - 1;
		await r.gc.onReport("A", "phone", []); // active device no longer refs H1
		const res = await r.gc.sweep();
		expect(res.marked).toBe(0); // the offline laptop may still need it
		expect(await r.cas.has(H1)).toBe(true);
	});

	test("a device silent beyond retention stops protecting (and is pruned)", async () => {
		const r = rig();
		await putOwned(r, "A", H1);
		await r.gc.onReport("A", "laptop", [H1]); // t=0
		r.clock.t = RETENTION + 1;
		await r.gc.onReport("A", "phone", []);
		let res = await r.gc.sweep();
		expect(res.marked).toBe(1);
		expect((await r.ledger.read("A")).devices.laptop).toBeUndefined(); // pruned
		r.clock.t += GRACE;
		res = await r.gc.sweep();
		expect(res.deleted).toBe(1);
		expect(await r.cas.has(H1)).toBe(false);
	});

	test("an account with no within-retention report is skipped entirely", async () => {
		const r = rig();
		await putOwned(r, "A", H1);
		await r.gc.onReport("A", "laptop", []); // even says "unreferenced"…
		r.clock.t = RETENTION + 1; // …but the whole account went dark
		const res = await r.gc.sweep();
		expect(res.skipped).toBe(1);
		expect(res.marked).toBe(0);
		expect(await r.cas.has(H1)).toBe(true); // dormant bytes are kept
	});
});

describe("AssetGc — cross-account safety", () => {
	test("a chunk another account still references is never marked", async () => {
		const r = rig();
		await putOwned(r, "A", H1); // A claims ownership…
		await r.gc.onReport("A", "d1", []); // …and doesn't reference it
		await r.cas.put(H1, new Uint8Array(4));
		await r.gc.onReport("B", "d1", [H1]); // but B still references it
		const res = await r.gc.sweep();
		expect(res.marked).toBe(0);
		expect(await r.cas.has(H1)).toBe(true);
	});

	test("chunks owned by a skipped (dormant) account are globally protected", async () => {
		const r = rig();
		await putOwned(r, "victim", H1);
		await r.gc.onReport("victim", "d1", [H1]); // t=0, then dormant
		r.clock.t = RETENTION + 1;
		await putOwned(r, "hostile", H1); // hostile co-claims the address
		await r.gc.onReport("hostile", "d1", []); // and reports it unreferenced
		r.clock.t += GRACE * 2;
		const res = await r.gc.sweep();
		expect(res.deleted).toBe(0);
		expect(await r.cas.has(H1)).toBe(true); // the dormant owner shields it
	});

	test("chunks no account owns are never touched", async () => {
		const r = rig();
		await r.cas.put(H1, new Uint8Array(4)); // pre-B6 upload, unattributed
		await r.gc.onReport("A", "d1", []);
		r.clock.t += GRACE * 2;
		const res = await r.gc.sweep();
		expect(res.marked).toBe(0);
		expect(res.deleted).toBe(0);
		expect(await r.cas.has(H1)).toBe(true);
	});

	test("a report attributes ownership, joining pre-B6 chunks to the lifecycle", async () => {
		const r = rig();
		const chunk = new Uint8Array(64);
		await r.cas.put(H1, chunk); // unattributed upload
		await r.gc.onReport("A", "d1", [H1]); // referencing it attributes it
		expect((await r.ledger.read("A")).owned[H1]).toBe(0); // size unknown
		await r.gc.onReport("A", "d1", []); // later: converged state drops it
		await r.gc.sweep();
		r.clock.t += GRACE;
		const res = await r.gc.sweep();
		expect(res.deleted).toBe(1);
		expect(res.reclaimedBytes).toBe(chunk.length); // measured at delete
		expect(await r.cas.has(H1)).toBe(false);
	});
});

describe("AssetGc — ledger bounds", () => {
	test("device entries are capped; the newest reporter is never evicted", async () => {
		const r = rig();
		for (let i = 0; i < MAX_DEVICES_PER_ACCOUNT + 8; i++) {
			r.clock.t = i;
			await r.gc.onReport("A", `device-${i}`, []);
		}
		const state = await r.ledger.read("A");
		const devices = Object.keys(state.devices);
		expect(devices.length).toBe(MAX_DEVICES_PER_ACCOUNT);
		expect(devices).toContain(`device-${MAX_DEVICES_PER_ACCOUNT + 7}`);
		expect(devices).not.toContain("device-0"); // stalest evicted
	});
});
