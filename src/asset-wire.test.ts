/**
 * Asset-B3/B6 — the node's asset wire protocol (responder side). Zero-dep
 * `bun test`. Covers request decode + validation (hash format, bad kind,
 * malformed frames, ref-report shape) and `handleAssetRequest` against an
 * in-memory CAS + GC hooks, including the metered byte counts and the
 * proven-account forcing.
 */

import { describe, expect, test } from "bun:test";
import {
	type AssetGcHooks,
	type AssetRequest,
	AssetWireKind,
	decodeAssetRequest,
	encodeAssetRequest,
	handleAssetRequest,
} from "./asset-wire";
import { MemoryAssetCas } from "./sync/asset-cas";

const HASH = "deadbeef".repeat(8);
const HASH2 = "0123abcd".repeat(8);

function recordingHooks() {
	const puts: Array<{ account: string | null; hash: string; bytes: number }> = [];
	const reports: Array<{ account: string; device: string; hashes: string[] }> = [];
	const gc: AssetGcHooks = {
		async onPut(account, hash, bytes) {
			puts.push({ account, hash, bytes });
		},
		async onReport(account, device, hashes) {
			reports.push({ account, device, hashes });
		},
	};
	return { gc, puts, reports };
}

describe("decodeAssetRequest validation", () => {
	test("round-trips a valid Has/Get/Put", () => {
		expect(decodeAssetRequest(encodeAssetRequest({ kind: AssetWireKind.Has, hash: HASH }))).toEqual(
			{
				kind: AssetWireKind.Has,
				hash: HASH,
			},
		);
		const chunk = crypto.getRandomValues(new Uint8Array(100));
		const put = decodeAssetRequest(
			encodeAssetRequest({ kind: AssetWireKind.Put, hash: HASH, chunk }),
		);
		expect(put.kind).toBe(AssetWireKind.Put);
		if (put.kind === AssetWireKind.Put) {
			expect(Buffer.from(put.chunk).equals(Buffer.from(chunk))).toBe(true);
		}
	});

	test("rejects a non-64-hex address (path-traversal / malformed)", () => {
		const bad = encodeAssetRequest({ kind: AssetWireKind.Get, hash: "../../escape" });
		expect(() => decodeAssetRequest(bad)).toThrow(/64-hex/);
		const short = encodeAssetRequest({ kind: AssetWireKind.Get, hash: "abc" });
		expect(() => decodeAssetRequest(short)).toThrow(/64-hex/);
	});

	test("rejects a bad kind / truncated / non-JSON frame", () => {
		expect(() => decodeAssetRequest(new Uint8Array([0, 0]))).toThrow();
		const bad = new Uint8Array(8);
		new DataView(bad.buffer).setUint32(0, 999, false);
		expect(() => decodeAssetRequest(bad)).toThrow();
		const bogus = encodeAssetRequest({ kind: "bogus", hash: HASH } as unknown as AssetRequest);
		expect(() => decodeAssetRequest(bogus)).toThrow(/bad kind/);
	});

	test("round-trips a Refs report (including an empty set)", () => {
		const full = decodeAssetRequest(
			encodeAssetRequest({
				kind: AssetWireKind.Refs,
				account: "acct",
				device: "laptop",
				hashes: [HASH, HASH2],
			}),
		);
		expect(full).toEqual({
			kind: AssetWireKind.Refs,
			account: "acct",
			device: "laptop",
			hashes: [HASH, HASH2],
		});
		const empty = decodeAssetRequest(
			encodeAssetRequest({ kind: AssetWireKind.Refs, account: "acct", device: "d", hashes: [] }),
		);
		expect(empty).toEqual({ kind: AssetWireKind.Refs, account: "acct", device: "d", hashes: [] });
	});

	test("rejects a malformed Refs report", () => {
		const refs = (over: Record<string, unknown>, hashes: string[] = []) =>
			encodeAssetRequest({
				kind: AssetWireKind.Refs,
				account: "acct",
				device: "d",
				hashes,
				...over,
			} as AssetRequest);
		expect(() => decodeAssetRequest(refs({ account: "" }))).toThrow(/account/);
		expect(() => decodeAssetRequest(refs({ account: 7 }))).toThrow(/account/);
		expect(() => decodeAssetRequest(refs({ device: "" }))).toThrow(/device/);
		expect(() => decodeAssetRequest(refs({ device: "x".repeat(129) }))).toThrow(/device/);
		// A ref-set entry that is not a 64-hex address (uppercase / traversal).
		expect(() => decodeAssetRequest(refs({}, ["A".repeat(64)]))).toThrow(/64-hex/);
		expect(() => decodeAssetRequest(refs({}, ["../escape".padEnd(64, "x")]))).toThrow(/64-hex/);
		// A ragged trailing chunk (not a multiple of 64).
		const ragged = encodeAssetRequest({
			kind: AssetWireKind.Refs,
			account: "acct",
			device: "d",
			hashes: [HASH.slice(0, 32)],
		});
		expect(() => decodeAssetRequest(ragged)).toThrow(/multiple of 64/);
	});
});

describe("handleAssetRequest", () => {
	test("Has / Put / Get against the CAS, with metered bytes", async () => {
		const cas = new MemoryAssetCas();
		const chunk = crypto.getRandomValues(new Uint8Array(4096));

		const has0 = await handleAssetRequest(
			cas,
			encodeAssetRequest({ kind: AssetWireKind.Has, hash: HASH }),
		);
		expect(has0.meteredBytes).toBe(0);

		const put = await handleAssetRequest(
			cas,
			encodeAssetRequest({ kind: AssetWireKind.Put, hash: HASH, chunk }),
		);
		expect(put.meteredBytes).toBe(chunk.length); // ingress = chunk size
		expect(await cas.has(HASH)).toBe(true);

		const get = await handleAssetRequest(
			cas,
			encodeAssetRequest({ kind: AssetWireKind.Get, hash: HASH }),
		);
		expect(get.meteredBytes).toBe(chunk.length); // egress = chunk size

		const miss = await handleAssetRequest(
			cas,
			encodeAssetRequest({ kind: AssetWireKind.Get, hash: "f".repeat(64) }),
		);
		expect(miss.meteredBytes).toBe(0);
	});

	test("a Refs report reaches the GC hooks; the proven account overrides the header", async () => {
		const cas = new MemoryAssetCas();
		const { gc, reports } = recordingHooks();
		const req = encodeAssetRequest({
			kind: AssetWireKind.Refs,
			account: "forged",
			device: "laptop",
			hashes: [HASH],
		});

		// Gated context: the header account is IGNORED in favor of the proven one.
		const gated = await handleAssetRequest(cas, req, { gc, account: "proven" });
		expect(gated.kind).toBe(AssetWireKind.Refs);
		expect(gated.meteredBytes).toBe(0);
		expect(reports).toEqual([{ account: "proven", device: "laptop", hashes: [HASH] }]);

		// Open context (no proven account): the header account is used.
		await handleAssetRequest(cas, req, { gc, account: null });
		expect(reports[1]?.account).toBe("forged");
	});

	test("a Refs report on a node with no GC plane is rejected (dropped upstream)", async () => {
		const cas = new MemoryAssetCas();
		const req = encodeAssetRequest({
			kind: AssetWireKind.Refs,
			account: "a",
			device: "d",
			hashes: [],
		});
		await expect(handleAssetRequest(cas, req)).rejects.toThrow(/unsupported/);
	});

	test("a Put attributes ownership to the proven account via the GC hooks", async () => {
		const cas = new MemoryAssetCas();
		const { gc, puts } = recordingHooks();
		const chunk = new Uint8Array(32);
		await handleAssetRequest(
			cas,
			encodeAssetRequest({ kind: AssetWireKind.Put, hash: HASH, chunk }),
			{
				gc,
				account: "proven",
			},
		);
		expect(puts).toEqual([{ account: "proven", hash: HASH, bytes: 32 }]);
	});
});
