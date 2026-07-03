/**
 * Asset-B3/B6 — the durable node's content-addressed chunk store. Zero-dep
 * `bun test`. Covers the in-memory + filesystem + object backends via one
 * contract suite (round-trip, immutability, miss, GC delete), hash validation /
 * path-traversal defense, and durability across a restart.
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type AssetCas, MemoryAssetCas, isAssetHash } from "./asset-cas";
import { FileAssetCas } from "./file-asset-cas";
import { ObjectAssetCas } from "./object-asset-cas";
import { MemoryBucket } from "./object-store";

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);

describe("isAssetHash", () => {
	test("accepts a 64-hex address, rejects everything else", () => {
		expect(isAssetHash(HASH_A)).toBe(true);
		expect(isAssetHash("")).toBe(false);
		expect(isAssetHash("a".repeat(63))).toBe(false);
		expect(isAssetHash("A".repeat(64))).toBe(false); // uppercase
		expect(isAssetHash("../../etc/passwd")).toBe(false); // traversal
		expect(isAssetHash(42)).toBe(false);
	});
});

function casContract(make: () => AssetCas) {
	test("put → has → get round-trips", async () => {
		const cas = make();
		const chunk = crypto.getRandomValues(new Uint8Array(1024));
		expect(await cas.has(HASH_A)).toBe(false);
		expect(await cas.get(HASH_A)).toBeNull();
		await cas.put(HASH_A, chunk);
		expect(await cas.has(HASH_A)).toBe(true);
		const got = await cas.get(HASH_A);
		expect(got).not.toBeNull();
		expect(Buffer.from(got as Uint8Array).equals(Buffer.from(chunk))).toBe(true);
	});

	test("put is idempotent (immutable content)", async () => {
		const cas = make();
		const chunk = crypto.getRandomValues(new Uint8Array(64));
		await cas.put(HASH_A, chunk);
		await cas.put(HASH_A, chunk); // no-op, no throw
		expect(await cas.has(HASH_A)).toBe(true);
	});

	test("distinct addresses are independent", async () => {
		const cas = make();
		await cas.put(HASH_A, new Uint8Array([1, 2, 3]));
		expect(await cas.has(HASH_B)).toBe(false);
	});

	test("delete removes a chunk (Asset-B6 GC reclaim); deleting an absent one is a no-op", async () => {
		const cas = make();
		await cas.put(HASH_A, new Uint8Array([1, 2, 3]));
		await cas.put(HASH_B, new Uint8Array([4]));
		await cas.delete(HASH_A);
		expect(await cas.has(HASH_A)).toBe(false);
		expect(await cas.get(HASH_A)).toBeNull();
		expect(await cas.has(HASH_B)).toBe(true); // siblings untouched
		await cas.delete(HASH_A); // absent — no throw
		await cas.delete("../../escape"); // hostile — no-op, no traversal
	});
}

describe("MemoryAssetCas", () => {
	casContract(() => new MemoryAssetCas());
	test("size reflects distinct chunks", async () => {
		const cas = new MemoryAssetCas();
		await cas.put(HASH_A, new Uint8Array([1]));
		await cas.put(HASH_A, new Uint8Array([1]));
		await cas.put(HASH_B, new Uint8Array([2]));
		expect(cas.size).toBe(2);
	});
});

describe("FileAssetCas", () => {
	let dir: string;
	beforeEach(async () => {
		dir = await mkdtemp(join(tmpdir(), "asset-cas-"));
	});
	afterEach(async () => {
		await rm(dir, { recursive: true, force: true });
	});

	casContract(() => new FileAssetCas(dir));

	test("rejects an invalid hash on put / returns null+false on get/has", async () => {
		const cas = new FileAssetCas(dir);
		await expect(cas.put("../../escape", new Uint8Array([1]))).rejects.toThrow();
		expect(await cas.get("../../escape")).toBeNull();
		expect(await cas.has("../../escape")).toBe(false);
		// Nothing leaked outside the root.
		const entries = await readdir(dir).catch(() => []);
		expect(entries.every((e) => e.length === 2)).toBe(true); // only 2-char shard dirs
	});

	test("shards by the first two hash chars", async () => {
		const cas = new FileAssetCas(dir);
		await cas.put(HASH_A, new Uint8Array([1]));
		const shards = await readdir(dir);
		expect(shards).toContain("aa");
	});

	test("survives a restart (durable)", async () => {
		const chunk = crypto.getRandomValues(new Uint8Array(2048));
		await new FileAssetCas(dir).put(HASH_A, chunk);
		const reopened = new FileAssetCas(dir); // fresh instance, same root
		const got = await reopened.get(HASH_A);
		expect(Buffer.from(got as Uint8Array).equals(Buffer.from(chunk))).toBe(true);
	});

	test("concurrent puts of the same address don't race", async () => {
		const cas = new FileAssetCas(dir);
		const chunk = crypto.getRandomValues(new Uint8Array(512));
		await Promise.all([cas.put(HASH_A, chunk), cas.put(HASH_A, chunk), cas.put(HASH_A, chunk)]);
		const got = await cas.get(HASH_A);
		expect(Buffer.from(got as Uint8Array).equals(Buffer.from(chunk))).toBe(true);
	});
});

describe("ObjectAssetCas", () => {
	casContract(() => new ObjectAssetCas(new MemoryBucket(), "node1/"));

	test("delete removes exactly the chunk's object", async () => {
		const bucket = new MemoryBucket();
		const cas = new ObjectAssetCas(bucket, "node1/");
		await cas.put(HASH_A, new Uint8Array([1]));
		await cas.put(HASH_B, new Uint8Array([2]));
		expect(bucket.size()).toBe(2);
		await cas.delete(HASH_A);
		expect(bucket.size()).toBe(1);
		expect(await bucket.get(`node1/assets/${HASH_B}.bin`)).not.toBeNull();
	});
});
