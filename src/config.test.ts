import { describe, expect, test } from "bun:test";
import { readConfig } from "./main";
import { DEFAULT_GRACE_MS, DEFAULT_RETENTION_MS } from "./sync/asset-gc";

describe("readConfig", () => {
	test("defaults", () => {
		const c = readConfig({});
		expect(c.port).toBe(7780);
		expect(c.auditLogPath).toBeNull();
		expect(c.debug).toBe(false);
	});

	test("reads PORT / AUDIT_LOG_PATH / LOG_LEVEL", () => {
		const c = readConfig({ PORT: "9001", AUDIT_LOG_PATH: "/tmp/a.log", LOG_LEVEL: "debug" });
		expect(c.port).toBe(9001);
		expect(c.auditLogPath).toBe("/tmp/a.log");
		expect(c.debug).toBe(true);
	});

	test("rejects an out-of-range port", () => {
		expect(() => readConfig({ PORT: "0" })).toThrow();
		expect(() => readConfig({ PORT: "70000" })).toThrow();
		expect(() => readConfig({ PORT: "nope" })).toThrow();
	});

	test("empty AUDIT_LOG_PATH is treated as unset", () => {
		expect(readConfig({ AUDIT_LOG_PATH: "" }).auditLogPath).toBeNull();
	});

	test("storage defaults to forward-only (none)", () => {
		expect(readConfig({}).storage).toEqual({ kind: "none" });
	});

	test("STORAGE_DIR selects the local provider", () => {
		expect(readConfig({ STORAGE_DIR: "/data" }).storage).toEqual({ kind: "local", dir: "/data" });
	});

	test("S3_* env selects the s3 provider (backend inferred from S3_BUCKET)", () => {
		const c = readConfig({
			S3_BUCKET: "b",
			S3_ACCESS_KEY_ID: "k",
			S3_SECRET_ACCESS_KEY: "s",
			S3_ENDPOINT: "https://r2.example",
			S3_PREFIX: "node1/",
		});
		expect(c.storage).toEqual({
			kind: "s3",
			s3: {
				bucket: "b",
				accessKeyId: "k",
				secretAccessKey: "s",
				endpoint: "https://r2.example",
				prefix: "node1/",
			},
		});
	});

	test("STORAGE_BACKEND=s3 without credentials throws", () => {
		expect(() => readConfig({ STORAGE_BACKEND: "s3" })).toThrow(/S3_BUCKET/);
	});

	test("STORAGE_BACKEND=s3 overrides a present STORAGE_DIR", () => {
		const c = readConfig({
			STORAGE_BACKEND: "s3",
			STORAGE_DIR: "/data",
			S3_BUCKET: "b",
			S3_ACCESS_KEY_ID: "k",
			S3_SECRET_ACCESS_KEY: "s",
		});
		expect(c.storage.kind).toBe("s3");
	});

	test("asset GC defaults: 30d grace, 90d retention, no automatic sweep", () => {
		expect(readConfig({}).assetGc).toEqual({
			graceMs: DEFAULT_GRACE_MS,
			retentionMs: DEFAULT_RETENTION_MS,
			sweepIntervalMs: null,
		});
	});

	test("ASSET_GC_* env overrides the windows and enables the sweep interval", () => {
		const c = readConfig({
			ASSET_GC_GRACE_MS: "60000",
			ASSET_GC_RETENTION_MS: "120000",
			ASSET_GC_SWEEP_INTERVAL_MS: "5000",
		});
		expect(c.assetGc).toEqual({ graceMs: 60_000, retentionMs: 120_000, sweepIntervalMs: 5000 });
	});

	test("ASSET_GC_SWEEP_INTERVAL_MS=0 means no automatic sweep", () => {
		expect(readConfig({ ASSET_GC_SWEEP_INTERVAL_MS: "0" }).assetGc.sweepIntervalMs).toBeNull();
	});

	test("rejects non-positive / non-integer GC windows", () => {
		expect(() => readConfig({ ASSET_GC_GRACE_MS: "0" })).toThrow(/positive/);
		expect(() => readConfig({ ASSET_GC_RETENTION_MS: "0" })).toThrow(/positive/);
		expect(() => readConfig({ ASSET_GC_GRACE_MS: "-5" })).toThrow();
		expect(() => readConfig({ ASSET_GC_RETENTION_MS: "ninety days" })).toThrow();
	});
});
