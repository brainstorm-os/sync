import { describe, expect, test } from "bun:test";
import { classify, ingest, validateCrash, validateFeedback } from "./ingest";
import { FIXTURE_ULID as ULID, validCrash, validFeedback } from "./test-fixtures";

describe("classify", () => {
	test("crash header wins regardless of body", () => {
		expect(classify(validFeedback(), "renderer-crashed")).toBe("crash");
	});
	test("crash kind in body", () => {
		expect(classify(validCrash(), null)).toBe("crash");
	});
	test("duration + capturedAt fallback", () => {
		const body = { ...validCrash(), kind: undefined };
		expect(classify(body, null)).toBe("crash");
	});
	test("defaults to feedback", () => {
		expect(classify(validFeedback(), null)).toBe("feedback");
	});
});

describe("validateFeedback", () => {
	test("accepts a valid payload", () => {
		expect(validateFeedback(validFeedback()).ok).toBe(true);
	});
	test("accepts contactEmail under identity-voluntary", () => {
		const r = validateFeedback({
			...validFeedback(),
			sensitivity: "identity-voluntary",
			contactEmail: "a@b.co",
		});
		expect(r.ok).toBe(true);
	});
	test("tolerates unknown extra fields", () => {
		expect(validateFeedback({ ...validFeedback(), futureField: 42 }).ok).toBe(true);
	});
	const invalids: [string, Record<string, unknown>][] = [
		["invalid-kind", { kind: "rant" }],
		["invalid-title", { title: "" }],
		["invalid-title", { title: "x".repeat(201) }],
		["invalid-body", { body: "" }],
		["invalid-body", { body: "x".repeat(10_001) }],
		["invalid-sensitivity", { sensitivity: "public" }],
		["invalid-include-log", { includeRecentLog: "yes" }],
		["invalid-log-excerpt", { recentLogExcerpt: "x".repeat(64 * 1024 + 1) }],
		["invalid-client-version", { clientVersion: "" }],
		["invalid-platform", { clientPlatform: "" }],
		["invalid-submitted-at", { submittedAt: "now" }],
		["invalid-request-id", { requestId: "short" }],
		["invalid-request-id", { requestId: `${ULID.slice(0, 25)}U` }],
		["invalid-installation-id", { installationId: 7 }],
	];
	for (const [reason, patch] of invalids) {
		test(`rejects ${reason} (${JSON.stringify(patch).slice(0, 40)})`, () => {
			const r = validateFeedback({ ...validFeedback(), ...patch });
			expect(r.ok).toBe(false);
			if (!r.ok) expect(r.reason).toBe(reason);
		});
	}
});

describe("validateCrash", () => {
	test("accepts a valid payload", () => {
		expect(validateCrash(validCrash()).ok).toBe(true);
	});
	test("accepts minimal payload (no stack / reason / app)", () => {
		const { stack, rendererReason, appId, ...rest } = validCrash();
		expect(validateCrash(rest).ok).toBe(true);
	});
	const invalids: [string, Record<string, unknown>][] = [
		["invalid-kind", { kind: "explosion" }],
		["invalid-renderer-reason", { rendererReason: "gremlins" }],
		["invalid-exit-code", { exitCode: 1.5 }],
		["invalid-message", { message: "" }],
		["invalid-message", { message: "x".repeat(1025) }],
		["invalid-stack", { stack: "x".repeat(32 * 1024 + 1) }],
		["invalid-log-excerpt", { recentLogExcerpt: undefined }],
		["invalid-captured-at", { capturedAt: null }],
		["invalid-duration", { durationSinceBootMs: -1 }],
		["invalid-request-id", { requestId: "nope" }],
	];
	for (const [reason, patch] of invalids) {
		test(`rejects ${reason}`, () => {
			const r = validateCrash({ ...validCrash(), ...patch });
			expect(r.ok).toBe(false);
			if (!r.ok) expect(r.reason).toBe(reason);
		});
	}
});

describe("ingest", () => {
	test("stamps receivedAt from the injected clock", () => {
		const r = ingest(validFeedback(), null, () => 42);
		expect(r.ok).toBe(true);
		if (r.ok) {
			expect(r.record.receivedAt).toBe(42);
			expect(r.record.recordKind).toBe("feedback");
		}
	});
	test("rejects non-objects with not-an-object", () => {
		for (const bad of [null, 3, "hi", [1]]) {
			const r = ingest(bad, null, Date.now);
			expect(r.ok).toBe(false);
			if (!r.ok) expect(r.reason).toBe("not-an-object");
		}
	});
	test("prefixes reason with the classified kind", () => {
		const r = ingest({ ...validCrash(), message: "" }, null, Date.now);
		expect(r.ok).toBe(false);
		if (!r.ok) expect(r.reason).toBe("crash:invalid-message");
	});
});
