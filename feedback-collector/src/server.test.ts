import { describe, expect, test } from "bun:test";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { GithubPipe } from "./github";
import type { StoredRecord } from "./ingest";
import { MAX_BODY_BYTES, makeCollector } from "./server";
import { JsonlStore } from "./store";
import { validCrash, validFeedback } from "./test-fixtures";

function silentPipe(): GithubPipe {
	return new GithubPipe({ repo: "", token: "", dryRun: false }, fetch, () => {});
}

async function tempStore(): Promise<{ store: JsonlStore; dir: string }> {
	const dir = await mkdtemp(join(tmpdir(), "feedback-collector-"));
	return { store: new JsonlStore(dir), dir };
}

function post(body: unknown, headers: Record<string, string> = {}): Request {
	return new Request("http://collector.local/", {
		method: "POST",
		headers: { "content-type": "application/json", ...headers },
		body: typeof body === "string" ? body : JSON.stringify(body),
	});
}

describe("collector routing", () => {
	test("GET /healthz → 200 ok", async () => {
		const { store } = await tempStore();
		const c = makeCollector({ store, pipe: silentPipe() });
		const res = await c.handle(new Request("http://x/healthz"), "1.1.1.1");
		expect(res.status).toBe(200);
		expect(await res.text()).toBe("ok");
	});

	test("GET elsewhere → 405", async () => {
		const { store } = await tempStore();
		const c = makeCollector({ store, pipe: silentPipe() });
		const res = await c.handle(new Request("http://x/"), "1.1.1.1");
		expect(res.status).toBe(405);
	});

	test("valid feedback → 200 + JSONL row", async () => {
		const { store, dir } = await tempStore();
		const c = makeCollector({ store, pipe: silentPipe(), now: () => Date.UTC(2026, 6, 19) });
		const res = await c.handle(post(validFeedback()), "1.1.1.1");
		expect(res.status).toBe(200);
		expect(c.stats.accepted).toBe(1);
		const rows = (await readFile(join(dir, "feedback-2026-07.jsonl"), "utf8"))
			.trim()
			.split("\n")
			.map((l) => JSON.parse(l) as StoredRecord);
		expect(rows.length).toBe(1);
		expect(rows[0]?.recordKind).toBe("feedback");
	});

	test("valid crash with header → 200 + crash JSONL row", async () => {
		const { store, dir } = await tempStore();
		const c = makeCollector({ store, pipe: silentPipe(), now: () => Date.UTC(2026, 6, 19) });
		const res = await c.handle(
			post(validCrash(), { "x-brainstorm-crash-kind": "renderer-crashed" }),
			"1.1.1.1",
		);
		expect(res.status).toBe(200);
		const rows = (await readFile(join(dir, "crash-2026-07.jsonl"), "utf8")).trim().split("\n");
		expect(rows.length).toBe(1);
	});

	test("malformed JSON → 400 not-json", async () => {
		const { store } = await tempStore();
		const c = makeCollector({ store, pipe: silentPipe() });
		const res = await c.handle(post("{nope"), "1.1.1.1");
		expect(res.status).toBe(400);
	});

	test("invalid payload → 400 with classified reason", async () => {
		const { store } = await tempStore();
		const c = makeCollector({ store, pipe: silentPipe() });
		const res = await c.handle(post({ ...validFeedback(), title: "" }), "1.1.1.1");
		expect(res.status).toBe(400);
		expect(((await res.json()) as { error: string }).error).toBe("feedback:invalid-title");
	});

	test("oversize body → 413", async () => {
		const { store } = await tempStore();
		const c = makeCollector({ store, pipe: silentPipe() });
		const res = await c.handle(post("x".repeat(MAX_BODY_BYTES + 1)), "1.1.1.1");
		expect(res.status).toBe(413);
	});
});

describe("collector rate limiting", () => {
	test("feedback burst exhausts per installation → 429", async () => {
		const { store } = await tempStore();
		let clock = 0;
		const c = makeCollector({
			store,
			pipe: silentPipe(),
			now: () => clock,
			limits: {
				feedbackPerSec: 0,
				feedbackBurst: 2,
				crashPerSec: 0,
				crashBurst: 2,
				disabled: false,
			},
		});
		// Distinct IPs so only the installation key can be the limiter that trips.
		expect((await c.handle(post(validFeedback()), "1.1.1.1")).status).toBe(200);
		clock += 10;
		expect((await c.handle(post(validFeedback()), "2.2.2.2")).status).toBe(200);
		clock += 10;
		expect((await c.handle(post(validFeedback()), "3.3.3.3")).status).toBe(429);
		expect(c.stats.rateLimited).toBe(1);
	});

	test("per-IP limit trips across installations", async () => {
		const { store } = await tempStore();
		const other = { ...validFeedback(), installationId: "01BX5ZZKBKACTAV9WEVGEMMVS0" };
		const c = makeCollector({
			store,
			pipe: silentPipe(),
			now: () => 0,
			limits: {
				feedbackPerSec: 0,
				feedbackBurst: 1,
				crashPerSec: 0,
				crashBurst: 1,
				disabled: false,
			},
		});
		expect((await c.handle(post(validFeedback()), "9.9.9.9")).status).toBe(200);
		expect((await c.handle(post(other), "9.9.9.9")).status).toBe(429);
	});

	test("crash and feedback ride separate limiters", async () => {
		const { store } = await tempStore();
		const c = makeCollector({
			store,
			pipe: silentPipe(),
			now: () => 0,
			limits: {
				feedbackPerSec: 0,
				feedbackBurst: 1,
				crashPerSec: 0,
				crashBurst: 1,
				disabled: false,
			},
		});
		expect((await c.handle(post(validFeedback()), "1.1.1.1")).status).toBe(200);
		expect((await c.handle(post(validCrash()), "1.1.1.1")).status).toBe(200);
	});

	test("disabled limits never 429", async () => {
		const { store } = await tempStore();
		const c = makeCollector({
			store,
			pipe: silentPipe(),
			now: () => 0,
			limits: {
				feedbackPerSec: 0,
				feedbackBurst: 1,
				crashPerSec: 0,
				crashBurst: 1,
				disabled: true,
			},
		});
		for (let i = 0; i < 5; i++) {
			expect((await c.handle(post(validFeedback()), "1.1.1.1")).status).toBe(200);
		}
	});
});

describe("collector storage failure", () => {
	test("append throw → 500 (client will retry)", async () => {
		const badStore = {
			append: () => Promise.reject(new Error("disk full")),
		} as unknown as JsonlStore;
		const c = makeCollector({ store: badStore, pipe: silentPipe(), log: () => {} });
		const res = await c.handle(post(validFeedback()), "1.1.1.1");
		expect(res.status).toBe(500);
	});
});
