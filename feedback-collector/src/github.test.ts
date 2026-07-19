import { describe, expect, test } from "bun:test";
import type { CrashWire, FeedbackWire } from "./contract";
import { GithubPipe, crashFingerprint, formatCrashIssue, formatFeedbackIssue } from "./github";
import type { StoredRecord } from "./ingest";
import { validCrash, validFeedback } from "./test-fixtures";

function feedbackRecord(): StoredRecord {
	return {
		recordKind: "feedback",
		receivedAt: 1,
		payload: validFeedback() as unknown as FeedbackWire,
	};
}
function crashRecord(): StoredRecord {
	return { recordKind: "crash", receivedAt: 1, payload: validCrash() as unknown as CrashWire };
}

type Call = { url: string; init?: RequestInit };
function fakeFetcher(responder: (call: Call) => Response): { calls: Call[]; fetch: typeof fetch } {
	const calls: Call[] = [];
	const impl = async (url: string, init?: RequestInit) => {
		const call = { url, ...(init !== undefined ? { init } : {}) };
		calls.push(call);
		return responder(call);
	};
	return { calls, fetch: impl as unknown as typeof fetch };
}

describe("crashFingerprint", () => {
	test("stable for same kind + stack head", async () => {
		const a = await crashFingerprint(validCrash() as unknown as CrashWire);
		const b = await crashFingerprint(validCrash() as unknown as CrashWire);
		expect(a).toBe(b);
		expect(a).toMatch(/^[0-9a-f]{12}$/);
	});
	test("differs across kinds and stacks", async () => {
		const base = validCrash() as unknown as CrashWire;
		const otherKind = await crashFingerprint({ ...base, kind: "uncaught-exception" });
		const otherStack = await crashFingerprint({ ...base, stack: "Boom\n    at elsewhere:2:2" });
		const baseFp = await crashFingerprint(base);
		expect(otherKind).not.toBe(baseFp);
		expect(otherStack).not.toBe(baseFp);
	});
	test("falls back to message when no stack", async () => {
		const { stack, ...rest } = validCrash();
		const fp = await crashFingerprint(rest as unknown as CrashWire);
		expect(fp).toMatch(/^[0-9a-f]{12}$/);
	});
});

describe("issue formatting", () => {
	test("feedback: kind label + prefixed title, no contact row when anonymous", () => {
		const issue = formatFeedbackIssue(validFeedback() as unknown as FeedbackWire);
		expect(issue.title).toStartWith("[bug] ");
		expect(issue.labels).toEqual(["feedback", "bug"]);
		expect(issue.body).not.toContain("| contact |");
	});
	test("feedback: contact row under identity-voluntary; excerpt in details", () => {
		const issue = formatFeedbackIssue({
			...(validFeedback() as unknown as FeedbackWire),
			sensitivity: "identity-voluntary",
			contactEmail: "who@example.com",
			includeRecentLog: true,
			recentLogExcerpt: "line one",
		});
		expect(issue.body).toContain("| contact | who@example.com |");
		expect(issue.body).toContain("<details>");
		expect(issue.body).toContain("line one");
	});
	test("crash: fingerprint marker in title, stack + uptime in body", () => {
		const issue = formatCrashIssue(validCrash() as unknown as CrashWire, "abcdef012345");
		expect(issue.title).toContain("(fp-abcdef012345)");
		expect(issue.labels).toEqual(["crash"]);
		expect(issue.body).toContain("| uptime | 5s |");
		expect(issue.body).toContain("TypeError");
	});
});

describe("GithubPipe", () => {
	test("disabled without a repo — no calls", async () => {
		const { calls, fetch } = fakeFetcher(() => new Response("{}"));
		const pipe = new GithubPipe({ repo: "", token: "", dryRun: false }, fetch, () => {});
		expect(pipe.enabled).toBe(false);
		await pipe.pipe(feedbackRecord());
		expect(calls.length).toBe(0);
	});

	test("dry-run logs instead of fetching", async () => {
		const { calls, fetch } = fakeFetcher(() => new Response("{}"));
		const logged: string[] = [];
		const pipe = new GithubPipe({ repo: "o/r", token: "", dryRun: true }, fetch, (m) =>
			logged.push(m),
		);
		await pipe.pipe(feedbackRecord());
		expect(calls.length).toBe(0);
		expect(logged.join("\n")).toContain("DRY-RUN issue");
	});

	test("feedback → POST create issue with auth headers", async () => {
		const { calls, fetch } = fakeFetcher(() => new Response("{}", { status: 201 }));
		const pipe = new GithubPipe({ repo: "o/r", token: "tok", dryRun: false }, fetch, () => {});
		await pipe.pipe(feedbackRecord());
		expect(calls.length).toBe(1);
		const call = calls[0];
		expect(call?.url).toBe("https://api.github.com/repos/o/r/issues");
		expect(call?.init?.method).toBe("POST");
		const headers = call?.init?.headers as Record<string, string>;
		expect(headers.authorization).toBe("Bearer tok");
	});

	test("crash: new fingerprint → search miss then create", async () => {
		const { calls, fetch } = fakeFetcher((call) =>
			call.url.includes("/search/")
				? new Response(JSON.stringify({ items: [] }))
				: new Response("{}", { status: 201 }),
		);
		const pipe = new GithubPipe({ repo: "o/r", token: "tok", dryRun: false }, fetch, () => {});
		await pipe.pipe(crashRecord());
		expect(calls.length).toBe(2);
		expect(calls[0]?.url).toContain("/search/issues");
		expect(calls[1]?.url).toBe("https://api.github.com/repos/o/r/issues");
	});

	test("crash: existing fingerprint → comment, no new issue", async () => {
		const { calls, fetch } = fakeFetcher((call) =>
			call.url.includes("/search/")
				? new Response(JSON.stringify({ items: [{ number: 7 }] }))
				: new Response("{}", { status: 201 }),
		);
		const pipe = new GithubPipe({ repo: "o/r", token: "tok", dryRun: false }, fetch, () => {});
		await pipe.pipe(crashRecord());
		expect(calls.length).toBe(2);
		expect(calls[1]?.url).toBe("https://api.github.com/repos/o/r/issues/7/comments");
	});

	test("pipe failure logs and never throws", async () => {
		const { fetch } = fakeFetcher(() => {
			throw new Error("network down");
		});
		const logged: string[] = [];
		const pipe = new GithubPipe({ repo: "o/r", token: "tok", dryRun: false }, fetch, (m) =>
			logged.push(m),
		);
		await pipe.pipe(feedbackRecord());
		expect(logged.join("\n")).toContain("github pipe failed");
	});
});
