/**
 * Collector core — a plain `(request, clientIp) → Response` handler,
 * socket-free so the whole request matrix is testable without a port
 * (mirrors `src/server.ts`'s testable-core pattern).
 *
 * Routes: `GET /healthz` → 200; `POST` on any other path → ingest. The
 * client POSTs to whatever URL was configured verbatim, so the collector
 * accepts POST on any path rather than pinning one.
 *
 * Refusals follow the shipped client's semantics (see contract.ts): 400/413/
 * 429 are terminal drops for the client, 500 asks it to retry.
 */

import { KeyedRateLimiter } from "../../src/limits";
import { CRASH_KIND_HEADER, INSTALLATION_ID_HEADER } from "./contract";
import type { GithubPipe } from "./github";
import { ingest } from "./ingest";
import type { JsonlStore } from "./store";

/** Whole-request body cap: max legitimate payload is ~100 KiB (64 KiB log +
 *  32 KiB stack + slack), so 256 KiB refuses abuse without ever refusing a
 *  real client. */
export const MAX_BODY_BYTES = 256 * 1024;

export type CollectorLimitsConfig = {
	/** Feedback POSTs per installation (and per IP): sustained/sec + burst. */
	readonly feedbackPerSec: number;
	readonly feedbackBurst: number;
	/** Crash POSTs per installation (and per IP): sustained/sec + burst. */
	readonly crashPerSec: number;
	readonly crashBurst: number;
	readonly disabled: boolean;
};

/** Feedback is human-driven (10/min); crashes are machine-driven but queued
 *  client-side (60/h) — a crash-looping install sheds excess at the edge. */
export const DEFAULT_COLLECTOR_LIMITS: CollectorLimitsConfig = {
	feedbackPerSec: 10 / 60,
	feedbackBurst: 20,
	crashPerSec: 60 / 3600,
	crashBurst: 30,
	disabled: false,
};

export type CollectorDeps = {
	readonly store: JsonlStore;
	readonly pipe: GithubPipe;
	readonly limits?: CollectorLimitsConfig;
	readonly now?: () => number;
	readonly log?: (message: string) => void;
};

export type CollectorStats = {
	accepted: number;
	rejected: number;
	rateLimited: number;
};

export type Collector = {
	handle(request: Request, clientIp: string): Promise<Response>;
	readonly stats: CollectorStats;
};

function json(status: number, body: Record<string, unknown>): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json" },
	});
}

export function makeCollector(deps: CollectorDeps): Collector {
	const now = deps.now ?? Date.now;
	const log = deps.log ?? console.error;
	const limits = deps.limits ?? DEFAULT_COLLECTOR_LIMITS;
	const feedbackLimiter = new KeyedRateLimiter(limits.feedbackPerSec, limits.feedbackBurst, now);
	const crashLimiter = new KeyedRateLimiter(limits.crashPerSec, limits.crashBurst, now);
	const stats: CollectorStats = { accepted: 0, rejected: 0, rateLimited: 0 };

	async function handle(request: Request, clientIp: string): Promise<Response> {
		const url = new URL(request.url);
		if (url.pathname === "/healthz") return new Response("ok", { status: 200 });
		if (request.method !== "POST") return json(405, { error: "method-not-allowed" });

		const raw = await request.arrayBuffer();
		if (raw.byteLength > MAX_BODY_BYTES) {
			stats.rejected++;
			return json(413, { error: "body-too-large" });
		}
		let body: unknown;
		try {
			body = JSON.parse(new TextDecoder().decode(raw));
		} catch {
			stats.rejected++;
			return json(400, { error: "not-json" });
		}

		const crashKindHeader = request.headers.get(CRASH_KIND_HEADER);
		const result = ingest(body, crashKindHeader, now);
		if (!result.ok) {
			stats.rejected++;
			return json(400, { error: result.reason });
		}

		if (!limits.disabled) {
			const limiter = result.record.recordKind === "crash" ? crashLimiter : feedbackLimiter;
			const installationId =
				request.headers.get(INSTALLATION_ID_HEADER) ?? result.record.payload.installationId;
			if (!limiter.allow(`ip:${clientIp}`) || !limiter.allow(`inst:${installationId}`)) {
				stats.rateLimited++;
				return json(429, { error: "rate-limited" });
			}
		}

		try {
			await deps.store.append(result.record);
		} catch (error) {
			log(`[feedback-collector] store append failed: ${String(error)}`);
			return json(500, { error: "storage-failure" });
		}
		stats.accepted++;
		// Fire-and-forget: the 200 never waits on GitHub; pipe() catches its own.
		void deps.pipe.pipe(result.record);
		return json(200, { ok: true });
	}

	return { handle, stats };
}
