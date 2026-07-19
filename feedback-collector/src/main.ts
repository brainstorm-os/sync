/**
 * Feedback-collector entrypoint — `Bun.serve` around the testable core.
 *
 * A SEPARATE service from the relay node (`src/main.ts`): this plane accepts
 * PLAINTEXT (client-redacted) feedback + crash reports, so it deliberately
 * does not share a process, port, or deploy unit with the relay-blind
 * ciphertext node. See feedback-collector/README.md.
 *
 * Env:
 *   FEEDBACK_PORT            listen port (default 7790)
 *   FEEDBACK_DATA_DIR        JSONL retention dir (default ./feedback-data)
 *   FEEDBACK_GITHUB_REPO     owner/name of the private inbox repo ("" = JSONL only)
 *   FEEDBACK_GITHUB_TOKEN    fine-grained PAT, issues:write on that repo
 *   FEEDBACK_GITHUB_DRY_RUN  "1" = log would-be issues instead of POSTing
 *   FEEDBACK_LIMITS_DISABLED "1" = no rate limiting (tests/dev only)
 */

import { GithubPipe } from "./github";
import { DEFAULT_COLLECTOR_LIMITS, makeCollector } from "./server";
import { JsonlStore } from "./store";

const port = Number(process.env.FEEDBACK_PORT ?? 7790);
const dataDir = process.env.FEEDBACK_DATA_DIR ?? "./feedback-data";

const pipe = new GithubPipe({
	repo: process.env.FEEDBACK_GITHUB_REPO ?? "",
	token: process.env.FEEDBACK_GITHUB_TOKEN ?? "",
	dryRun: process.env.FEEDBACK_GITHUB_DRY_RUN === "1",
});

const collector = makeCollector({
	store: new JsonlStore(dataDir),
	pipe,
	limits: {
		...DEFAULT_COLLECTOR_LIMITS,
		disabled: process.env.FEEDBACK_LIMITS_DISABLED === "1",
	},
});

const server = Bun.serve({
	port,
	fetch(request, srv) {
		const ip = srv.requestIP(request)?.address ?? "unknown";
		return collector.handle(request, ip);
	},
});

console.log(
	`[feedback-collector] listening on :${server.port} — data=${dataDir} github=${
		pipe.enabled ? (process.env.FEEDBACK_GITHUB_DRY_RUN === "1" ? "dry-run" : "on") : "off"
	}`,
);

function shutdown(): void {
	console.log(
		`[feedback-collector] shutting down — accepted=${collector.stats.accepted} rejected=${collector.stats.rejected} rate-limited=${collector.stats.rateLimited}`,
	);
	server.stop();
	process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
