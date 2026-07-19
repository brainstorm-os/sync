/**
 * GitHub issue piping — turns accepted records into triage-able issues in a
 * private inbox repo. Best-effort and asynchronous: the ingest 200 never
 * waits on GitHub, and a failure here only logs (the JSONL store already
 * holds the record).
 *
 *   feedback → one issue per item, labeled `feedback` + the kind.
 *   crash    → deduplicated by a stack fingerprint: an existing open/closed
 *              issue carrying `fp-<hash>` in its title gets a comment
 *              (occurrence++), otherwise a new `crash`-labeled issue.
 *
 * Zero deps: global fetch + WebCrypto SHA-256. `fetcher` is injected for
 * tests. Dry-run mode logs the would-be issue instead of calling out —
 * lets the whole loop be proven without a token.
 */

import type { CrashWire, FeedbackWire } from "./contract";
import type { StoredRecord } from "./ingest";

export type GithubPipeConfig = {
	/** `owner/name`. Empty disables piping entirely (JSONL-only mode). */
	readonly repo: string;
	/** Fine-grained PAT with issues:write on the inbox repo. */
	readonly token: string;
	/** Log the formatted issue instead of POSTing. */
	readonly dryRun: boolean;
};

export type Fetcher = (url: string, init?: RequestInit) => Promise<Response>;

const API = "https://api.github.com";
const FINGERPRINT_STACK_FRAMES = 5;

export async function crashFingerprint(payload: CrashWire): Promise<string> {
	// Top frames only: deeper frames churn across versions; message excluded
	// (it can embed volatile values even after redaction).
	const stackHead = (payload.stack ?? payload.message)
		.split("\n")
		.slice(0, FINGERPRINT_STACK_FRAMES)
		.map((line) => line.trim())
		.join("\n");
	const bytes = new TextEncoder().encode(`${payload.kind}\n${stackHead}`);
	const digest = await crypto.subtle.digest("SHA-256", bytes);
	return Array.from(new Uint8Array(digest).slice(0, 6))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

function detailsBlock(summary: string, text: string): string {
	return `<details><summary>${summary}</summary>\n\n\`\`\`\n${text}\n\`\`\`\n\n</details>`;
}

export function formatFeedbackIssue(payload: FeedbackWire): {
	title: string;
	body: string;
	labels: string[];
} {
	const meta = [
		`| version | \`${payload.clientVersion}\` |`,
		`| platform | \`${payload.clientPlatform}\` |`,
		`| sensitivity | ${payload.sensitivity} |`,
		...(payload.contactEmail !== undefined ? [`| contact | ${payload.contactEmail} |`] : []),
		`| submitted | ${new Date(payload.submittedAt).toISOString()} |`,
		`| request | \`${payload.requestId}\` |`,
		`| installation | \`${payload.installationId}\` |`,
	].join("\n");
	const excerpt =
		payload.recentLogExcerpt !== undefined && payload.recentLogExcerpt.length > 0
			? `\n\n${detailsBlock("Recent log excerpt", payload.recentLogExcerpt)}`
			: "";
	return {
		title: `[${payload.kind}] ${payload.title}`,
		body: `| | |\n|---|---|\n${meta}\n\n---\n\n${payload.body}${excerpt}`,
		labels: ["feedback", payload.kind],
	};
}

export function formatCrashIssue(
	payload: CrashWire,
	fingerprint: string,
): { title: string; body: string; labels: string[] } {
	const headline = payload.message.split("\n")[0]?.slice(0, 80) ?? payload.kind;
	const meta = [
		`| kind | \`${payload.kind}\` |`,
		...(payload.rendererReason !== undefined
			? [`| renderer reason | \`${payload.rendererReason}\` |`]
			: []),
		...(payload.appId !== undefined ? [`| app | \`${payload.appId}\` |`] : []),
		`| version | \`${payload.clientVersion}\` |`,
		`| platform | \`${payload.clientPlatform}\` |`,
		`| captured | ${new Date(payload.capturedAt).toISOString()} |`,
		`| uptime | ${Math.round(payload.durationSinceBootMs / 1000)}s |`,
		`| installation | \`${payload.installationId}\` |`,
	].join("\n");
	const stack = payload.stack !== undefined ? `\n\n${detailsBlock("Stack", payload.stack)}` : "";
	const excerpt =
		payload.recentLogExcerpt.length > 0
			? `\n\n${detailsBlock("Recent log excerpt", payload.recentLogExcerpt)}`
			: "";
	return {
		title: `[crash] ${payload.kind}: ${headline} (fp-${fingerprint})`,
		body: `| | |\n|---|---|\n${meta}\n\n**\`${payload.message}\`**${stack}${excerpt}`,
		labels: ["crash"],
	};
}

export function formatCrashOccurrenceComment(payload: CrashWire): string {
	return `Occurred again — version \`${payload.clientVersion}\`, platform \`${payload.clientPlatform}\`, captured ${new Date(payload.capturedAt).toISOString()}, installation \`${payload.installationId}\`.`;
}

export class GithubPipe {
	readonly #config: GithubPipeConfig;
	readonly #fetch: Fetcher;
	readonly #log: (message: string) => void;

	constructor(config: GithubPipeConfig, fetcher: Fetcher = fetch, log = console.error) {
		this.#config = config;
		this.#fetch = fetcher;
		this.#log = log;
	}

	get enabled(): boolean {
		return this.#config.repo.length > 0 && (this.#config.dryRun || this.#config.token.length > 0);
	}

	async pipe(record: StoredRecord): Promise<void> {
		if (!this.enabled) return;
		try {
			if (record.recordKind === "feedback") {
				await this.#pipeFeedback(record.payload as FeedbackWire);
			} else {
				await this.#pipeCrash(record.payload as CrashWire);
			}
		} catch (error) {
			this.#log(`[feedback-collector] github pipe failed: ${String(error)}`);
		}
	}

	async #pipeFeedback(payload: FeedbackWire): Promise<void> {
		await this.#createIssue(formatFeedbackIssue(payload));
	}

	async #pipeCrash(payload: CrashWire): Promise<void> {
		const fingerprint = await crashFingerprint(payload);
		const existing = await this.#findIssueByFingerprint(fingerprint);
		if (existing !== null) {
			await this.#comment(existing, formatCrashOccurrenceComment(payload));
			return;
		}
		await this.#createIssue(formatCrashIssue(payload, fingerprint));
	}

	async #findIssueByFingerprint(fingerprint: string): Promise<number | null> {
		if (this.#config.dryRun) return null;
		const q = encodeURIComponent(`repo:${this.#config.repo} "fp-${fingerprint}" in:title`);
		const res = await this.#request(`${API}/search/issues?q=${q}&per_page=1`);
		if (!res.ok) return null;
		const data = (await res.json()) as { items?: { number: number }[] };
		return data.items?.[0]?.number ?? null;
	}

	async #createIssue(issue: { title: string; body: string; labels: string[] }): Promise<void> {
		if (this.#config.dryRun) {
			this.#log(`[feedback-collector] DRY-RUN issue → ${issue.title}\n${issue.body}`);
			return;
		}
		const res = await this.#request(`${API}/repos/${this.#config.repo}/issues`, {
			method: "POST",
			body: JSON.stringify(issue),
		});
		if (!res.ok) throw new Error(`create issue: HTTP ${res.status}`);
	}

	async #comment(issueNumber: number, body: string): Promise<void> {
		if (this.#config.dryRun) {
			this.#log(`[feedback-collector] DRY-RUN comment on #${issueNumber} → ${body}`);
			return;
		}
		const res = await this.#request(
			`${API}/repos/${this.#config.repo}/issues/${issueNumber}/comments`,
			{ method: "POST", body: JSON.stringify({ body }) },
		);
		if (!res.ok) throw new Error(`comment: HTTP ${res.status}`);
	}

	#request(url: string, init?: RequestInit): Promise<Response> {
		return this.#fetch(url, {
			...init,
			headers: {
				authorization: `Bearer ${this.#config.token}`,
				accept: "application/vnd.github+json",
				"x-github-api-version": "2022-11-28",
				"content-type": "application/json",
				"user-agent": "brainstorm-feedback-collector",
			},
		});
	}
}
