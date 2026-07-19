/**
 * Mirrored wire contract for the Brainstorm in-app feedback + crash clients.
 *
 * The product's `packages/shell/src/main/feedback/{feedback,crash}-payload.ts`
 * is the canonical source; this file mirrors only what the collector needs to
 * accept — the same "shared contract, never shared code" seam as `src/wire.ts`.
 * Payloads arrive ALREADY REDACTED by the client (vault paths, home dirs,
 * credential keys, emails); the collector never sees raw vault content.
 *
 * Client response semantics (fixed by the shipped client):
 *   2xx → accepted (response body ignored) · 4xx → dropped permanently ·
 *   5xx / transport → retried. Rate-limit refusals are 429 (a 4xx) on purpose:
 *   a crash-looping installation should shed its excess, not queue it.
 */

export const FEEDBACK_KINDS = ["bug", "idea", "question", "other"] as const;
export type FeedbackKind = (typeof FEEDBACK_KINDS)[number];

export const FEEDBACK_SENSITIVITIES = ["anonymous", "identity-voluntary"] as const;
export type FeedbackSensitivity = (typeof FEEDBACK_SENSITIVITIES)[number];

export const CRASH_KINDS = [
	"uncaught-exception",
	"unhandled-rejection",
	"renderer-process-gone",
	"renderer-crashed",
	"renderer-killed",
	"unresponsive-renderer",
	"main-process-gone",
] as const;
export type CrashKind = (typeof CRASH_KINDS)[number];

export const RENDERER_REASONS = [
	"crashed",
	"killed",
	"oom",
	"launch-failed",
	"integrity-failure",
] as const;
export type RendererReason = (typeof RENDERER_REASONS)[number];

/** Bounds — byte-identical to the client's validator so nothing the shipped
 *  client can emit is ever refused for size. */
export const TITLE_MAX_LENGTH = 200;
export const BODY_MAX_LENGTH = 10_000;
export const RECENT_LOG_MAX_BYTES = 64 * 1024;
export const CRASH_MESSAGE_MAX_LENGTH = 1024;
export const CRASH_STACK_MAX_BYTES = 32 * 1024;
/** ULID as minted by the client (`newRequestId`): 26 Crockford-base32 chars. */
export const ULID_PATTERN = /^[0-9A-HJKMNP-TV-Z]{26}$/;

/** Header stamped on every client POST. */
export const INSTALLATION_ID_HEADER = "x-brainstorm-installation-id";
/** Header present ONLY on crash POSTs — the primary classification signal. */
export const CRASH_KIND_HEADER = "x-brainstorm-crash-kind";

/** Feedback wire body = redacted FeedbackPayload + injected installationId. */
export type FeedbackWire = {
	readonly kind: FeedbackKind;
	readonly title: string;
	readonly body: string;
	readonly sensitivity: FeedbackSensitivity;
	readonly contactEmail?: string;
	readonly includeRecentLog: boolean;
	readonly recentLogExcerpt?: string;
	readonly clientVersion: string;
	readonly clientPlatform: string;
	readonly submittedAt: number;
	readonly requestId: string;
	readonly installationId: string;
};

/** Crash wire body = one redacted CrashPayload (always anonymous). */
export type CrashWire = {
	readonly kind: CrashKind;
	readonly rendererReason?: RendererReason;
	readonly exitCode?: number;
	readonly message: string;
	readonly stack?: string;
	readonly appId?: string;
	readonly routePath?: string;
	readonly recentLogExcerpt: string;
	readonly clientVersion: string;
	readonly clientPlatform: string;
	readonly capturedAt: number;
	readonly submittedAt?: number;
	readonly requestId: string;
	readonly installationId: string;
	readonly durationSinceBootMs: number;
};

export function isFeedbackKind(value: unknown): value is FeedbackKind {
	return typeof value === "string" && (FEEDBACK_KINDS as readonly string[]).includes(value);
}

export function isCrashKind(value: unknown): value is CrashKind {
	return typeof value === "string" && (CRASH_KINDS as readonly string[]).includes(value);
}

export function isRendererReason(value: unknown): value is RendererReason {
	return typeof value === "string" && (RENDERER_REASONS as readonly string[]).includes(value);
}

export function isSensitivity(value: unknown): value is FeedbackSensitivity {
	return typeof value === "string" && (FEEDBACK_SENSITIVITIES as readonly string[]).includes(value);
}
