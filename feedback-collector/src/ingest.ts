/**
 * Pure ingest pipeline: classify a POST as feedback or crash, validate it
 * against the mirrored contract, and normalise it into a stored record.
 * No IO — the server hands in the parsed body + headers, tests drive it
 * with fixtures.
 *
 * Validation posture: STRICT on the fields the shipped client always sends
 * (so garbage is refused with a 4xx the client treats as terminal), but
 * TOLERANT of unknown extra fields — a newer client adding a field must not
 * bounce off an older collector.
 */

import {
	BODY_MAX_LENGTH,
	CRASH_MESSAGE_MAX_LENGTH,
	CRASH_STACK_MAX_BYTES,
	type CrashWire,
	type FeedbackWire,
	RECENT_LOG_MAX_BYTES,
	TITLE_MAX_LENGTH,
	ULID_PATTERN,
	isCrashKind,
	isFeedbackKind,
	isRendererReason,
	isSensitivity,
} from "./contract";

export type RecordKind = "feedback" | "crash";

export type StoredRecord = {
	readonly recordKind: RecordKind;
	readonly receivedAt: number;
	readonly payload: FeedbackWire | CrashWire;
};

export type IngestResult =
	| { readonly ok: true; readonly record: StoredRecord }
	| { readonly ok: false; readonly reason: string };

function isNonEmptyString(v: unknown, max = 512): v is string {
	return typeof v === "string" && v.length > 0 && v.length <= max;
}

function utf8Bytes(s: string): number {
	return new TextEncoder().encode(s).byteLength;
}

/** Crash POSTs carry the `X-Brainstorm-Crash-Kind` header; the body shape is
 *  the fallback signal so a proxy stripping custom headers doesn't misfile. */
export function classify(
	body: Record<string, unknown>,
	crashKindHeader: string | null,
): RecordKind {
	if (crashKindHeader !== null && crashKindHeader.length > 0) return "crash";
	if (isCrashKind(body.kind)) return "crash";
	if (typeof body.durationSinceBootMs === "number" && typeof body.capturedAt === "number") {
		return "crash";
	}
	return "feedback";
}

export function validateFeedback(
	body: Record<string, unknown>,
):
	| { readonly ok: true; readonly payload: FeedbackWire }
	| { readonly ok: false; readonly reason: string } {
	if (!isFeedbackKind(body.kind)) return { ok: false, reason: "invalid-kind" };
	if (!isNonEmptyString(body.title, TITLE_MAX_LENGTH))
		return { ok: false, reason: "invalid-title" };
	if (!isNonEmptyString(body.body, BODY_MAX_LENGTH)) return { ok: false, reason: "invalid-body" };
	if (!isSensitivity(body.sensitivity)) return { ok: false, reason: "invalid-sensitivity" };
	if (body.contactEmail !== undefined && !isNonEmptyString(body.contactEmail, 320)) {
		return { ok: false, reason: "invalid-contact-email" };
	}
	if (typeof body.includeRecentLog !== "boolean")
		return { ok: false, reason: "invalid-include-log" };
	if (
		body.recentLogExcerpt !== undefined &&
		(typeof body.recentLogExcerpt !== "string" ||
			utf8Bytes(body.recentLogExcerpt) > RECENT_LOG_MAX_BYTES)
	) {
		return { ok: false, reason: "invalid-log-excerpt" };
	}
	if (!isNonEmptyString(body.clientVersion, 64))
		return { ok: false, reason: "invalid-client-version" };
	if (!isNonEmptyString(body.clientPlatform, 64)) return { ok: false, reason: "invalid-platform" };
	if (typeof body.submittedAt !== "number" || !Number.isFinite(body.submittedAt)) {
		return { ok: false, reason: "invalid-submitted-at" };
	}
	if (typeof body.requestId !== "string" || !ULID_PATTERN.test(body.requestId)) {
		return { ok: false, reason: "invalid-request-id" };
	}
	if (typeof body.installationId !== "string" || !ULID_PATTERN.test(body.installationId)) {
		return { ok: false, reason: "invalid-installation-id" };
	}
	const payload: FeedbackWire = {
		kind: body.kind,
		title: body.title,
		body: body.body,
		sensitivity: body.sensitivity,
		...(body.contactEmail !== undefined ? { contactEmail: body.contactEmail as string } : {}),
		includeRecentLog: body.includeRecentLog,
		...(body.recentLogExcerpt !== undefined
			? { recentLogExcerpt: body.recentLogExcerpt as string }
			: {}),
		clientVersion: body.clientVersion,
		clientPlatform: body.clientPlatform,
		submittedAt: body.submittedAt,
		requestId: body.requestId,
		installationId: body.installationId,
	};
	return { ok: true, payload };
}

export function validateCrash(
	body: Record<string, unknown>,
):
	| { readonly ok: true; readonly payload: CrashWire }
	| { readonly ok: false; readonly reason: string } {
	if (!isCrashKind(body.kind)) return { ok: false, reason: "invalid-kind" };
	if (body.rendererReason !== undefined && !isRendererReason(body.rendererReason)) {
		return { ok: false, reason: "invalid-renderer-reason" };
	}
	if (body.exitCode !== undefined && !Number.isInteger(body.exitCode)) {
		return { ok: false, reason: "invalid-exit-code" };
	}
	if (!isNonEmptyString(body.message, CRASH_MESSAGE_MAX_LENGTH)) {
		return { ok: false, reason: "invalid-message" };
	}
	if (
		body.stack !== undefined &&
		(typeof body.stack !== "string" || utf8Bytes(body.stack) > CRASH_STACK_MAX_BYTES)
	) {
		return { ok: false, reason: "invalid-stack" };
	}
	if (body.appId !== undefined && !isNonEmptyString(body.appId, 256)) {
		return { ok: false, reason: "invalid-app-id" };
	}
	if (body.routePath !== undefined && !isNonEmptyString(body.routePath, 1024)) {
		return { ok: false, reason: "invalid-route-path" };
	}
	if (
		typeof body.recentLogExcerpt !== "string" ||
		utf8Bytes(body.recentLogExcerpt) > RECENT_LOG_MAX_BYTES
	) {
		return { ok: false, reason: "invalid-log-excerpt" };
	}
	if (!isNonEmptyString(body.clientVersion, 64))
		return { ok: false, reason: "invalid-client-version" };
	if (!isNonEmptyString(body.clientPlatform, 64)) return { ok: false, reason: "invalid-platform" };
	if (typeof body.capturedAt !== "number" || !Number.isFinite(body.capturedAt)) {
		return { ok: false, reason: "invalid-captured-at" };
	}
	if (
		body.submittedAt !== undefined &&
		(typeof body.submittedAt !== "number" || !Number.isFinite(body.submittedAt))
	) {
		return { ok: false, reason: "invalid-submitted-at" };
	}
	if (typeof body.requestId !== "string" || !ULID_PATTERN.test(body.requestId)) {
		return { ok: false, reason: "invalid-request-id" };
	}
	if (typeof body.installationId !== "string" || !ULID_PATTERN.test(body.installationId)) {
		return { ok: false, reason: "invalid-installation-id" };
	}
	if (typeof body.durationSinceBootMs !== "number" || body.durationSinceBootMs < 0) {
		return { ok: false, reason: "invalid-duration" };
	}
	const payload: CrashWire = {
		kind: body.kind,
		...(isRendererReason(body.rendererReason) ? { rendererReason: body.rendererReason } : {}),
		...(body.exitCode !== undefined ? { exitCode: body.exitCode as number } : {}),
		message: body.message,
		...(body.stack !== undefined ? { stack: body.stack as string } : {}),
		...(body.appId !== undefined ? { appId: body.appId as string } : {}),
		...(body.routePath !== undefined ? { routePath: body.routePath as string } : {}),
		recentLogExcerpt: body.recentLogExcerpt,
		clientVersion: body.clientVersion,
		clientPlatform: body.clientPlatform,
		capturedAt: body.capturedAt,
		...(body.submittedAt !== undefined ? { submittedAt: body.submittedAt as number } : {}),
		requestId: body.requestId,
		installationId: body.installationId,
		durationSinceBootMs: body.durationSinceBootMs,
	};
	return { ok: true, payload };
}

export function ingest(
	body: unknown,
	crashKindHeader: string | null,
	now: () => number,
): IngestResult {
	if (body === null || typeof body !== "object" || Array.isArray(body)) {
		return { ok: false, reason: "not-an-object" };
	}
	const record = body as Record<string, unknown>;
	const recordKind = classify(record, crashKindHeader);
	const validated = recordKind === "crash" ? validateCrash(record) : validateFeedback(record);
	if (!validated.ok) return { ok: false, reason: `${recordKind}:${validated.reason}` };
	return {
		ok: true,
		record: { recordKind, receivedAt: now(), payload: validated.payload },
	};
}
