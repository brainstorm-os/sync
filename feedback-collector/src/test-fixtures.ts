/** Shared valid-wire fixtures for the collector test suites. */

const ULID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

export function validFeedback(): Record<string, unknown> {
	return {
		kind: "bug",
		title: "The sidebar collapses on rename",
		body: "Renaming a note while the sidebar is filtered collapses the tree.",
		sensitivity: "anonymous",
		includeRecentLog: false,
		clientVersion: "0.6.0",
		clientPlatform: "darwin-arm64",
		submittedAt: 1_752_900_000_000,
		requestId: ULID,
		installationId: ULID,
	};
}

export function validCrash(): Record<string, unknown> {
	return {
		kind: "renderer-crashed",
		rendererReason: "crashed",
		message: "Cannot read properties of undefined (reading 'uid')",
		stack: "TypeError: Cannot read properties of undefined\n    at <vault>/apps/x.js:1:1",
		appId: "io.brainstorm.mailbox",
		recentLogExcerpt: "[app] boot ok",
		clientVersion: "0.6.0",
		clientPlatform: "darwin-arm64",
		capturedAt: 1_752_900_000_000,
		requestId: ULID,
		installationId: ULID,
		durationSinceBootMs: 5_000,
	};
}

export { ULID as FIXTURE_ULID };
