/**
 * Asset-B6 — the GC ref ledger: per-account bookkeeping the conservative
 * mark-and-sweep runs against. The node is relay-blind (it cannot read
 * manifests or entities), so "which chunks are still referenced" comes from
 * **client-reported ref-sets**: each authenticated device periodically posts
 * the FULL set of chunk hashes its converged vault state still references
 * (`AssetWireKind.Refs`). Hashes are the same opaque ciphertext-hash addresses
 * the CAS already keys — a report leaks nothing the node doesn't already hold.
 *
 * Per account the ledger tracks:
 *   - `devices`  — per-device last-report time + the reported ref-set (full-set
 *                  replace; the last report is the device's converged view).
 *   - `owned`    — hashes attributed to the account (recorded on gated PUT, and
 *                  backfilled by reports: a referenced hash becomes owned so
 *                  pre-B6 uploads join the GC lifecycle). Value = chunk bytes
 *                  (0 = size unknown, i.e. attribution came from a report).
 *   - `marked`   — grace-marked hashes (`hash → markedAt ms`): the reversible
 *                  "condemned, not deleted" state between the two GC gates.
 *
 * **Relay-blind.** Opaque hash strings + timestamps only; zero crypto imports.
 * The interface is storage-agnostic so the backend rides the same SYNC-3
 * provider choice as the CAS (memory here, file / object next to it).
 */

export type DeviceRefs = {
	/** Wall-clock ms of the device's latest full-set report (its last-seen). */
	lastReportAt: number;
	/** The full ref-set of that report (deduped, 64-hex addresses). */
	refs: string[];
};

export type AccountGcState = {
	devices: Record<string, DeviceRefs>;
	/** hash → stored chunk bytes (0 = unknown; attributed via a report). */
	owned: Record<string, number>;
	/** hash → grace-mark timestamp (ms). */
	marked: Record<string, number>;
};

export function emptyGcState(): AccountGcState {
	return { devices: {}, owned: {}, marked: {} };
}

export interface RefLedger {
	/** Every account with ledger state, in stable order. */
	accounts(): Promise<string[]>;
	/** The account's state (an empty default when absent). */
	read(account: string): Promise<AccountGcState>;
	/** Serialized read-modify-write of one account's state. */
	update(account: string, mutate: (state: AccountGcState) => void): Promise<void>;
}

const HASH_RE = /^[0-9a-f]{64}$/;

/** Re-shape untrusted persisted JSON into a valid state (default-on-corrupt —
 *  a malformed field degrades to empty, which only makes GC MORE conservative:
 *  lost reports block sweep, lost marks restart grace). */
export function sanitizeGcState(raw: unknown): AccountGcState {
	const state = emptyGcState();
	if (!raw || typeof raw !== "object") return state;
	const v = raw as Record<string, unknown>;
	if (v.devices && typeof v.devices === "object") {
		for (const [device, entry] of Object.entries(v.devices as Record<string, unknown>)) {
			if (!entry || typeof entry !== "object") continue;
			const e = entry as Record<string, unknown>;
			if (typeof e.lastReportAt !== "number" || !Number.isFinite(e.lastReportAt)) continue;
			if (!Array.isArray(e.refs)) continue;
			state.devices[device] = {
				lastReportAt: e.lastReportAt,
				refs: e.refs.filter((h): h is string => typeof h === "string" && HASH_RE.test(h)),
			};
		}
	}
	if (v.owned && typeof v.owned === "object") {
		for (const [hash, bytes] of Object.entries(v.owned as Record<string, unknown>)) {
			if (HASH_RE.test(hash) && typeof bytes === "number" && Number.isFinite(bytes) && bytes >= 0) {
				state.owned[hash] = bytes;
			}
		}
	}
	if (v.marked && typeof v.marked === "object") {
		for (const [hash, at] of Object.entries(v.marked as Record<string, unknown>)) {
			if (HASH_RE.test(hash) && typeof at === "number" && Number.isFinite(at)) {
				state.marked[hash] = at;
			}
		}
	}
	return state;
}

/** In-memory ledger — tests + ephemeral runs. */
export class MemoryRefLedger implements RefLedger {
	readonly #states = new Map<string, AccountGcState>();

	async accounts(): Promise<string[]> {
		return [...this.#states.keys()];
	}

	async read(account: string): Promise<AccountGcState> {
		const state = this.#states.get(account);
		return state ? structuredClone(state) : emptyGcState();
	}

	async update(account: string, mutate: (state: AccountGcState) => void): Promise<void> {
		const state = this.#states.get(account) ?? emptyGcState();
		mutate(state);
		this.#states.set(account, state);
	}
}
