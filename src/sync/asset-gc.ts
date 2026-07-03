/**
 * Asset-B6 — cross-device / offline-peer asset GC: conservative mark-and-sweep
 * over the chunk CAS, driven by client-reported ref-sets (doc-70 §Garbage
 * collection). The node NEVER reclaims on a single device's say-so; a chunk
 * dies only after BOTH gates pass:
 *
 *   1. **Last-seen guard** — a chunk is protected while it appears in the
 *      ref-set of ANY device whose last report is within the retention window
 *      (default 90 days). A device offline-but-within-retention still protects
 *      everything it last reported; only a device silent BEYOND the window
 *      stops counting (the documented data-loss trade-off, per OQ-46). An
 *      account with NO device reporting within the window is skipped entirely
 *      (a dormant account's bytes are a billing decision, not GC's).
 *   2. **Grace window** — an unprotected chunk is first MARKED (reversible):
 *      any re-reference (a report naming it, or a re-PUT) un-marks it. Only a
 *      mark older than the grace window (default 30 days) is actually deleted.
 *
 * Cross-account safety: sweep candidates are the account's OWN attributed
 * chunks minus a GLOBAL protected set (every within-retention ref-set of every
 * account, plus everything owned by skipped accounts) — so an account claiming
 * ownership of a hash another account still references can never delete it.
 * Chunks no account owns are never touched (conservative; a report naming a
 * hash attributes it, which organically backfills pre-B6 uploads).
 *
 * Scheduling is explicit: call `sweep()` (ops / tests), or let `main.ts` run it
 * on `ASSET_GC_SWEEP_INTERVAL_MS`. Reclaimed bytes are metered
 * (`MeterKind.Reclaim`) per account so the billing plane sees storage shrink.
 *
 * **Relay-blind.** Opaque hashes, timestamps, byte counts. Zero crypto imports,
 * no chunk payload parsing — the route path stays blind. See CLAUDE.md.
 */

import { type MeterEvent, MeterKind } from "../metering";
import type { AssetCas } from "./asset-cas";
import type { RefLedger } from "./ref-ledger";

export const DEFAULT_GRACE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
export const DEFAULT_RETENTION_MS = 90 * 24 * 60 * 60 * 1000; // 90 days

/** Bound on distinct device entries per account: a hostile-but-authenticated
 *  client minting fresh device ids must not grow the ledger without bound.
 *  On overflow the stalest device is evicted (least protection lost). */
export const MAX_DEVICES_PER_ACCOUNT = 64;

export type AssetGcOptions = {
	cas: AssetCas;
	ledger: RefLedger;
	/** Mark → delete delay (reversible window). Default 30 days. */
	graceMs?: number;
	/** Device last-seen retention window. Default 90 days. */
	retentionMs?: number;
	now?: () => number;
	/** Reclaimed-bytes metering sink (MeterKind.Reclaim, per account). */
	meter?: (event: MeterEvent) => void;
	/** Sweep-summary log sink (ops visibility; GC is silent client-side). */
	onLog?: (message: string) => void;
};

export type SweepResult = {
	/** Accounts with ledger state examined. */
	accounts: number;
	/** Accounts skipped by the last-seen guard (no within-retention report). */
	skipped: number;
	/** Chunks newly grace-marked this sweep. */
	marked: number;
	/** Marked chunks rescued (re-referenced) this sweep. */
	unmarked: number;
	/** Chunks deleted from the CAS (grace expired, still unreferenced). */
	deleted: number;
	reclaimedBytes: number;
};

export class AssetGc {
	readonly #cas: AssetCas;
	readonly #ledger: RefLedger;
	readonly #graceMs: number;
	readonly #retentionMs: number;
	readonly #now: () => number;
	readonly #meter: ((event: MeterEvent) => void) | null;
	readonly #onLog: ((message: string) => void) | null;

	constructor(opts: AssetGcOptions) {
		this.#cas = opts.cas;
		this.#ledger = opts.ledger;
		this.#graceMs = opts.graceMs ?? DEFAULT_GRACE_MS;
		this.#retentionMs = opts.retentionMs ?? DEFAULT_RETENTION_MS;
		this.#now = opts.now ?? Date.now;
		this.#meter = opts.meter ?? null;
		this.#onLog = opts.onLog ?? null;
	}

	/** A stored chunk is attributed to the uploading account (gated nodes prove
	 *  it; an open node has no account → unattributed, so never swept until a
	 *  report claims it). A re-PUT is a re-reference: it un-marks. */
	async onPut(account: string | null, hash: string, bytes: number): Promise<void> {
		if (!account) return;
		await this.#ledger.update(account, (state) => {
			state.owned[hash] = bytes;
			delete state.marked[hash];
		});
	}

	/** A device's FULL converged ref-set (idempotent replace — the last report
	 *  is that device's view). Every reported hash is un-marked (re-reference
	 *  rescues) and attributed to the account if unowned. */
	async onReport(account: string, device: string, hashes: string[]): Promise<void> {
		const refs = [...new Set(hashes)];
		const now = this.#now();
		await this.#ledger.update(account, (state) => {
			state.devices[device] = { lastReportAt: now, refs };
			for (const hash of refs) {
				delete state.marked[hash];
				if (state.owned[hash] === undefined) state.owned[hash] = 0;
			}
			evictOverflowDevices(state.devices, device);
		});
	}

	/**
	 * One conservative mark-and-sweep pass. Ledger mutations commit (serialized
	 * per account) BEFORE bytes are deleted, so a crash mid-sweep can only leak
	 * an orphan chunk — never leave a live ledger entry for deleted bytes.
	 */
	async sweep(): Promise<SweepResult> {
		const now = this.#now();
		const cutoff = now - this.#retentionMs;
		const result: SweepResult = {
			accounts: 0,
			skipped: 0,
			marked: 0,
			unmarked: 0,
			deleted: 0,
			reclaimedBytes: 0,
		};

		// Pass 1 — the global protected set: every ref reported by a
		// within-retention device of ANY account, plus everything owned by an
		// account the last-seen guard skips.
		const accounts = await this.#ledger.accounts();
		const protectedHashes = new Set<string>();
		const eligible: string[] = [];
		for (const account of accounts) {
			result.accounts += 1;
			const state = await this.#ledger.read(account);
			let hasFreshReport = false;
			for (const device of Object.values(state.devices)) {
				if (device.lastReportAt < cutoff) continue;
				hasFreshReport = true;
				for (const hash of device.refs) protectedHashes.add(hash);
			}
			if (hasFreshReport) {
				eligible.push(account);
			} else {
				result.skipped += 1;
				for (const hash of Object.keys(state.owned)) protectedHashes.add(hash);
			}
		}

		// Pass 2 — per eligible account: un-mark rescued chunks, mark newly
		// unreferenced ones, and commit expired marks as deletions.
		for (const account of eligible) {
			const deletions: Array<{ hash: string; bytes: number }> = [];
			await this.#ledger.update(account, (state) => {
				// Re-check freshness inside the serialized update (reports may have
				// landed since pass 1 — their refs joined `state.devices`).
				const union = new Set(protectedHashes);
				let fresh = false;
				for (const [device, entry] of Object.entries(state.devices)) {
					if (entry.lastReportAt < cutoff) {
						delete state.devices[device]; // beyond retention — prune
						continue;
					}
					fresh = true;
					for (const hash of entry.refs) union.add(hash);
				}
				if (!fresh) return; // guard re-tripped — leave everything untouched

				for (const [hash, markedAt] of Object.entries(state.marked)) {
					if (union.has(hash)) {
						delete state.marked[hash]; // rescued by a re-reference
						result.unmarked += 1;
					} else if (now - markedAt >= this.#graceMs) {
						deletions.push({ hash, bytes: state.owned[hash] ?? 0 });
						delete state.marked[hash];
						delete state.owned[hash];
					}
				}
				for (const hash of Object.keys(state.owned)) {
					if (!union.has(hash) && state.marked[hash] === undefined) {
						state.marked[hash] = now;
						result.marked += 1;
					}
				}
			});

			let reclaimed = 0;
			for (const { hash, bytes } of deletions) {
				// Size for metering: the recorded PUT size, else measure the stored
				// chunk (report-attributed chunks record 0 = unknown).
				const size = bytes > 0 ? bytes : ((await this.#cas.get(hash))?.length ?? 0);
				await this.#cas.delete(hash);
				result.deleted += 1;
				reclaimed += size;
			}
			if (reclaimed > 0 && this.#meter) {
				this.#meter({
					ts: now,
					kind: MeterKind.Reclaim,
					account,
					sub: null,
					plan: null,
					bytes: reclaimed,
				});
			}
			result.reclaimedBytes += reclaimed;
		}

		this.#onLog?.(
			`asset-gc sweep: accounts=${result.accounts} skipped=${result.skipped} marked=${result.marked} unmarked=${result.unmarked} deleted=${result.deleted} reclaimedBytes=${result.reclaimedBytes}`,
		);
		return result;
	}
}

/** Keep the newest `MAX_DEVICES_PER_ACCOUNT` devices; never evict the one that
 *  just reported. */
function evictOverflowDevices(
	devices: Record<string, { lastReportAt: number }>,
	justReported: string,
): void {
	const entries = Object.entries(devices);
	if (entries.length <= MAX_DEVICES_PER_ACCOUNT) return;
	entries.sort((a, b) => a[1].lastReportAt - b[1].lastReportAt);
	let excess = entries.length - MAX_DEVICES_PER_ACCOUNT;
	for (const [device] of entries) {
		if (excess === 0) break;
		if (device === justReported) continue;
		delete devices[device];
		excess -= 1;
	}
}
