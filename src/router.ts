/**
 * Routing table — `(entityId → Set<connId>)` subscriptions + blind fan-out.
 *
 * Pure data-flow class. On `route(connId, frame)` it peeks the routing header,
 * fans the untouched frame bytes out to every OTHER subscriber for that entity,
 * and appends one audit entry per delivery.
 *
 * **No echo.** A subscriber that's also the sender does NOT receive its own
 * frame back. Per-connection ids so a single device with two sockets gets
 * fan-out across both.
 *
 * **Malformed-header tolerance.** A frame whose header fails strict-shape
 * validation is dropped + counted; we do NOT close the connection (a malformed-
 * frame-as-DoS would be worse — the recipient is the last line of defense).
 *
 * **Relay-blind.** Zero crypto imports; never decodes the ciphertext body. See
 * CLAUDE.md.
 */

import type { AuditLog } from "./audit-log";
import { type RoutingHeader, peekRoutingHeader } from "./wire";

export type RouteResult = {
	delivered: number;
	dropped: 0 | 1;
	header: RoutingHeader | null;
	/** The CANONICAL routing key the frame was fanned out (and should be
	 *  persisted/catalogued) under — `header.entityId` resolved through any
	 *  live rotation alias (10.11). Null when the header was malformed. */
	routingKey: string | null;
};

/** 10.11 — a rotation alias `from → to`, live until `expiresAt` (the
 *  dual-token grace window). Opaque strings only — relay-blind. */
type RotationAlias = { to: string; expiresAt: number };

/** Alias chains are followed at most this many hops (a rotation of a rotation
 *  inside one grace window); a longer chain or a cycle stops resolving. */
const MAX_ALIAS_HOPS = 8;

export class FrameRouter {
	readonly #audit: AuditLog;
	readonly #connectionsByEntity = new Map<string, Set<string>>();
	readonly #entitiesByConnection = new Map<string, Set<string>>();
	readonly #aliases = new Map<string, RotationAlias>();
	readonly #now: () => number;
	#malformedDropped = 0;

	constructor(audit: AuditLog, opts: { now?: () => number } = {}) {
		this.#audit = audit;
		this.#now = opts.now ?? Date.now;
	}

	/**
	 * 10.11 routing-token rotation — canonicalize a routing key through any
	 * unexpired rotation aliases. Expired aliases are lazily dropped. During the
	 * grace window a subscribe / frame / backfill under the OLD token lands on
	 * the NEW token's channel; after expiry the old token is an unknown key.
	 */
	resolveKey(key: string): string {
		let current = key;
		for (let hop = 0; hop < MAX_ALIAS_HOPS; hop++) {
			const alias = this.#aliases.get(current);
			if (!alias) return current;
			if (alias.expiresAt <= this.#now()) {
				this.#aliases.delete(current);
				return current;
			}
			if (alias.to === key) return current; // cycle guard
			current = alias.to;
		}
		return current;
	}

	/**
	 * 10.11 — apply a routing-token rotation: every current subscriber of
	 * `from` is moved onto `to` (in-flight peers keep receiving frames without
	 * a re-subscribe), and `from → to` is aliased until `expiresAt` so late
	 * subscribes / frames / backfills under the old token still land on the new
	 * channel during the grace window.
	 */
	applyRotation(from: string, to: string, expiresAt: number): void {
		if (from === to) return;
		const fromSet = this.#connectionsByEntity.get(from);
		if (fromSet) {
			for (const connId of [...fromSet]) {
				this.unsubscribe(connId, from);
				this.subscribe(connId, to);
			}
		}
		this.#aliases.set(from, { to, expiresAt });
	}

	subscribe(connId: string, rawEntityId: string): void {
		const entityId = this.resolveKey(rawEntityId);
		let set = this.#connectionsByEntity.get(entityId);
		if (!set) {
			set = new Set<string>();
			this.#connectionsByEntity.set(entityId, set);
		}
		set.add(connId);
		let entitySet = this.#entitiesByConnection.get(connId);
		if (!entitySet) {
			entitySet = new Set<string>();
			this.#entitiesByConnection.set(connId, entitySet);
		}
		entitySet.add(entityId);
	}

	unsubscribe(connId: string, rawEntityId: string): void {
		const entityId = this.resolveKey(rawEntityId);
		const set = this.#connectionsByEntity.get(entityId);
		if (set) {
			set.delete(connId);
			if (set.size === 0) this.#connectionsByEntity.delete(entityId);
		}
		const entitySet = this.#entitiesByConnection.get(connId);
		if (entitySet) {
			entitySet.delete(entityId);
			if (entitySet.size === 0) this.#entitiesByConnection.delete(connId);
		}
	}

	dropConnection(connId: string): void {
		const entities = this.#entitiesByConnection.get(connId);
		if (!entities) return;
		for (const entityId of entities) {
			const set = this.#connectionsByEntity.get(entityId);
			if (set) {
				set.delete(connId);
				if (set.size === 0) this.#connectionsByEntity.delete(entityId);
			}
		}
		this.#entitiesByConnection.delete(connId);
	}

	/** Subscribers for `entityId` excluding `excludeConnId` (the sender). */
	subscribersFor(entityId: string, excludeConnId: string): string[] {
		const set = this.#connectionsByEntity.get(entityId);
		if (!set) return [];
		const out: string[] = [];
		for (const id of set) {
			if (id !== excludeConnId) out.push(id);
		}
		return out;
	}

	/**
	 * Peek the routing header, fan-out the (untouched) frame bytes to every
	 * OTHER subscriber, append one audit entry per delivery. The caller does the
	 * socket-write — the router is pure logic and returns the recipient count.
	 *
	 * `admit` (SYNC-4b) is an optional pre-fan-out guard on the parsed header
	 * (e.g. "the sender matches the connection's proven account", "the account
	 * is within its frame quota"). A `false` drops the frame WITHOUT fan-out,
	 * persistence, or audit — reported as `dropped: 1` so the caller skips its
	 * own persist/meter/catalog side-effects, exactly like a malformed frame.
	 */
	route(
		fromConnId: string,
		frame: Uint8Array,
		send: (toConnId: string, frame: Uint8Array) => void,
		admit?: (header: RoutingHeader) => boolean,
	): RouteResult {
		let header: RoutingHeader;
		try {
			const peeked = peekRoutingHeader(frame);
			header = peeked.header;
		} catch {
			this.#malformedDropped += 1;
			return { delivered: 0, dropped: 1, header: null, routingKey: null };
		}
		if (admit && !admit(header)) {
			return { delivered: 0, dropped: 1, header, routingKey: null };
		}
		// 10.11 — a frame emitted under a rotated-away token during the grace
		// window fans out (and is persisted by the caller) under the NEW token.
		const routingKey = this.resolveKey(header.entityId);
		const recipients = this.subscribersFor(routingKey, fromConnId);
		let delivered = 0;
		for (const toConnId of recipients) {
			try {
				send(toConnId, frame);
				this.#audit.record({
					fromConnId,
					toConnId,
					entityId: routingKey,
					kind: header.kind,
					bytes: frame.length,
				});
				delivered += 1;
			} catch {
				// A failed write must not block fan-out to siblings.
			}
		}
		return { delivered, dropped: 0, header, routingKey };
	}

	malformedDropped(): number {
		return this.#malformedDropped;
	}

	subscriberCount(entityId: string): number {
		return this.#connectionsByEntity.get(entityId)?.size ?? 0;
	}

	connectionEntities(connId: string): readonly string[] {
		const set = this.#entitiesByConnection.get(connId);
		return set ? [...set] : [];
	}
}
