# brainstorm-sync

The **zero-knowledge sync plane** for Brainstorm — a relay-blind sync node.

It forwards (and, from SYNC-2, durably stores) the **encrypted** CRDT traffic
between a user's devices and collaborators. It holds **no key** and can never
decrypt vault content: it reads only the plaintext routing header (which entity,
who sent it) to fan a frame out to the other subscribers, and forwards the
opaque ciphertext body untouched.

This is a **separate deploy boundary** from the Electron client (`../app`)
and the commercial control plane (`../cloud`). See [CLAUDE.md](./CLAUDE.md)
for the invariants and the three-plane model.

> A forward-only relay keeps nothing — lose your local data and there's no
> restore. **SYNC-1** (this) is the live, online forwarding node; **SYNC-2** adds
> the durable encrypted-snapshot store that makes backup/restore real (the
> any-sync model). Roadmap in `../docs/implementation-plan.md`
> §"Durable sync node".

## Run

```sh
bun install        # devDeps only (biome, tsc); the node has no runtime deps
bun run start      # listen on PORT (default 7780)
bun test           # core behavior + ciphertext-only audit invariant
```

Clients connect over WebSocket and speak the binary wire protocol:

- `0x00` + JSON control: `{op:"subscribe"|"unsubscribe", entityIds:[…]}`,
  `{op:"catalog", account}` (cold-restore enumeration), and — on a gated node —
  the `{op:"auth", token, account, sig}` handshake reply.
- `0x01` + `<wire frame>` — an opaque encrypted update; the node fans it out to
  the entity's other subscribers.

`GET /healthz` → `ok`.

## Storage providers (SYNC-3)

One wire protocol, swappable backend — pick with env, no client change:

| Provider | When | Config |
|---|---|---|
| **forward-only** | dev / live-only (SYNC-1) | _nothing set_ — persists nothing |
| **local** | self-hosted single box (the OQ-SYNC-1 default) | `STORAGE_DIR=/var/lib/brainstorm-sync` |
| **s3** | our managed bucket, or self-hosted bring-your-own R2/S3/MinIO | `S3_BUCKET` + `S3_ACCESS_KEY_ID` + `S3_SECRET_ACCESS_KEY` (+ `S3_ENDPOINT`/`S3_REGION`/`S3_PREFIX`) |

The object backend stores the **same opaque snapshot+tail blobs** as the local
one (it's the `ObjectBucket` seam behind `SnapshotStore`), so durability +
offline backfill + cold-restore work identically — the node still holds no key.

## Admission & metering (SYNC-4b)

Set `ENTITLEMENT_KEYS` (a `{kid: base64url-ed25519-pubkey}` JSON map of the
`cloud` billing-edge signer keys) to make the node **gated**. A gated
connection must complete a two-proof handshake before it can emit/subscribe/query:

1. a **`cloud` entitlement token** (verified offline against the
   keyset) → admission + plan + quota;
2. a **server nonce signed by the device identity key** → proves the wire
   `account` (= `sender`), so the `catalog` query is scoped to it and emission is
   checked against it (no impersonation, no foreign-account enumeration).

The node emits NDJSON **metering** events (connect / ingress / egress byte
counts, keyed by the verified billing `sub`) to `METERING_LOG_PATH` for
billing-edge ingestion. Token + nonce verification is the one reviewed
`relay-blind-exempt` crypto (auth, never content). Unset `ENTITLEMENT_KEYS` ⇒
open admission (dev / forward node), wire path unchanged.

## Ops: rate limits & abuse caps (SYNC-5)

On by default (`LIMITS_DISABLED=1` to turn off): per-IP connection rate, per-
connection message + byte rate, per-account frame rate, and hard caps on frame
size / control-message size / subscriptions-per-connection. Token buckets absorb
bursts and shed sustained over-rate; idle limiter state is evicted to bound
memory.

## Config

| Env | Default | Meaning |
|---|---|---|
| `PORT` | `7780` | WebSocket + healthz port |
| `AUDIT_LOG_PATH` | _(unset)_ | NDJSON sink for routing metadata (**never** ciphertext) |
| `LOG_LEVEL` | `info` | `debug` adds per-connection subscribe/route logs |
| `STORAGE_BACKEND` | _(inferred)_ | `local` \| `s3` (else: `S3_BUCKET` ⇒ s3, `STORAGE_DIR` ⇒ local) |
| `STORAGE_DIR` | _(unset)_ | local durable root |
| `S3_BUCKET` … `S3_PREFIX` | _(unset)_ | object-storage credentials + endpoint |
| `ENTITLEMENT_KEYS` | _(unset)_ | JSON `{kid: b64url-pubkey}`; **present ⇒ gated** |
| `REQUIRE_FEATURE` | _(unset)_ | require this token `features` flag to admit |
| `AUTH_TIMEOUT_MS` | `10000` | close a connection that never authenticates |
| `METERING_LOG_PATH` | _(unset)_ | NDJSON usage-metering sink |
| `LIMITS_DISABLED` | _(unset)_ | `1` turns off all rate limits / abuse caps |

See [`.env.example`](./.env.example) for the annotated full set.

## Docker

```sh
docker build -t brainstorm-sync .
docker run -p 7780:7780 -e STORAGE_DIR=/data -v bs-sync:/data brainstorm-sync
```

For a managed/self-hosted object backend, pass the `S3_*` env instead of mounting
a volume; for a gated deploy add `ENTITLEMENT_KEYS` + `METERING_LOG_PATH`.

## Security

Relay-blind by construction: no crypto/credential imports on the route path
(`wire`/`router`/`server`/`audit`/`sync/*`), no product-code dependency,
ciphertext never enters the audit log. The **only** sanctioned crypto is SYNC-4b
admission (`entitlement.ts`/`admission.ts` — Ed25519 *verify* for auth, never
content; reviewed `relay-blind-exempt`). The S3 credential is bucket transport
auth, not a vault key. The wire format is the only contract shared with the
product. Don't break those — see [CLAUDE.md](./CLAUDE.md).
