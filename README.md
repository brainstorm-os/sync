# Brainstorm Sync

A **zero-knowledge sync node** for [Brainstorm](https://github.com/brainst0rm-os/shell) — a relay-blind server that forwards and durably stores the **encrypted** CRDT traffic between a user's devices and collaborators.

It holds **no key** and can never decrypt your content. It reads only the plaintext routing header (which entity, who sent it) to fan a message out to the other subscribers, and forwards the opaque ciphertext body untouched. Confidentiality is the client's job; this node only moves and stores sealed bytes.

You can run your own — it's a single, dependency-free process — or use a managed instance.

## Run

```sh
bun install        # dev tooling only (biome, tsc); the node has no runtime deps
bun run start      # listen on PORT (default 7780)
bun test           # core behavior + the ciphertext-only audit invariant
```

`GET /healthz` → `ok`.

Clients connect over WebSocket and speak a small binary wire protocol:

- `0x00` + JSON control — `{op:"subscribe"|"unsubscribe", entityIds:[…]}`, `{op:"catalog", account}` (cold-restore enumeration), and, on a gated node, the `{op:"auth", token, account, sig}` handshake.
- `0x01` + `<frame>` — an opaque encrypted update; the node fans it out to the entity's other subscribers.

## Storage

One wire protocol, swappable backend — pick with env, no client change:

| Backend | When | Config |
|---|---|---|
| **forward-only** | live-only relay; persists nothing | _nothing set_ |
| **local** | self-hosted single box | `STORAGE_DIR=/var/lib/brainstorm-sync` |
| **object store** | managed or bring-your-own R2 / S3 / MinIO | `S3_BUCKET` + `S3_ACCESS_KEY_ID` + `S3_SECRET_ACCESS_KEY` (+ `S3_ENDPOINT` / `S3_REGION` / `S3_PREFIX`) |

Durable backends store the **same opaque snapshot+tail blobs** as the local one, so offline backfill and cold restore work identically — the node still holds no key. The storage credential is bucket transport auth, not a vault key.

## Gated admission & metering

Set `ENTITLEMENT_KEYS` (a `{kid: base64url-ed25519-pubkey}` map of signer keys) to make the node **gated**. A gated connection completes a two-proof handshake before it can subscribe or emit:

1. an **entitlement token** (verified offline against the keyset) → admission, plan, and quota;
2. a **server nonce signed by the device identity key** → proves the connection's account, so enumeration and emission are scoped to it.

The node emits NDJSON **metering** events (connect / ingress / egress byte counts) to `METERING_LOG_PATH`. Token and nonce verification are the only cryptographic operations the node performs — for authorization, never content. Leave `ENTITLEMENT_KEYS` unset for an open node.

## Rate limits

On by default (`LIMITS_DISABLED=1` to turn off): per-IP connection rate, per-connection message + byte rate, per-account frame rate, and hard caps on message size and subscriptions-per-connection. Token buckets absorb bursts and shed sustained over-rate.

## Config

| Env | Default | Meaning |
|---|---|---|
| `PORT` | `7780` | WebSocket + healthz port |
| `AUDIT_LOG_PATH` | _(unset)_ | NDJSON sink for routing metadata (**never** ciphertext) |
| `LOG_LEVEL` | `info` | `debug` adds per-connection subscribe/route logs |
| `STORAGE_BACKEND` | _(inferred)_ | `local` \| `s3` (else inferred from `S3_BUCKET` / `STORAGE_DIR`) |
| `STORAGE_DIR` | _(unset)_ | local durable root |
| `S3_BUCKET` … `S3_PREFIX` | _(unset)_ | object-storage credentials + endpoint |
| `ENTITLEMENT_KEYS` | _(unset)_ | JSON `{kid: b64url-pubkey}`; **present ⇒ gated** |
| `REQUIRE_FEATURE` | _(unset)_ | require this token feature flag to admit |
| `AUTH_TIMEOUT_MS` | `10000` | close a connection that never authenticates |
| `METERING_LOG_PATH` | _(unset)_ | NDJSON usage-metering sink |
| `LIMITS_DISABLED` | _(unset)_ | `1` turns off all rate limits |

See [`.env.example`](./.env.example) for the annotated full set.

## Docker

```sh
docker build -t brainstorm-sync .
docker run -p 7780:7780 -e STORAGE_DIR=/data -v bs-sync:/data brainstorm-sync
```

For an object backend, pass the `S3_*` env instead of mounting a volume; for a gated deploy add `ENTITLEMENT_KEYS` + `METERING_LOG_PATH`.

## Security

Relay-blind by construction: no cryptographic or credential handling on the route path, no decryption, and ciphertext never enters the audit log. The only cryptography the node performs is offline signature *verification* for gated admission — authorization, never content.

## License

[AGPL-3.0-or-later](LICENSE.md) © Brainstorm — free and open source; network use triggers the copyleft source-disclosure obligation.
