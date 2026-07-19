# Brainstorm feedback collector

The receiving end for the Brainstorm shell's in-app **Send feedback** dialog and
**opt-in crash reporter** (product-side Feedback-1/Feedback-2). A tiny Bun HTTP
service: accept the client's redacted JSON POSTs, retain them as append-only
JSONL, and pipe each one into a private GitHub inbox repo as a triage-able issue.

## Why it lives in this repo but NOT in the relay

The relay node (`../src`) is **relay-blind** — its invariant is that it never
sees cleartext. Feedback and crash payloads are plaintext (client-redacted)
user text and stack traces, so they must not share a process, port, or storage
with the ciphertext plane. This directory is a **separate service and deploy
unit** that only shares repo tooling and the pure `KeyedRateLimiter` from
`src/limits.ts`. Nothing in `src/` imports from here; nothing here touches the
wire path.

## Contract (fixed by the shipped client)

- `POST <any path>` `Content-Type: application/json`, header
  `X-Brainstorm-Installation-Id`; crash POSTs also carry
  `X-Brainstorm-Crash-Kind`. One JSON object per POST.
- **2xx** → accepted (the client ignores the response body).
- **4xx** → the client drops the item permanently (schema refusal / rate limit).
- **5xx** → the client retries (crash queue drains at boot, every 15 min, on quit).
- The client authenticates nothing (doc-48 §Posture: anonymous best-effort
  intake) — abuse control is this service's job: per-IP + per-installation
  token buckets, 256 KiB body cap, strict field validation.

`src/contract.ts` mirrors the product's payload shapes
(`packages/shell/src/main/feedback/*-payload.ts` in the app repo) — shared
contract, never shared code, same as the relay's `src/wire.ts`.

## Run

```sh
bun run start:feedback                   # from the repo root; port 7790
FEEDBACK_GITHUB_DRY_RUN=1 \
FEEDBACK_GITHUB_REPO=owner/inbox \
bun run start:feedback                   # log would-be issues, no token needed
```

Point a dev shell at it:

```sh
BRAINSTORM_FEEDBACK_ENDPOINT=http://127.0.0.1:7790/ bun run dev   # in the app repo
```

(The shell seeds the endpoint into `<userData>/feedback-settings.json` on first
launch; feedback + crash reporting remain **opt-in** in Settings → Privacy.)

## Deploy

```sh
docker build -f feedback-collector/Dockerfile -t brainstorm-feedback .   # repo root
docker run -d -p 7790:7790 \
  -v feedback-data:/app/feedback-data \
  -e FEEDBACK_GITHUB_REPO=owner/feedback-inbox \
  -e FEEDBACK_GITHUB_TOKEN=github_pat_… \
  brainstorm-feedback
```

Then bake the public URL into release builds with
`BRAINSTORM_FEEDBACK_ENDPOINT=https://feedback.example.com/` in the release
workflow environment. TLS termination (Caddy/nginx/Cloudflare) sits in front —
the service itself speaks plain HTTP.

## Storage & triage

- `FEEDBACK_DATA_DIR/feedback-YYYY-MM.jsonl` / `crash-YYYY-MM.jsonl` — one
  record per line (`{recordKind, receivedAt, payload}`), no client IPs stored
  (doc-48 data minimisation). Rotation = archive/delete old month files.
- GitHub: feedback → one issue per item labeled `feedback` + kind; crash →
  deduplicated by a `fp-<stack-hash>` marker in the issue title (new occurrence
  = comment). The fine-grained PAT needs Issues read+write on the inbox repo
  only.
