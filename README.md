# fastmail-jmap-push-bridge

Cloudflare Worker that bridges **Fastmail JMAP PushSubscription** events to a **Grok Bot webhook**.

Flow:

1. Fastmail sends a Web Push (`Content-Encoding: aes128gcm`) to `POST /jmap-push`
2. Worker decrypts as the **UA** (RFC 8291 §3.4 + RFC 8188 single-record `aes128gcm`)
3. On `PushVerification`, calls `PushSubscription/set` with `verificationCode`
4. On `StateChange` for `Email`, runs `Email/changes` + `Email/get` and `POST`s JSON to your Grok Bot webhook

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/` | — | Short pointer to this README |
| `GET` | `/health` | — | Liveness JSON |
| `POST` | `/jmap-push` | — (Fastmail push) | Receive / decrypt / handle push |
| `POST` | `/admin/keys` | `Authorization: Bearer ADMIN_TOKEN` | Generate UA ECDH keypair + auth |
| `POST` | `/admin/register` | `Authorization: Bearer ADMIN_TOKEN` | Create Fastmail `PushSubscription` |

Poison / undecryptable messages are **acked with HTTP 200** to avoid push retry storms; errors are logged.

## Forward payload

```json
{
  "source": "fastmail-jmap-push-bridge",
  "accountId": "uXXXX",
  "emailId": "Mxxxxx",
  "from": "Alice <alice@example.com>",
  "subject": "Hello",
  "preview": "First line…",
  "receivedAt": "2026-09-17T20:00:00Z",
  "mailboxIds": ["INBOX"]
}
```

## Secrets & env (exact names)

Set via `wrangler secret put <NAME>` (never commit these):

| Name | Required | Description |
|------|----------|-------------|
| `FASTMAIL_JMAP_TOKEN` | yes | Fastmail API token with JMAP / mail scope |
| `GROK_BOT_WEBHOOK_URL` | yes | Absolute URL of the Grok Bot webhook routine |
| `GROK_BOT_WEBHOOK_AUTH` | yes | Bearer token (with or without `Bearer ` prefix) |
| `ADMIN_TOKEN` | yes | Shared secret for `/admin/*` |
| `PUSH_UA_PRIVATE_JWK` | yes | **JSON string** of EC P-256 JWK: `{"kty":"EC","crv":"P-256","d":"...","x":"...","y":"..."}` |
| `PUSH_P256DH` | yes | UA public key, **uncompressed** (65 bytes, leading `0x04`), **base64url** |
| `PUSH_AUTH` | yes | 16-byte auth secret, **base64url** |

Optional (plain `[vars]` in `wrangler.toml` or secrets):

| Name | Description |
|------|-------------|
| `PUBLIC_BASE_URL` | Public origin of this worker (no trailing slash). Used when registering the push URL. Defaults to the incoming request host. |
| `FROM_ALLOWLIST` | Comma-separated substrings matched against `from` (case-insensitive). Empty = allow all. |

### Key material notes

- **Preferred private key form:** `PUSH_UA_PRIVATE_JWK` (JWK JSON string).  
  PKCS8 is **not** used by this worker — always JWK.
- Public subscription keys sent to Fastmail: `PUSH_P256DH` + `PUSH_AUTH` (Web Push / RFC 8291).
- Generate with `npm run keygen` or `POST /admin/keys`.

## KV binding

Binding name: **`STATE`** (see `wrangler.toml`).

Keys used:

| Key | Purpose |
|-----|---------|
| `emailState` | Last JMAP Email state string |
| `recentEmailIds` | JSON array of recent email ids (cap ~100) |
| `pushSubscriptionId` | Last known Fastmail push subscription id |
| `pushPublicKeys` | Optional cache of last generated public key material |

```bash
wrangler kv:namespace create STATE
# paste the id into wrangler.toml [[kv_namespaces]] id = "..."
```

## Setup

### 1. Fastmail API token

1. Fastmail → Settings → Privacy & Security → **API tokens** (or Integrations)
2. Create a token with **JMAP** / mail access
3. Session probe (optional):

```bash
curl -s -H "Authorization: Bearer $FASTMAIL_JMAP_TOKEN" \
  https://api.fastmail.com/jmap/session | jq '.apiUrl, .primaryAccounts'
```

### 2. Clone / install

```bash
git clone https://github.com/vezaynk/fastmail-jmap-push-bridge.git
cd fastmail-jmap-push-bridge
npm install
```

### 3. KV + config

```bash
wrangler kv:namespace create STATE
# edit wrangler.toml → replace REPLACE_WITH_KV_NAMESPACE_ID
```

### 4. Generate push keys & set secrets

```bash
npm run keygen
# or after first deploy: curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" https://<worker>/admin/keys

echo '<jwk-json>' | wrangler secret put PUSH_UA_PRIVATE_JWK
echo -n '<p256dh>' | wrangler secret put PUSH_P256DH
echo -n '<auth>'   | wrangler secret put PUSH_AUTH

wrangler secret put FASTMAIL_JMAP_TOKEN
wrangler secret put GROK_BOT_WEBHOOK_URL
wrangler secret put GROK_BOT_WEBHOOK_AUTH
wrangler secret put ADMIN_TOKEN
```

Optional:

```bash
wrangler secret put PUBLIC_BASE_URL   # https://fastmail-jmap-push-bridge.<account>.workers.dev
```

### 5. Deploy

```bash
npm run deploy
```

### 6. Register PushSubscription

```bash
curl -sS -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://<your-worker>/admin/register | jq .
```

This creates a subscription with:

- `deviceClientId`: `grok-fastmail-bridge-1`
- `url`: `{PUBLIC_BASE_URL or request origin}/jmap-push`
- `keys`: `{ p256dh, auth }` from env
- `types`: `["Email"]`

Fastmail then POSTs a `PushVerification` to `/jmap-push`; the worker completes verification automatically.

### 7. Wire Grok Bot webhook

Point `GROK_BOT_WEBHOOK_URL` at your Grok Bot / automation HTTP routine.  
Authorize with `GROK_BOT_WEBHOOK_AUTH`. Expect the forward payload shape above.

## Local dev

```bash
cp .dev.vars.example .dev.vars   # if present — fill secrets locally
npm run dev
npm test                         # RFC 8291 §5 decrypt vector
```

## Security

- **Never commit** tokens, JWKs, or `.dev.vars`.
- `/admin/*` requires `ADMIN_TOKEN`; keep it long and random.
- Push endpoint intentionally returns **200** on decrypt/parse failures so Fastmail does not retry forever; monitor Worker logs.
- Prefer `FROM_ALLOWLIST` if you only want mail from known senders forwarded to the bot.
- Rotate push keys by generating new ones, updating secrets, and re-registering the subscription.
- Worker holds mail metadata (from/subject/preview) in transit to your webhook — treat the webhook URL as confidential.

## Project layout

```
src/index.ts          Worker routes
src/webpush.ts        RFC 8291 UA decrypt + keygen
src/jmap.ts           Fastmail session + PushSubscription + Email
src/types.ts          Env / payload / KV key names
src/base64url.ts      base64url helpers
test/webpush-decrypt.test.ts   RFC 8291 §5 vector
scripts/keygen.mjs    CLI key generator
wrangler.toml         Worker + KV binding STATE
```

## License

MIT
