/**
 * Fastmail JMAP Push → Grok Bot webhook bridge (Cloudflare Worker).
 */

import type { Env, ForwardPayload, JmapPushMessage } from "./types";
import { KV } from "./types";
import {
  b64urlDecode,
  decryptWebPushToString,
  generatePushKeys,
  parseUaPrivateJwk,
} from "./webpush";
import {
  createPushSubscription,
  fetchNewEmails,
  verifyPushSubscription,
} from "./jmap";

const RECENT_CAP = 100;
const SOURCE = "fastmail-jmap-push-bridge" as const;

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    try {
      if (request.method === "GET" && (path === "/health" || path === "/healthz")) {
        return json({ ok: true, service: SOURCE });
      }

      if (request.method === "GET" && path === "/") {
        return new Response(
          [
            "fastmail-jmap-push-bridge",
            "",
            "Fastmail JMAP PushSubscription → decrypt Web Push (RFC 8291) → Grok Bot webhook.",
            "See README.md in the repository for setup, secrets, and /admin/register.",
            "",
            "Endpoints: GET /health, POST /jmap-push, POST /admin/register, POST /admin/keys",
          ].join("\n"),
          { status: 200, headers: { "Content-Type": "text/plain; charset=utf-8" } },
        );
      }

      if (request.method === "POST" && path === "/jmap-push") {
        // Always ack with 200 on poison/bad messages to avoid push retry storms.
        return await handleJmapPush(request, env, ctx);
      }

      if (request.method === "POST" && path === "/admin/register") {
        return await handleAdminRegister(request, env);
      }

      if (request.method === "POST" && path === "/admin/keys") {
        return await handleAdminKeys(request, env);
      }

      return json({ error: "not_found" }, 404);
    } catch (err) {
      console.error("unhandled", err);
      return json({ error: "internal", message: String(err) }, 500);
    }
  },
};

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function requireAdmin(request: Request, env: Env): Response | null {
  const auth = request.headers.get("Authorization") ?? "";
  const expected = `Bearer ${env.ADMIN_TOKEN}`;
  if (!env.ADMIN_TOKEN || auth !== expected) {
    return json({ error: "unauthorized" }, 401);
  }
  return null;
}

function publicBase(request: Request, env: Env): string {
  if (env.PUBLIC_BASE_URL) return env.PUBLIC_BASE_URL.replace(/\/+$/, "");
  const u = new URL(request.url);
  return `${u.protocol}//${u.host}`;
}

async function handleAdminKeys(request: Request, env: Env): Promise<Response> {
  const denied = requireAdmin(request, env);
  if (denied) return denied;

  const keys = await generatePushKeys();

  // Store public parts in KV for convenience; private must be set as a Worker secret.
  await env.STATE.put(
    "pushPublicKeys",
    JSON.stringify({ p256dh: keys.p256dh, auth: keys.auth, generatedAt: new Date().toISOString() }),
  );

  return json({
    p256dh: keys.p256dh,
    auth: keys.auth,
    instructions: [
      "Set these Worker secrets (do NOT commit them):",
      `  wrangler secret put PUSH_UA_PRIVATE_JWK   # paste exactly: ${keys.privateJwkJson}`,
      `  wrangler secret put PUSH_P256DH           # value: ${keys.p256dh}`,
      `  wrangler secret put PUSH_AUTH             # value: ${keys.auth}`,
      "Then call POST /admin/register to create the Fastmail PushSubscription.",
    ],
    // Return private JWK once so the operator can set the secret; it is not stored in KV.
    PUSH_UA_PRIVATE_JWK: keys.privateJwkJson,
    note: "Private key is returned once in this response only. Public parts also written to KV key pushPublicKeys.",
  });
}

async function handleAdminRegister(request: Request, env: Env): Promise<Response> {
  const denied = requireAdmin(request, env);
  if (denied) return denied;

  if (!env.FASTMAIL_JMAP_TOKEN) return json({ error: "missing FASTMAIL_JMAP_TOKEN" }, 500);
  if (!env.PUSH_P256DH || !env.PUSH_AUTH) {
    return json({ error: "missing PUSH_P256DH / PUSH_AUTH — run POST /admin/keys first" }, 500);
  }

  const pushUrl = `${publicBase(request, env)}/jmap-push`;
  try {
    const sub = await createPushSubscription(env.FASTMAIL_JMAP_TOKEN, {
      url: pushUrl,
      p256dh: env.PUSH_P256DH,
      auth: env.PUSH_AUTH,
      deviceClientId: "grok-fastmail-bridge-1",
      types: ["Email"],
    });
    await env.STATE.put(KV.pushSubscriptionId, sub.id);
    return json({
      ok: true,
      pushSubscriptionId: sub.id,
      expires: sub.expires ?? null,
      url: pushUrl,
      deviceClientId: "grok-fastmail-bridge-1",
      types: ["Email"],
      note: "Fastmail will POST a PushVerification to /jmap-push; this worker acknowledges it automatically.",
    });
  } catch (err) {
    console.error("register failed", err);
    return json({ error: "register_failed", message: String(err) }, 502);
  }
}

async function handleJmapPush(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  try {
    const encoding = (request.headers.get("Content-Encoding") ?? "").toLowerCase();
    const raw = await request.arrayBuffer();

    let text: string;
    if (encoding.includes("aes128gcm") || looksLikeAes128Gcm(raw)) {
      if (!env.PUSH_UA_PRIVATE_JWK || !env.PUSH_AUTH) {
        console.error("encrypted push but missing PUSH_UA_PRIVATE_JWK / PUSH_AUTH");
        return json({ ok: true, ignored: "missing_decrypt_keys" });
      }
      try {
        const jwk = parseUaPrivateJwk(env.PUSH_UA_PRIVATE_JWK);
        const auth = b64urlDecode(env.PUSH_AUTH);
        text = await decryptWebPushToString(raw, jwk, auth);
      } catch (err) {
        console.error("decrypt failed (acking 200)", err);
        return json({ ok: true, ignored: "decrypt_failed" });
      }
    } else {
      text = new TextDecoder().decode(raw);
    }

    let msg: JmapPushMessage;
    try {
      msg = JSON.parse(text) as JmapPushMessage;
    } catch (err) {
      console.error("invalid JSON push (acking 200)", err, text.slice(0, 200));
      return json({ ok: true, ignored: "invalid_json" });
    }

    const type = (msg as { "@type"?: string })["@type"];

    if (type === "PushVerification") {
      const m = msg as { pushSubscriptionId: string; verificationCode: string };
      try {
        await verifyPushSubscription(
          env.FASTMAIL_JMAP_TOKEN,
          m.pushSubscriptionId,
          m.verificationCode,
        );
        await env.STATE.put(KV.pushSubscriptionId, m.pushSubscriptionId);
        console.log("PushVerification acknowledged", m.pushSubscriptionId);
        return json({ ok: true, verified: true });
      } catch (err) {
        console.error("PushVerification failed (acking 200)", err);
        return json({ ok: true, verified: false });
      }
    }

    if (type === "StateChange") {
      const changed = (msg as { changed?: Record<string, Record<string, string>> }).changed ?? {};
      // Process Email state changes asynchronously so we respond quickly.
      ctx.waitUntil(processStateChange(env, changed));
      return json({ ok: true, accepted: true });
    }

    console.log("unknown push type (acking 200)", type);
    return json({ ok: true, ignored: "unknown_type", type: type ?? null });
  } catch (err) {
    console.error("jmap-push handler error (acking 200)", err);
    return json({ ok: true, ignored: "handler_error" });
  }
}

function looksLikeAes128Gcm(buf: ArrayBuffer): boolean {
  // Heuristic: binary body with idlen=65 (0x41) at offset 20 → uncompressed key in keyid
  const b = new Uint8Array(buf);
  return b.length > 86 && b[20] === 65 && b[21] === 0x04;
}

async function processStateChange(
  env: Env,
  changed: Record<string, Record<string, string>>,
): Promise<void> {
  for (const [accountId, types] of Object.entries(changed)) {
    if (!types || !("Email" in types)) continue;
    try {
      await processEmailChanges(env, accountId);
    } catch (err) {
      console.error("processEmailChanges failed", accountId, err);
    }
  }
}

async function processEmailChanges(env: Env, accountId: string): Promise<void> {
  if (!env.FASTMAIL_JMAP_TOKEN) {
    console.error("missing FASTMAIL_JMAP_TOKEN");
    return;
  }
  if (!env.GROK_BOT_WEBHOOK_URL) {
    console.error("missing GROK_BOT_WEBHOOK_URL");
    return;
  }

  const sinceState = await env.STATE.get(KV.emailState);
  const { emails, newState } = await fetchNewEmails(
    env.FASTMAIL_JMAP_TOKEN,
    accountId,
    sinceState,
  );

  const recent = await loadRecentIds(env);
  const allow = parseAllowlist(env.FROM_ALLOWLIST);

  for (const email of emails) {
    if (recent.has(email.id)) continue;
    if (allow && !fromAllowed(email.from, allow)) {
      console.log("skipped by allowlist", email.id, email.from);
      recent.add(email.id);
      continue;
    }

    const payload: ForwardPayload = {
      source: SOURCE,
      accountId,
      emailId: email.id,
      from: email.from,
      subject: email.subject,
      preview: email.preview,
      receivedAt: email.receivedAt,
      mailboxIds: email.mailboxIds,
    };

    try {
      await forwardToGrok(env, payload);
      recent.add(email.id);
    } catch (err) {
      console.error("forward failed", email.id, err);
      // Still mark seen to avoid poison retry loops on permanently bad payloads
      recent.add(email.id);
    }
  }

  await saveRecentIds(env, recent);
  if (newState) await env.STATE.put(KV.emailState, newState);
}

function parseAllowlist(raw: string | undefined): Set<string> | null {
  if (!raw || !raw.trim()) return null;
  const set = new Set(
    raw
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  );
  return set.size ? set : null;
}

function fromAllowed(from: string, allow: Set<string>): boolean {
  const lower = from.toLowerCase();
  for (const a of allow) {
    if (lower.includes(a)) return true;
  }
  return false;
}

async function loadRecentIds(env: Env): Promise<Set<string>> {
  const raw = await env.STATE.get(KV.recentEmailIds);
  if (!raw) return new Set();
  try {
    const arr = JSON.parse(raw) as string[];
    return new Set(arr);
  } catch {
    return new Set();
  }
}

async function saveRecentIds(env: Env, ids: Set<string>): Promise<void> {
  const arr = [...ids];
  const trimmed = arr.length > RECENT_CAP ? arr.slice(arr.length - RECENT_CAP) : arr;
  await env.STATE.put(KV.recentEmailIds, JSON.stringify(trimmed));
}

async function forwardToGrok(env: Env, payload: ForwardPayload): Promise<void> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (env.GROK_BOT_WEBHOOK_AUTH) {
    headers.Authorization = env.GROK_BOT_WEBHOOK_AUTH.startsWith("Bearer ")
      ? env.GROK_BOT_WEBHOOK_AUTH
      : `Bearer ${env.GROK_BOT_WEBHOOK_AUTH}`;
  }
  const res = await fetch(env.GROK_BOT_WEBHOOK_URL, {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`webhook HTTP ${res.status}: ${text.slice(0, 300)}`);
  }
}
