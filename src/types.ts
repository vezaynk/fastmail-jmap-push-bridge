export type Env = {
  STATE: KVNamespace;

  FASTMAIL_JMAP_TOKEN: string;
  GROK_BOT_WEBHOOK_URL: string;
  GROK_BOT_WEBHOOK_AUTH: string;
  ADMIN_TOKEN: string;

  /** EC P-256 private JWK as JSON string (kty, crv, d, x, y). */
  PUSH_UA_PRIVATE_JWK: string;
  /** Uncompressed UA public key, base64url. */
  PUSH_P256DH: string;
  /** 16-byte auth secret, base64url. */
  PUSH_AUTH: string;

  /** Optional absolute base URL of this worker (no trailing slash). */
  PUBLIC_BASE_URL?: string;
  /** Comma-separated allowlist of from-addresses; empty/unset = allow all. */
  FROM_ALLOWLIST?: string;
};

export type ForwardPayload = {
  source: "fastmail-jmap-push-bridge";
  accountId: string;
  emailId: string;
  from: string;
  subject: string;
  preview: string;
  receivedAt: string;
  mailboxIds: string[];
};

export type PushVerification = {
  "@type": "PushVerification";
  pushSubscriptionId: string;
  verificationCode: string;
};

export type StateChange = {
  "@type": "StateChange";
  changed: Record<string, Record<string, string>>;
};

export type JmapPushMessage = PushVerification | StateChange | Record<string, unknown>;

/** KV key names */
export const KV = {
  emailState: "emailState",
  recentEmailIds: "recentEmailIds",
  pushSubscriptionId: "pushSubscriptionId",
} as const;
