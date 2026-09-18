/**
 * Minimal Fastmail JMAP client: session, PushSubscription, Email/changes+get.
 */

export type JmapSession = {
  apiUrl: string;
  eventSourceUrl?: string;
  primaryAccounts: Record<string, string>;
  accountId: string;
};

export type EmailSummary = {
  id: string;
  from: string;
  subject: string;
  preview: string;
  receivedAt: string;
  mailboxIds: string[];
};

type JmapResponse = {
  methodResponses: Array<[string, Record<string, unknown>, string]>;
  sessionState?: string;
};

async function jmapCall(
  apiUrl: string,
  token: string,
  methodCalls: unknown[],
): Promise<JmapResponse> {
  const res = await fetch(apiUrl, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      using: [
        "urn:ietf:params:jmap:core",
        "urn:ietf:params:jmap:mail",
      ],
      methodCalls,
    }),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`JMAP HTTP ${res.status}: ${text.slice(0, 500)}`);
  }
  return (await res.json()) as JmapResponse;
}

export async function getSession(token: string): Promise<JmapSession> {
  const res = await fetch("https://api.fastmail.com/jmap/session", {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`JMAP session HTTP ${res.status}: ${text.slice(0, 500)}`);
  }
  const session = (await res.json()) as {
    apiUrl: string;
    eventSourceUrl?: string;
    primaryAccounts: Record<string, string>;
  };
  const accountId =
    session.primaryAccounts["urn:ietf:params:jmap:mail"] ??
    Object.values(session.primaryAccounts)[0];
  if (!accountId) throw new Error("No JMAP mail account in session");
  return {
    apiUrl: session.apiUrl,
    eventSourceUrl: session.eventSourceUrl,
    primaryAccounts: session.primaryAccounts,
    accountId,
  };
}

export async function createPushSubscription(
  token: string,
  opts: {
    url: string;
    p256dh: string;
    auth: string;
    deviceClientId?: string;
    types?: string[];
  },
): Promise<{ id: string; expires?: string | null }> {
  const session = await getSession(token);
  const deviceClientId = opts.deviceClientId ?? "grok-fastmail-bridge-1";
  const types = opts.types ?? ["Email"];

  const data = await jmapCall(session.apiUrl, token, [
    [
      "PushSubscription/set",
      {
        create: {
          sub: {
            deviceClientId,
            url: opts.url,
            keys: {
              p256dh: opts.p256dh,
              auth: opts.auth,
            },
            types,
          },
        },
      },
      "0",
    ],
  ]);

  const [, result] = data.methodResponses[0] ?? [];
  if (!result) throw new Error("Empty PushSubscription/set response");
  if (result.notCreated) {
    throw new Error(`PushSubscription create failed: ${JSON.stringify(result.notCreated)}`);
  }
  const created = result.created as Record<string, { id: string; expires?: string | null }> | undefined;
  const sub = created?.sub;
  if (!sub?.id) throw new Error(`PushSubscription create missing id: ${JSON.stringify(result)}`);
  return { id: sub.id, expires: sub.expires };
}

export async function verifyPushSubscription(
  token: string,
  pushSubscriptionId: string,
  verificationCode: string,
): Promise<void> {
  const session = await getSession(token);
  const data = await jmapCall(session.apiUrl, token, [
    [
      "PushSubscription/set",
      {
        update: {
          [pushSubscriptionId]: {
            verificationCode,
          },
        },
      },
      "0",
    ],
  ]);
  const [, result] = data.methodResponses[0] ?? [];
  if (!result) throw new Error("Empty PushSubscription/set (verify) response");
  if (result.notUpdated) {
    throw new Error(`PushSubscription verify failed: ${JSON.stringify(result.notUpdated)}`);
  }
}

function formatEmailAddress(addr: { name?: string | null; email: string } | undefined): string {
  if (!addr) return "";
  if (addr.name) return `${addr.name} <${addr.email}>`;
  return addr.email;
}

export async function fetchNewEmails(
  token: string,
  accountId: string,
  sinceState: string | null,
): Promise<{ emails: EmailSummary[]; newState: string }> {
  const session = await getSession(token);
  // Prefer provided accountId; fall back to session primary
  const acct = accountId || session.accountId;

  if (!sinceState) {
    // Bootstrap: get current state + recent emails via Email/query
    const data = await jmapCall(session.apiUrl, token, [
      [
        "Email/query",
        {
          accountId: acct,
          sort: [{ property: "receivedAt", isAscending: false }],
          limit: 20,
        },
        "0",
      ],
      [
        "Email/get",
        {
          accountId: acct,
          "#ids": {
            resultOf: "0",
            name: "Email/query",
            path: "/ids",
          },
          properties: ["id", "from", "subject", "preview", "receivedAt", "mailboxIds"],
        },
        "1",
      ],
    ]);

    const queryResp = data.methodResponses.find((m) => m[0] === "Email/query")?.[1];
    const getResp = data.methodResponses.find((m) => m[0] === "Email/get")?.[1];
    const newState = (queryResp?.queryState as string) ?? (getResp?.state as string) ?? "";
    const list = (getResp?.list as Array<Record<string, unknown>>) ?? [];
    const emails = list.map(mapEmail);
    return { emails, newState };
  }

  const data = await jmapCall(session.apiUrl, token, [
    [
      "Email/changes",
      {
        accountId: acct,
        sinceState,
        maxChanges: 50,
      },
      "0",
    ],
    [
      "Email/get",
      {
        accountId: acct,
        "#ids": {
          resultOf: "0",
          name: "Email/changes",
          path: "/created",
        },
        properties: ["id", "from", "subject", "preview", "receivedAt", "mailboxIds"],
      },
      "1",
    ],
  ]);

  const changes = data.methodResponses.find((m) => m[0] === "Email/changes")?.[1];
  const getResp = data.methodResponses.find((m) => m[0] === "Email/get")?.[1];

  if (!changes) {
    // sinceState may be too old — fall back to query bootstrap
    if (
      data.methodResponses.some(
        (m) => m[0] === "error" || (typeof m[1]?.type === "string" && String(m[1].type).includes("cannotCalculate")),
      )
    ) {
      return fetchNewEmails(token, acct, null);
    }
  }

  // Handle error method response
  for (const [name, body] of data.methodResponses) {
    if (name === "error" || (body && (body as { type?: string }).type === "cannotCalculateChanges")) {
      return fetchNewEmails(token, acct, null);
    }
  }

  const newState = (changes?.newState as string) ?? (getResp?.state as string) ?? sinceState;
  const list = (getResp?.list as Array<Record<string, unknown>>) ?? [];
  return { emails: list.map(mapEmail), newState };
}

function mapEmail(e: Record<string, unknown>): EmailSummary {
  const fromArr = e.from as Array<{ name?: string | null; email: string }> | undefined;
  const mailboxIdsObj = (e.mailboxIds as Record<string, boolean>) ?? {};
  return {
    id: String(e.id ?? ""),
    from: formatEmailAddress(fromArr?.[0]),
    subject: String(e.subject ?? ""),
    preview: String(e.preview ?? ""),
    receivedAt: String(e.receivedAt ?? ""),
    mailboxIds: Object.keys(mailboxIdsObj).filter((k) => mailboxIdsObj[k]),
  };
}
