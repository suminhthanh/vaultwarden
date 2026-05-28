import { describe, it, expect, beforeAll } from "vitest";
import WebSocket from "ws";

const BASE_URL = process.env.WORKER_URL ?? "http://127.0.0.1:8787";
const WS_URL = BASE_URL.replace(/^http/, "ws");

async function req(path: string, init?: RequestInit) {
  return fetch(`${BASE_URL}${path}`, init);
}

function tokenForm(extra: Record<string, string>): URLSearchParams {
  const f = new URLSearchParams();
  f.set("grant_type", "password");
  f.set("scope", "api offline_access");
  f.set("client_id", "web");
  f.set("deviceIdentifier", "00000000-0000-4000-8000-00000000live");
  f.set("deviceName", "LiveSyncTest");
  f.set("deviceType", "9");
  for (const [k, v] of Object.entries(extra)) f.set(k, v);
  return f;
}

interface Session {
  email: string;
  userId: string;
  accessToken: string;
}

async function loggedIn(suffix: string): Promise<Session> {
  const email = `live-${suffix}-${Date.now()}@example.com`;
  const hash = new Uint8Array(32);
  for (let i = 0; i < hash.length; i++) hash[i] = (i * 41 + 9) & 0xff;
  let bin = "";
  for (const b of hash) bin += String.fromCharCode(b);
  const hashB64 = Buffer.from(bin, "binary").toString("base64");

  await req("/api/accounts/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, masterPasswordHash: hashB64, key: "0.k" }),
  });
  const login = await req("/identity/connect/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: tokenForm({ username: email, password: hashB64 }).toString(),
  });
  const body = (await login.json()) as { access_token: string };
  const profile = await req("/api/accounts/profile", { headers: { authorization: `Bearer ${body.access_token}` } });
  const p = (await profile.json()) as { Id: string };
  return { email, userId: p.Id, accessToken: body.access_token };
}

function openSocket(token: string): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`${WS_URL}/notifications/hub`, {
      headers: { authorization: `Bearer ${token}` },
    });
    ws.once("open", () => resolve(ws));
    ws.once("error", reject);
  });
}

function collectMessages(ws: WebSocket): { messages: string[]; close: () => void } {
  const messages: string[] = [];
  const handler = (data: WebSocket.Data) => messages.push(data.toString("utf-8"));
  ws.on("message", handler);
  return {
    messages,
    close: () => {
      ws.off("message", handler);
      ws.close();
    },
  };
}

async function waitFor<T>(check: () => T | undefined, timeoutMs = 5000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const v = check();
    if (v !== undefined) return v;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error("waitFor timed out");
}

describe("phase 3: live sync of vault edits over WebSocket", () => {
  let s: Session;
  beforeAll(async () => {
    s = await loggedIn("flow");
  });

  it("cipher create/update/soft-delete/hard-delete each push a notification", async () => {
    const ws = await openSocket(s.accessToken);
    const collector = collectMessages(ws);

    try {
      const create = await req("/api/ciphers", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${s.accessToken}` },
        body: JSON.stringify({ type: 1, name: "Live", login: { username: "u", password: "p" } }),
      });
      expect(create.status).toBe(200);
      const { Id } = (await create.json()) as { Id: string };

      await waitFor(() =>
        collector.messages.find((m) => {
          const j = JSON.parse(m);
          return j.Type === 1 && j.Payload.Id === Id;
        }),
      );

      const upd = await req(`/api/ciphers/${Id}`, {
        method: "PUT",
        headers: { "content-type": "application/json", authorization: `Bearer ${s.accessToken}` },
        body: JSON.stringify({ type: 1, name: "Live v2", login: { username: "u", password: "p2" } }),
      });
      expect(upd.status).toBe(200);
      await waitFor(() =>
        collector.messages.find((m) => {
          const j = JSON.parse(m);
          return j.Type === 0 && j.Payload.Id === Id;
        }),
      );

      const soft = await req(`/api/ciphers/${Id}/delete`, {
        method: "PUT",
        headers: { authorization: `Bearer ${s.accessToken}` },
      });
      expect(soft.status).toBe(200);
      await waitFor(
        () =>
          collector.messages.filter((m) => {
            const j = JSON.parse(m);
            return j.Type === 0 && j.Payload.Id === Id;
          }).length >= 2,
      );

      const hard = await req(`/api/ciphers/${Id}/delete-admin`, {
        method: "DELETE",
        headers: { authorization: `Bearer ${s.accessToken}` },
      });
      expect(hard.status).toBe(200);
      await waitFor(() =>
        collector.messages.find((m) => {
          const j = JSON.parse(m);
          return j.Type === 9 && j.Payload.Id === Id;
        }),
      );
    } finally {
      collector.close();
    }
  });

  it("two browser tabs both see folder create live", async () => {
    const a = await openSocket(s.accessToken);
    const b = await openSocket(s.accessToken);
    const ca = collectMessages(a);
    const cb = collectMessages(b);

    try {
      const r = await req("/api/folders", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${s.accessToken}` },
        body: JSON.stringify({ name: "Shared" }),
      });
      const { Id } = (await r.json()) as { Id: string };

      await waitFor(() =>
        ca.messages.find((m) => {
          const j = JSON.parse(m);
          return j.Type === 7 && j.Payload.Id === Id;
        }),
      );
      await waitFor(() =>
        cb.messages.find((m) => {
          const j = JSON.parse(m);
          return j.Type === 7 && j.Payload.Id === Id;
        }),
      );
    } finally {
      ca.close();
      cb.close();
    }
  });
});
