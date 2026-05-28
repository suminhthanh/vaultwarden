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
  f.set("deviceIdentifier", "00000000-0000-4000-8000-00000000ws01");
  f.set("deviceName", "WSTest");
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
  const email = `ws-${suffix}-${Date.now()}@example.com`;
  const hash = new Uint8Array(32);
  for (let i = 0; i < hash.length; i++) hash[i] = (i * 37 + 3) & 0xff;
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

function nextMessage(ws: WebSocket, timeoutMs = 10_000): Promise<string> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("ws message timeout")), timeoutMs);
    ws.once("message", (data) => {
      clearTimeout(timer);
      resolve(data.toString("utf-8"));
    });
  });
}

describe("phase 3: WebSocket notifications hub", () => {
  let s: Session;
  beforeAll(async () => {
    s = await loggedIn("hub");
  });

  it("client receives a SyncCipherUpdate fanned out from the DO", async () => {
    const ws = await openSocket(s.accessToken);
    try {
      const msgPromise = nextMessage(ws);
      const r = await req(`/_test/notify/${s.userId}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ kind: 0, payload_id: "cipher-test-id" }),
      });
      expect(r.status).toBe(200);
      const text = await msgPromise;
      const parsed = JSON.parse(text) as {
        Type: number;
        Payload: { Id: string; UserId: string };
      };
      expect(parsed.Type).toBe(0);
      expect(parsed.Payload.Id).toBe("cipher-test-id");
      expect(parsed.Payload.UserId).toBe(s.userId);
    } finally {
      ws.close();
    }
  });

  it("two parallel sockets both receive the broadcast", async () => {
    const a = await openSocket(s.accessToken);
    const b = await openSocket(s.accessToken);
    try {
      const both = Promise.all([nextMessage(a), nextMessage(b)]);
      await req(`/_test/notify/${s.userId}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ kind: 1, payload_id: "fanout-id" }),
      });
      const [m1, m2] = await both;
      expect(JSON.parse(m1).Payload.Id).toBe("fanout-id");
      expect(JSON.parse(m2).Payload.Id).toBe("fanout-id");
    } finally {
      a.close();
      b.close();
    }
  });

  it("rejects connections without a valid bearer token", async () => {
    await new Promise<void>((resolve) => {
      const ws = new WebSocket(`${WS_URL}/notifications/hub`);
      ws.once("error", () => resolve());
      ws.once("unexpected-response", (_req, res) => {
        expect(res.statusCode).toBe(400);
        ws.close();
        resolve();
      });
    });
  });
});
