import { describe, it, expect, beforeAll } from "vitest";

const BASE_URL = process.env.WORKER_URL ?? "http://127.0.0.1:8787";

async function req(path: string, init?: RequestInit) {
  return fetch(`${BASE_URL}${path}`, init);
}

function tokenForm(extra: Record<string, string>): URLSearchParams {
  const f = new URLSearchParams();
  f.set("grant_type", "password");
  f.set("scope", "api offline_access");
  f.set("client_id", "web");
  f.set("deviceIdentifier", "00000000-0000-4000-8000-00000000cron");
  f.set("deviceName", "CronTest");
  f.set("deviceType", "9");
  for (const [k, v] of Object.entries(extra)) f.set(k, v);
  return f;
}

interface Session {
  email: string;
  accessToken: string;
}

async function loggedIn(suffix: string): Promise<Session> {
  const email = `cron-${suffix}-${Date.now()}@example.com`;
  const hash = new Uint8Array(32);
  for (let i = 0; i < hash.length; i++) hash[i] = (i * 43 + 5) & 0xff;
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
  return { email, accessToken: ((await login.json()) as { access_token: string }).access_token };
}

async function fireCron(cron: string) {
  const r = await req(`/cdn-cgi/handler/scheduled?cron=${encodeURIComponent(cron)}`);
  expect(r.status).toBe(200);
}

describe("phase 3: cron triggers", () => {
  let s: Session;
  beforeAll(async () => {
    s = await loggedIn("trigger");
  });

  it("5-minute cron purges expired sends but leaves future ones", async () => {
    const past = "2000-01-01T00:00:00.000000Z";
    const future = "2099-12-31T23:59:59.000000Z";

    const expired = await req("/api/sends", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${s.accessToken}` },
      body: JSON.stringify({
        type: 0,
        name: "expired",
        text: { text: "x", hidden: false },
        key: "0.k",
        deletionDate: past,
      }),
    });
    expect(expired.status).toBe(200);
    const expiredId = ((await expired.json()) as { Id: string }).Id;

    const alive = await req("/api/sends", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${s.accessToken}` },
      body: JSON.stringify({
        type: 0,
        name: "alive",
        text: { text: "y", hidden: false },
        key: "0.k",
        deletionDate: future,
      }),
    });
    const aliveId = ((await alive.json()) as { Id: string }).Id;

    await fireCron("*/5 * * * *");

    const checkExpired = await req(`/api/sends/${expiredId}`, {
      headers: { authorization: `Bearer ${s.accessToken}` },
    });
    expect(checkExpired.status).toBe(404);

    const checkAlive = await req(`/api/sends/${aliveId}`, {
      headers: { authorization: `Bearer ${s.accessToken}` },
    });
    expect(checkAlive.status).toBe(200);

    await req(`/api/sends/${aliveId}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${s.accessToken}` },
    });
  });

  it("hourly cron does not crash with no work", async () => {
    await fireCron("0 * * * *");
  });

  it("daily cron does not crash with no work", async () => {
    await fireCron("0 0 * * *");
  });
});
