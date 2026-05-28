import { describe, it, expect, beforeAll } from "vitest";
import { createHmac } from "node:crypto";

const BASE_URL = process.env.WORKER_URL ?? "http://127.0.0.1:8787";

async function req(path: string, init?: RequestInit) {
  return fetch(`${BASE_URL}${path}`, init);
}

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Decode(input: string): Buffer {
  const cleaned = input.replace(/=+$/g, "").toUpperCase();
  let bits = "";
  for (const ch of cleaned) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error(`bad b32 char: ${ch}`);
    bits += idx.toString(2).padStart(5, "0");
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

function totp(keyB32: string, time: number): string {
  const counter = Math.floor(time / 30);
  const buf = Buffer.alloc(8);
  buf.writeBigInt64BE(BigInt(counter));
  const key = base32Decode(keyB32);
  const h = createHmac("sha1", key).update(buf).digest();
  const offset = h[19] & 0x0f;
  const code =
    ((h[offset] & 0x7f) << 24) |
    ((h[offset + 1] & 0xff) << 16) |
    ((h[offset + 2] & 0xff) << 8) |
    (h[offset + 3] & 0xff);
  return (code % 1_000_000).toString().padStart(6, "0");
}

function tokenForm(extra: Record<string, string>): URLSearchParams {
  const f = new URLSearchParams();
  f.set("grant_type", "password");
  f.set("scope", "api offline_access");
  f.set("client_id", "web");
  f.set("deviceIdentifier", "00000000-0000-4000-8000-00000000tot1");
  f.set("deviceName", "TotpTest");
  f.set("deviceType", "9");
  for (const [k, v] of Object.entries(extra)) f.set(k, v);
  return f;
}

interface Session {
  email: string;
  passwordHashB64: string;
  accessToken: string;
}

async function loggedIn(suffix: string): Promise<Session> {
  const email = `tf-${suffix}-${Date.now()}@example.com`;
  const hash = new Uint8Array(32);
  for (let i = 0; i < hash.length; i++) hash[i] = (i * 23 + 1) & 0xff;
  let bin = "";
  for (const b of hash) bin += String.fromCharCode(b);
  const hashB64 = Buffer.from(bin, "binary").toString("base64");

  const reg = await req("/api/accounts/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, masterPasswordHash: hashB64, key: "0.k" }),
  });
  expect(reg.status).toBe(200);
  const login = await req("/identity/connect/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: tokenForm({ username: email, password: hashB64 }).toString(),
  });
  const body = (await login.json()) as { access_token: string };
  return { email, passwordHashB64: hashB64, accessToken: body.access_token };
}

describe("phase 2: /api/two-factor (TOTP authenticator)", () => {
  let s: Session;
  beforeAll(async () => {
    s = await loggedIn("auth");
  });

  it("get-authenticator returns a fresh base32 secret when none enabled", async () => {
    const r = await req("/api/two-factor/get-authenticator", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${s.accessToken}` },
      body: JSON.stringify({ masterPasswordHash: s.passwordHashB64 }),
    });
    expect(r.status).toBe(200);
    const body = (await r.json()) as { Object: string; Enabled: boolean; Key: string };
    expect(body.Object).toBe("twoFactorAuthenticator");
    expect(body.Enabled).toBe(false);
    expect(body.Key).toMatch(/^[A-Z2-7]{32}$/);
  });

  it("activate with a valid TOTP code, then list-methods reports it enabled", async () => {
    const get = await req("/api/two-factor/get-authenticator", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${s.accessToken}` },
      body: JSON.stringify({ masterPasswordHash: s.passwordHashB64 }),
    });
    const { Key: key } = (await get.json()) as { Key: string };

    const code = totp(key, Math.floor(Date.now() / 1000));

    const activate = await req("/api/two-factor/authenticator", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${s.accessToken}` },
      body: JSON.stringify({ key, token: code, masterPasswordHash: s.passwordHashB64 }),
    });
    expect(activate.status).toBe(200);
    const body = (await activate.json()) as { Enabled: boolean };
    expect(body.Enabled).toBe(true);

    const list = await req("/api/two-factor", { headers: { authorization: `Bearer ${s.accessToken}` } });
    const listed = (await list.json()) as { Data: Array<{ Type: number; Enabled: boolean }> };
    const totpRow = listed.Data.find((d) => d.Type === 0);
    expect(totpRow?.Enabled).toBe(true);
  });

  it("activate rejects an invalid code", async () => {
    const fresh = await loggedIn("bad");
    const get = await req("/api/two-factor/get-authenticator", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${fresh.accessToken}` },
      body: JSON.stringify({ masterPasswordHash: fresh.passwordHashB64 }),
    });
    const { Key: key } = (await get.json()) as { Key: string };

    const bad = await req("/api/two-factor/authenticator", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${fresh.accessToken}` },
      body: JSON.stringify({ key, token: "000000", masterPasswordHash: fresh.passwordHashB64 }),
    });
    expect(bad.status).toBe(400);
    expect(((await bad.json()) as { Message: string }).Message).toMatch(/Invalid TOTP/i);
  });

  it("disable removes the authenticator factor", async () => {
    const fresh = await loggedIn("dis");
    const get = await req("/api/two-factor/get-authenticator", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${fresh.accessToken}` },
      body: JSON.stringify({ masterPasswordHash: fresh.passwordHashB64 }),
    });
    const { Key: key } = (await get.json()) as { Key: string };
    await req("/api/two-factor/authenticator", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${fresh.accessToken}` },
      body: JSON.stringify({
        key,
        token: totp(key, Math.floor(Date.now() / 1000)),
        masterPasswordHash: fresh.passwordHashB64,
      }),
    });

    const off = await req("/api/two-factor/authenticator", {
      method: "DELETE",
      headers: { "content-type": "application/json", authorization: `Bearer ${fresh.accessToken}` },
      body: JSON.stringify({ masterPasswordHash: fresh.passwordHashB64 }),
    });
    expect(off.status).toBe(200);
    const body = (await off.json()) as { Enabled: boolean };
    expect(body.Enabled).toBe(false);

    const list = await req("/api/two-factor", { headers: { authorization: `Bearer ${fresh.accessToken}` } });
    const listed = (await list.json()) as { Data: Array<{ Type: number }> };
    expect(listed.Data.find((d) => d.Type === 0)).toBeUndefined();
  });

  it("get-authenticator rejects wrong master password", async () => {
    const fresh = await loggedIn("wrongpw");
    const r = await req("/api/two-factor/get-authenticator", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${fresh.accessToken}` },
      body: JSON.stringify({ masterPasswordHash: "definitely-not-the-password" }),
    });
    expect(r.status).toBe(401);
  });
});
