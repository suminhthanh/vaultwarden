import { describe, it, expect } from "vitest";
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
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}
function totp(keyB32: string, time: number): string {
  const counter = Math.floor(time / 30);
  const buf = Buffer.alloc(8);
  buf.writeBigInt64BE(BigInt(counter));
  const h = createHmac("sha1", base32Decode(keyB32)).update(buf).digest();
  const offset = h[19] & 0x0f;
  const code =
    ((h[offset] & 0x7f) << 24) | ((h[offset + 1] & 0xff) << 16) | ((h[offset + 2] & 0xff) << 8) | (h[offset + 3] & 0xff);
  return (code % 1_000_000).toString().padStart(6, "0");
}

function tokenForm(extra: Record<string, string>): URLSearchParams {
  const f = new URLSearchParams();
  f.set("grant_type", "password");
  f.set("scope", "api offline_access");
  f.set("client_id", "web");
  f.set("deviceIdentifier", "00000000-0000-4000-8000-000000002fac");
  f.set("deviceName", "TwoFAChal");
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
  const email = `2fac-${suffix}-${Date.now()}@example.com`;
  const hash = new Uint8Array(32);
  for (let i = 0; i < hash.length; i++) hash[i] = (i * 47 + 11) & 0xff;
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
  return { email, passwordHashB64: hashB64, accessToken: ((await login.json()) as { access_token: string }).access_token };
}

async function enableTotp(s: Session): Promise<string> {
  const get = await req("/api/two-factor/get-authenticator", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${s.accessToken}` },
    body: JSON.stringify({ masterPasswordHash: s.passwordHashB64 }),
  });
  const { Key } = (await get.json()) as { Key: string };
  const code = totp(Key, Math.floor(Date.now() / 1000));
  const activate = await req("/api/two-factor/authenticator", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${s.accessToken}` },
    body: JSON.stringify({ key: Key, token: code, masterPasswordHash: s.passwordHashB64 }),
  });
  expect(activate.status).toBe(200);
  return Key;
}

describe("phase 5: /identity/connect/token enforces 2FA challenge", () => {
  it("user without 2FA can still login normally", async () => {
    const s = await loggedIn("none");
    const r = await req("/identity/connect/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: tokenForm({ username: s.email, password: s.passwordHashB64 }).toString(),
    });
    expect(r.status).toBe(200);
  });

  it("user with TOTP enabled gets TwoFactorRequired without code", async () => {
    const s = await loggedIn("required");
    await enableTotp(s);

    const r = await req("/identity/connect/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: tokenForm({ username: s.email, password: s.passwordHashB64 }).toString(),
    });
    expect(r.status).toBe(400);
    const body = (await r.json()) as { error: string; TwoFactorProviders: string[]; TwoFactorProviders2: Record<string, unknown> };
    expect(body.error).toBe("invalid_grant");
    expect(body.TwoFactorProviders).toContain("0");
    expect(body.TwoFactorProviders2["0"]).toBeNull();
  });

  it("retrying with valid TOTP code returns access_token", async () => {
    const s = await loggedIn("retry");
    const key = await enableTotp(s);

    const code = totp(key, Math.floor(Date.now() / 1000));
    const r = await req("/identity/connect/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: tokenForm({
        username: s.email,
        password: s.passwordHashB64,
        twoFactorProvider: "0",
        twoFactorToken: code,
      }).toString(),
    });
    expect(r.status).toBe(200);
    const body = (await r.json()) as { access_token: string };
    expect(body.access_token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  });

  it("retrying with wrong TOTP code rejects", async () => {
    const s = await loggedIn("wrong");
    await enableTotp(s);

    const r = await req("/identity/connect/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: tokenForm({
        username: s.email,
        password: s.passwordHashB64,
        twoFactorProvider: "0",
        twoFactorToken: "000000",
      }).toString(),
    });
    expect(r.status).toBe(400);
    const body = (await r.json()) as { error: string; error_description: string };
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toMatch(/two-factor/i);
  });

  it("unknown provider id is rejected with TwoFactorRequired", async () => {
    const s = await loggedIn("badprov");
    await enableTotp(s);

    const r = await req("/identity/connect/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: tokenForm({
        username: s.email,
        password: s.passwordHashB64,
        twoFactorProvider: "99",
        twoFactorToken: "123456",
      }).toString(),
    });
    expect(r.status).toBe(400);
    const body = (await r.json()) as { TwoFactorProviders: string[] };
    expect(body.TwoFactorProviders).toContain("0");
  });
});
