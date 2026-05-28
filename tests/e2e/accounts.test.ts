import { describe, it, expect } from "vitest";

const BASE_URL = process.env.WORKER_URL ?? "http://127.0.0.1:8787";

async function req(path: string, init?: RequestInit) {
  return fetch(`${BASE_URL}${path}`, init);
}

function tokenForm(extra: Record<string, string>): URLSearchParams {
  const f = new URLSearchParams();
  f.set("grant_type", "password");
  f.set("scope", "api offline_access");
  f.set("client_id", "web");
  f.set("deviceIdentifier", "00000000-0000-4000-8000-00000000acco");
  f.set("deviceName", "Vitest");
  f.set("deviceType", "9");
  for (const [k, v] of Object.entries(extra)) f.set(k, v);
  return f;
}

async function registerAndLogin(email: string, masterPasswordHashBytes: Uint8Array) {
  let bin = "";
  for (const b of masterPasswordHashBytes) bin += String.fromCharCode(b);
  const masterPasswordHashB64 = Buffer.from(bin, "binary").toString("base64");

  const reg = await req("/api/accounts/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      email,
      name: "Test User",
      masterPasswordHash: masterPasswordHashB64,
      masterPasswordHint: "rosebud",
      key: "0.encrypted-symmetric-key.value",
      keys: {
        publicKey: "MFw...stub",
        encryptedPrivateKey: "0.encrypted-private-key.value",
      },
      kdf: 0,
      kdfIterations: 600000,
    }),
  });
  expect(reg.status).toBe(200);

  // The server stores PBKDF2(masterPasswordHash, salt, kdfIterations) under password_hash,
  // and check_valid_password expects the bytes-as-Vec back. The Bitwarden client sends the
  // base64-encoded hash as the "password" in /identity. Our /identity reads it as a UTF-8
  // string and feeds those bytes through PBKDF2.
  const tokenRes = await req("/identity/connect/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: tokenForm({ username: email, password: masterPasswordHashB64 }).toString(),
  });
  return tokenRes;
}

describe("phase 2: /api/accounts/register and /profile", () => {
  it("registers a user, then can log in with the same masterPasswordHash", async () => {
    const email = `acct-${Date.now()}@example.com`;
    const hash = new Uint8Array(32);
    for (let i = 0; i < hash.length; i++) hash[i] = (i * 13 + 7) & 0xff;

    const tokenRes = await registerAndLogin(email, hash);
    expect(tokenRes.status).toBe(200);
    const body = (await tokenRes.json()) as { access_token: string; Key: string; PrivateKey: string };
    expect(body.access_token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(body.Key).toBe("0.encrypted-symmetric-key.value");
    expect(body.PrivateKey).toBe("0.encrypted-private-key.value");
  });

  it("rejects duplicate email registration", async () => {
    const email = `dup-${Date.now()}@example.com`;
    const hash = new Uint8Array([1, 2, 3, 4]);
    let bin = "";
    for (const b of hash) bin += String.fromCharCode(b);
    const hashB64 = Buffer.from(bin, "binary").toString("base64");

    const r1 = await req("/api/accounts/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, masterPasswordHash: hashB64, key: "k" }),
    });
    expect(r1.status).toBe(200);

    const r2 = await req("/api/accounts/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, masterPasswordHash: hashB64, key: "k" }),
    });
    expect(r2.status).toBe(400);
    expect(((await r2.json()) as { Message: string }).Message).toMatch(/already exists/i);
  });

  it("GET /api/accounts/profile requires Authorization, returns user data after login", async () => {
    const email = `prof-${Date.now()}@example.com`;
    const hash = new Uint8Array(32);
    for (let i = 0; i < hash.length; i++) hash[i] = i;
    const tokenRes = await registerAndLogin(email, hash);
    const { access_token } = (await tokenRes.json()) as { access_token: string };

    const noAuth = await req("/api/accounts/profile");
    expect(noAuth.status).toBe(401);

    const ok = await req("/api/accounts/profile", {
      headers: { authorization: `Bearer ${access_token}` },
    });
    expect(ok.status).toBe(200);
    const profile = (await ok.json()) as { Email: string; Object: string; Name: string };
    expect(profile.Object).toBe("profile");
    expect(profile.Email).toBe(email);
    expect(profile.Name).toBe("Test User");
  });

  it("PUT /api/accounts/profile updates name and password_hint", async () => {
    const email = `put-${Date.now()}@example.com`;
    const hash = new Uint8Array(32);
    const tokenRes = await registerAndLogin(email, hash);
    const { access_token } = (await tokenRes.json()) as { access_token: string };

    const put = await req("/api/accounts/profile", {
      method: "PUT",
      headers: { "content-type": "application/json", authorization: `Bearer ${access_token}` },
      body: JSON.stringify({ name: "Updated Name", masterPasswordHint: "new hint" }),
    });
    expect(put.status).toBe(200);
    const updated = (await put.json()) as { Name: string; MasterPasswordHint: string };
    expect(updated.Name).toBe("Updated Name");
    expect(updated.MasterPasswordHint).toBe("new hint");
  });
});

describe("phase 2: /identity/connect/token (refresh_token grant)", () => {
  it("refresh_token returns a fresh access_token and rotates the refresh_token", async () => {
    const email = `rt-${Date.now()}@example.com`;
    const hash = new Uint8Array(32);
    const r = await registerAndLogin(email, hash);
    const first = (await r.json()) as { refresh_token: string };

    const f = new URLSearchParams();
    f.set("grant_type", "refresh_token");
    f.set("refresh_token", first.refresh_token);
    f.set("client_id", "web");

    const res = await req("/identity/connect/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: f.toString(),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { access_token: string; refresh_token: string; scope: string };
    expect(body.access_token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(body.refresh_token).not.toBe(first.refresh_token);
    expect(body.scope).toBe("api offline_access");
  });

  it("rejects unknown refresh_token", async () => {
    const f = new URLSearchParams();
    f.set("grant_type", "refresh_token");
    f.set("refresh_token", "not-a-real-token");
    const res = await req("/identity/connect/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: f.toString(),
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe("invalid_grant");
  });

  it("rejects missing refresh_token with invalid_request", async () => {
    const f = new URLSearchParams();
    f.set("grant_type", "refresh_token");
    const res = await req("/identity/connect/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: f.toString(),
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe("invalid_request");
  });
});
