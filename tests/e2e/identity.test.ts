import { describe, it, expect } from "vitest";

const BASE_URL = process.env.WORKER_URL ?? "http://127.0.0.1:8787";

async function req(path: string, init?: RequestInit) {
  return fetch(`${BASE_URL}${path}`, init);
}

function decodeJwtPayload(token: string): Record<string, unknown> {
  const parts = token.split(".");
  expect(parts).toHaveLength(3);
  const padded = parts[1] + "=".repeat((4 - (parts[1].length % 4)) % 4);
  const json = Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf-8");
  return JSON.parse(json);
}

async function setupUser(password: string) {
  const email = `id-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
  const r = await req("/_test/users", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email }),
  });
  expect(r.status).toBe(200);
  const { uuid } = (await r.json()) as { uuid: string };

  const set = await req(`/_test/users/${uuid}/password`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ password }),
  });
  expect(set.status).toBe(200);
  return { uuid, email };
}

function tokenForm(extra: Record<string, string>): URLSearchParams {
  const f = new URLSearchParams();
  f.set("grant_type", "password");
  f.set("scope", "api offline_access");
  f.set("client_id", "web");
  f.set("deviceIdentifier", "00000000-0000-4000-8000-000000000abc");
  f.set("deviceName", "Vitest");
  f.set("deviceType", "9");
  for (const [k, v] of Object.entries(extra)) f.set(k, v);
  return f;
}

describe("phase 2: /identity/connect/token (password grant)", () => {
  it("returns access_token, refresh_token, kdf metadata for valid credentials", async () => {
    const password = "correct horse battery staple";
    const user = await setupUser(password);

    const res = await req("/identity/connect/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: tokenForm({ username: user.email, password }).toString(),
    });
    expect(res.status).toBe(200);

    const body = (await res.json()) as Record<string, unknown>;
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBeGreaterThan(0);
    expect(typeof body.access_token).toBe("string");
    expect(typeof body.refresh_token).toBe("string");
    expect(body.Kdf).toBe(0);
    expect(body.KdfIterations).toBe(600000);
    expect(body.scope).toBe("api offline_access");

    const decryption = body.UserDecryptionOptions as Record<string, unknown>;
    expect(decryption.HasMasterPassword).toBe(true);
    expect(decryption.MasterPasswordUnlock).not.toBeNull();
    const unlock = decryption.MasterPasswordUnlock as Record<string, unknown>;
    expect((unlock.Kdf as Record<string, unknown>).KdfType).toBe(0);
    expect(unlock.MasterKeyEncryptedUserKey).toBeDefined();
    expect(unlock.MasterKeyWrappedUserKey).toBeDefined();
    expect(unlock.Salt).toBe(user.email);

    const claims = decodeJwtPayload(body.access_token as string);
    expect(claims.iss).toBe("http://localhost:8787|login");
    expect(claims.sub).toBe(user.uuid);
    expect(claims.email).toBe(user.email);
    expect(claims.device).toBe("00000000-0000-4000-8000-000000000abc");
    expect(claims.scope).toEqual(["api", "offline_access"]);
    expect(claims.amr).toEqual(["Application"]);

    await req(`/_test/users/${user.uuid}`, { method: "DELETE" });
  });

  it("rejects wrong password with invalid_grant", async () => {
    const user = await setupUser("right-password");

    const res = await req("/identity/connect/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: tokenForm({ username: user.email, password: "wrong-password" }).toString(),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_grant");

    await req(`/_test/users/${user.uuid}`, { method: "DELETE" });
  });

  it("rejects unknown user with invalid_grant (no user enumeration)", async () => {
    const res = await req("/identity/connect/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: tokenForm({ username: "nobody@example.com", password: "anything" }).toString(),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string; error_description: string };
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toMatch(/incorrect/i);
  });

  it("rejects missing scope with invalid_scope", async () => {
    const user = await setupUser("pw");
    const f = tokenForm({ username: user.email, password: "pw" });
    f.set("scope", "api");

    const res = await req("/identity/connect/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: f.toString(),
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe("invalid_scope");

    await req(`/_test/users/${user.uuid}`, { method: "DELETE" });
  });

  it("rejects unsupported grant_type", async () => {
    const f = tokenForm({ username: "x", password: "y" });
    f.set("grant_type", "implicit");

    const res = await req("/identity/connect/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: f.toString(),
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe("unsupported_grant_type");
  });

  it("rotates refresh_token on each successful login", async () => {
    const password = "p";
    const user = await setupUser(password);

    const r1 = await req("/identity/connect/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: tokenForm({ username: user.email, password }).toString(),
    });
    const b1 = (await r1.json()) as { refresh_token: string };

    const r2 = await req("/identity/connect/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: tokenForm({ username: user.email, password }).toString(),
    });
    const b2 = (await r2.json()) as { refresh_token: string };

    expect(b1.refresh_token).not.toEqual(b2.refresh_token);

    await req(`/_test/users/${user.uuid}`, { method: "DELETE" });
  });
});
