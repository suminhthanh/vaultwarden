import { describe, it, expect } from "vitest";

const BASE_URL = process.env.WORKER_URL ?? "http://127.0.0.1:8787";

async function req(path: string, init?: RequestInit) {
  return fetch(`${BASE_URL}${path}`, init);
}

describe("phase 2: PBKDF2-SHA256 password hashing/verification", () => {
  it("hashes a password, verifies it, rejects wrong password", async () => {
    const create = await req("/_test/users", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: `pw-${Date.now()}@example.com` }),
    });
    expect(create.status).toBe(200);
    const { uuid } = (await create.json()) as { uuid: string };

    const set = await req(`/_test/users/${uuid}/password`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ password: "correct horse battery staple" }),
    });
    expect(set.status).toBe(200);
    const summary = (await set.json()) as { password_hash_len: number; salt_len: number; iterations: number };
    expect(summary.password_hash_len).toBe(32);
    expect(summary.salt_len).toBe(64);
    expect(summary.iterations).toBe(600000);

    const ok = await req(`/_test/users/${uuid}/password/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ password: "correct horse battery staple" }),
    });
    expect(ok.status).toBe(200);
    expect(((await ok.json()) as { valid: boolean }).valid).toBe(true);

    const bad = await req(`/_test/users/${uuid}/password/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ password: "wrong password" }),
    });
    expect(bad.status).toBe(200);
    expect(((await bad.json()) as { valid: boolean }).valid).toBe(false);

    await req(`/_test/users/${uuid}`, { method: "DELETE" });
  });

  it("does not validate against an empty password_hash", async () => {
    const create = await req("/_test/users", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: `empty-${Date.now()}@example.com` }),
    });
    const { uuid } = (await create.json()) as { uuid: string };

    const verify = await req(`/_test/users/${uuid}/password/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ password: "anything" }),
    });
    expect(verify.status).toBe(200);
    expect(((await verify.json()) as { valid: boolean }).valid).toBe(false);

    await req(`/_test/users/${uuid}`, { method: "DELETE" });
  });
});
