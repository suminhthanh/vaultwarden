import { describe, it, expect } from "vitest";

const BASE_URL = process.env.WORKER_URL ?? "http://127.0.0.1:8787";

async function req(path: string, init?: RequestInit) {
  return fetch(`${BASE_URL}${path}`, init);
}

describe("phase 5: prelogin (KDF parameters lookup)", () => {
  it("/identity/accounts/prelogin returns defaults for unknown email", async () => {
    const r = await req("/identity/accounts/prelogin", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: `nobody-${Date.now()}@example.com` }),
    });
    expect(r.status).toBe(200);
    const body = (await r.json()) as { kdf: number; kdfIterations: number };
    expect(body.kdf).toBe(0);
    expect(body.kdfIterations).toBe(600000);
  });

  it("/identity/accounts/prelogin/password is an alias for prelogin", async () => {
    const r = await req("/identity/accounts/prelogin/password", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: `also-nobody-${Date.now()}@example.com` }),
    });
    expect(r.status).toBe(200);
    const body = (await r.json()) as { kdf: number; kdfIterations: number };
    expect(body.kdf).toBe(0);
    expect(body.kdfIterations).toBe(600000);
  });

  it("returns the actual user's KDF settings after registration", async () => {
    const email = `pre-${Date.now()}@example.com`;
    const reg = await req("/api/accounts/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        email,
        masterPasswordHash: "AAAA",
        key: "k",
        kdf: 1,
        kdfIterations: 3,
        kdfMemory: 64,
        kdfParallelism: 4,
      }),
    });
    expect(reg.status).toBe(200);

    const r = await req("/identity/accounts/prelogin/password", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email }),
    });
    expect(r.status).toBe(200);
    const body = (await r.json()) as {
      kdf: number;
      kdfIterations: number;
      kdfMemory: number | null;
      kdfParallelism: number | null;
    };
    expect(body.kdf).toBe(1);
    expect(body.kdfIterations).toBe(3);
    expect(body.kdfMemory).toBe(64);
    expect(body.kdfParallelism).toBe(4);
  });
});
