import { describe, it, expect } from "vitest";

const BASE_URL = process.env.WORKER_URL ?? "http://127.0.0.1:8787";

async function req(path: string, init?: RequestInit) {
  return fetch(`${BASE_URL}${path}`, init);
}

function bytesToB64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return Buffer.from(s, "binary").toString("base64");
}

describe("phase 2: D1 BLOB column round-trip", () => {
  it("set password_hash + salt as bytes, read them back identically", async () => {
    const create = await req("/_test/users", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: `blob-${Date.now()}@example.com` }),
    });
    expect(create.status).toBe(200);
    const { uuid } = (await create.json()) as { uuid: string };

    const hash = new Uint8Array(32);
    const salt = new Uint8Array(64);
    for (let i = 0; i < hash.length; i++) hash[i] = (i * 7 + 3) & 0xff;
    for (let i = 0; i < salt.length; i++) salt[i] = (i * 11 + 5) & 0xff;

    const put = await req(`/_test/users/${uuid}/secrets`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        password_hash_b64: bytesToB64(hash),
        salt_b64: bytesToB64(salt),
      }),
    });
    expect(put.status).toBe(200);

    const get = await req(`/_test/users/${uuid}/secrets`);
    expect(get.status).toBe(200);
    const got = (await get.json()) as {
      password_hash_b64: string;
      salt_b64: string;
      password_hash_len: number;
      salt_len: number;
    };
    expect(got.password_hash_len).toBe(32);
    expect(got.salt_len).toBe(64);
    expect(got.password_hash_b64).toBe(bytesToB64(hash));
    expect(got.salt_b64).toBe(bytesToB64(salt));

    await req(`/_test/users/${uuid}`, { method: "DELETE" });
  });
});
