import { describe, it, expect } from "vitest";

const BASE_URL = process.env.WORKER_URL ?? "http://127.0.0.1:8787";

async function req(path: string, init?: RequestInit) {
  return fetch(`${BASE_URL}${path}`, init);
}

async function createUser(suffix: string) {
  const email = `cipher-test-${suffix}@example.com`;
  const res = await req("/_test/users", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, name: "Cipher Test" }),
  });
  expect(res.status).toBe(200);
  return (await res.json()) as { uuid: string };
}

describe("phase 1: Cipher model round-trip via D1", () => {
  it("create -> get -> list-by-user -> delete", async () => {
    const user = await createUser(`a-${Date.now()}`);

    const create = await req("/_test/ciphers", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        user_uuid: user.uuid,
        atype: 1,
        name: "Bank login",
        data: '{"username":"alice"}',
      }),
    });
    expect(create.status).toBe(200);
    const created = (await create.json()) as { uuid: string; user_uuid: string; name: string; atype: number };
    expect(created.uuid).toMatch(/^[0-9a-f-]{36}$/);
    expect(created.user_uuid).toBe(user.uuid);
    expect(created.name).toBe("Bank login");
    expect(created.atype).toBe(1);

    const get = await req(`/_test/ciphers/${created.uuid}`);
    expect(get.status).toBe(200);
    const fetched = (await get.json()) as { uuid: string; data: string };
    expect(fetched.uuid).toBe(created.uuid);
    expect(fetched.data).toBe('{"username":"alice"}');

    const list = await req(`/_test/users/${user.uuid}/ciphers`);
    expect(list.status).toBe(200);
    const ciphers = (await list.json()) as Array<{ uuid: string }>;
    expect(ciphers).toHaveLength(1);
    expect(ciphers[0].uuid).toBe(created.uuid);

    const del = await req(`/_test/ciphers/${created.uuid}`, { method: "DELETE" });
    expect(del.status).toBe(204);

    const after = await req(`/_test/ciphers/${created.uuid}`);
    expect(after.status).toBe(404);

    await req(`/_test/users/${user.uuid}`, { method: "DELETE" });
  });

  it("creating two ciphers under one user returns both in list", async () => {
    const user = await createUser(`b-${Date.now()}`);

    for (const name of ["Email", "Server"]) {
      const r = await req("/_test/ciphers", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ user_uuid: user.uuid, atype: 1, name, data: "{}" }),
      });
      expect(r.status).toBe(200);
    }

    const list = await req(`/_test/users/${user.uuid}/ciphers`);
    expect(list.status).toBe(200);
    const ciphers = (await list.json()) as Array<{ name: string }>;
    expect(ciphers).toHaveLength(2);
    expect(ciphers.map((c) => c.name).sort()).toEqual(["Email", "Server"]);

    for (const c of ciphers as Array<{ uuid: string }>) {
      await req(`/_test/ciphers/${c.uuid}`, { method: "DELETE" });
    }
    await req(`/_test/users/${user.uuid}`, { method: "DELETE" });
  });
});
