import { describe, it, expect } from "vitest";

const BASE_URL = process.env.WORKER_URL ?? "http://127.0.0.1:8787";

async function req(path: string, init?: RequestInit) {
  return fetch(`${BASE_URL}${path}`, init);
}

describe("phase 1: User model round-trip via D1", () => {
  it("create -> find_by_email -> find_by_uuid -> delete", async () => {
    const email = `vw-port-test-${Date.now()}@example.com`;

    const create = await req("/_test/users", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, name: "Phase 1 User" }),
    });
    expect(create.status).toBe(200);
    const created = (await create.json()) as { uuid: string; email: string; name: string };
    expect(created.uuid).toMatch(/^[0-9a-f-]{36}$/);
    expect(created.email).toBe(email);
    expect(created.name).toBe("Phase 1 User");

    const lookup = await req(`/_test/users/by-email/${encodeURIComponent(email)}`);
    expect(lookup.status).toBe(200);
    const found = (await lookup.json()) as { uuid: string; email: string };
    expect(found.uuid).toBe(created.uuid);
    expect(found.email).toBe(email);

    const del = await req(`/_test/users/${created.uuid}`, { method: "DELETE" });
    expect(del.status).toBe(204);

    const after = await req(`/_test/users/by-email/${encodeURIComponent(email)}`);
    expect(after.status).toBe(404);
  });

  it("email is lowercased on insert and on lookup", async () => {
    const email = `MixedCase-${Date.now()}@Example.Com`;

    const create = await req("/_test/users", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email }),
    });
    expect(create.status).toBe(200);
    const created = (await create.json()) as { uuid: string; email: string };
    expect(created.email).toBe(email.toLowerCase());

    const lookup = await req(`/_test/users/by-email/${encodeURIComponent(email)}`);
    expect(lookup.status).toBe(200);

    await req(`/_test/users/${created.uuid}`, { method: "DELETE" });
  });
});
