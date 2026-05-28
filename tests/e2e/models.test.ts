import { describe, it, expect } from "vitest";

const BASE_URL = process.env.WORKER_URL ?? "http://127.0.0.1:8787";

async function req(path: string, init?: RequestInit) {
  return fetch(`${BASE_URL}${path}`, init);
}

async function createUser(suffix: string) {
  const email = `models-${suffix}@example.com`;
  const r = await req("/_test/users", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email }),
  });
  expect(r.status).toBe(200);
  return (await r.json()) as { uuid: string };
}

async function createOrg(suffix: string) {
  const r = await req("/_test/orgs", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: `Org ${suffix}`, billing_email: `billing-${suffix}@example.com` }),
  });
  expect(r.status).toBe(200);
  return (await r.json()) as { uuid: string };
}

describe("phase 1 batch: Folder / Organization / Membership round-trip", () => {
  it("Folder: create, get, list-by-user, delete", async () => {
    const user = await createUser(`folder-${Date.now()}`);

    const create = await req("/_test/folders", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ user_uuid: user.uuid, name: "Personal" }),
    });
    expect(create.status).toBe(200);
    const created = (await create.json()) as { uuid: string; name: string; user_uuid: string };
    expect(created.name).toBe("Personal");
    expect(created.user_uuid).toBe(user.uuid);

    const got = await req(`/_test/folders/${created.uuid}`);
    expect(got.status).toBe(200);

    const list = await req(`/_test/users/${user.uuid}/folders`);
    expect(list.status).toBe(200);
    const folders = (await list.json()) as Array<{ uuid: string }>;
    expect(folders).toHaveLength(1);
    expect(folders[0].uuid).toBe(created.uuid);

    const del = await req(`/_test/folders/${created.uuid}`, { method: "DELETE" });
    expect(del.status).toBe(204);

    await req(`/_test/users/${user.uuid}`, { method: "DELETE" });
  });

  it("Organization: create, get, delete", async () => {
    const org = await createOrg(`a-${Date.now()}`);

    const got = await req(`/_test/orgs/${org.uuid}`);
    expect(got.status).toBe(200);
    const fetched = (await got.json()) as { uuid: string; billing_email: string };
    expect(fetched.uuid).toBe(org.uuid);
    expect(fetched.billing_email).toMatch(/^billing-a-/);

    const del = await req(`/_test/orgs/${org.uuid}`, { method: "DELETE" });
    expect(del.status).toBe(204);

    const after = await req(`/_test/orgs/${org.uuid}`);
    expect(after.status).toBe(404);
  });

  it("Membership: link a user to an org and look up by (org, user)", async () => {
    const user = await createUser(`memb-${Date.now()}`);
    const org = await createOrg(`memb-${Date.now()}`);

    const create = await req("/_test/memberships", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        user_uuid: user.uuid,
        org_uuid: org.uuid,
        akey: "akey-bytes",
        atype: 2,
        status: 2,
      }),
    });
    expect(create.status).toBe(200);
    const m = (await create.json()) as { uuid: string; atype: number; status: number };
    expect(m.atype).toBe(2);
    expect(m.status).toBe(2);

    const lookup = await req(`/_test/orgs/${org.uuid}/memberships/by-user/${user.uuid}`);
    expect(lookup.status).toBe(200);
    const found = (await lookup.json()) as { uuid: string };
    expect(found.uuid).toBe(m.uuid);

    // Cleanup: D1 has no ON DELETE CASCADE on these refs, so delete the membership
    // first, otherwise users_organizations rows pin the parent rows.
    const delMembership = await req(`/_test/memberships/${m.uuid}`, { method: "DELETE" });
    expect(delMembership.status).toBe(204);
    const delOrg = await req(`/_test/orgs/${org.uuid}`, { method: "DELETE" });
    expect(delOrg.status).toBe(204);
    const delUser = await req(`/_test/users/${user.uuid}`, { method: "DELETE" });
    expect(delUser.status).toBe(204);
  });
});
