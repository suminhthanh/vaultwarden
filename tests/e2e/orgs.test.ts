import { describe, it, expect, beforeAll } from "vitest";

const BASE_URL = process.env.WORKER_URL ?? "http://127.0.0.1:8787";

async function req(path: string, init?: RequestInit) {
  return fetch(`${BASE_URL}${path}`, init);
}

function tokenForm(extra: Record<string, string>): URLSearchParams {
  const f = new URLSearchParams();
  f.set("grant_type", "password");
  f.set("scope", "api offline_access");
  f.set("client_id", "web");
  f.set("deviceIdentifier", `00000000-0000-4000-8000-00000000o${(extra.username ?? "").length}`);
  f.set("deviceName", "Vitest");
  f.set("deviceType", "9");
  for (const [k, v] of Object.entries(extra)) f.set(k, v);
  return f;
}

interface Session {
  email: string;
  userId: string;
  accessToken: string;
}

async function loggedInUser(suffix: string): Promise<Session> {
  const email = `org-${suffix}-${Date.now()}@example.com`;
  const hash = new Uint8Array(32);
  for (let i = 0; i < hash.length; i++) hash[i] = (i * 19 + suffix.length) & 0xff;
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
  const body = (await login.json()) as { access_token: string };
  const profile = await req("/api/accounts/profile", {
    headers: { authorization: `Bearer ${body.access_token}` },
  });
  return { email, userId: ((await profile.json()) as { Id: string }).Id, accessToken: body.access_token };
}

function authJson(token: string, extra: RequestInit = {}): RequestInit {
  return {
    ...extra,
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${token}`,
      ...(extra.headers ?? {}),
    },
  };
}

describe("phase 2: organizations + collections", () => {
  let s: Session;
  beforeAll(async () => {
    s = await loggedInUser("a");
  });

  it("creates an organization, sees it in /api/sync, can fetch /api/organizations/{id}", async () => {
    const create = await req(
      "/api/organizations",
      authJson(s.accessToken, {
        method: "POST",
        body: JSON.stringify({
          name: "Acme",
          billingEmail: "billing@acme.test",
          key: "encrypted-org-key",
          keys: { publicKey: "pub", encryptedPrivateKey: "priv" },
        }),
      }),
    );
    expect(create.status).toBe(200);
    const org = (await create.json()) as { Id: string; Name: string; Object: string };
    expect(org.Object).toBe("organization");
    expect(org.Name).toBe("Acme");

    const get = await req(`/api/organizations/${org.Id}`, {
      headers: { authorization: `Bearer ${s.accessToken}` },
    });
    expect(get.status).toBe(200);

    const sync = await req("/api/sync", { headers: { authorization: `Bearer ${s.accessToken}` } });
    const body = (await sync.json()) as {
      Profile: { Organizations: Array<{ Id: string; Type: number; Status: number }> };
    };
    const inProfile = body.Profile.Organizations.find((o) => o.Id === org.Id);
    expect(inProfile).toBeTruthy();
    expect(inProfile!.Type).toBe(0);
    expect(inProfile!.Status).toBe(2);
  });

  it("non-member cannot read another org", async () => {
    const owner = await loggedInUser("b");
    const intruder = await loggedInUser("c");

    const create = await req(
      "/api/organizations",
      authJson(owner.accessToken, {
        method: "POST",
        body: JSON.stringify({ name: "Private", billingEmail: "owner@x.test", key: "k" }),
      }),
    );
    const { Id } = (await create.json()) as { Id: string };

    const peek = await req(`/api/organizations/${Id}`, {
      headers: { authorization: `Bearer ${intruder.accessToken}` },
    });
    expect(peek.status).toBe(404);

    const peekKeys = await req(`/api/organizations/${Id}/keys`, {
      headers: { authorization: `Bearer ${intruder.accessToken}` },
    });
    expect(peekKeys.status).toBe(404);
  });

  it("collections: create, list, get, update, delete inside an org", async () => {
    const create = await req(
      "/api/organizations",
      authJson(s.accessToken, {
        method: "POST",
        body: JSON.stringify({ name: "Coll Test", billingEmail: "ct@x.test", key: "k" }),
      }),
    );
    const orgId = ((await create.json()) as { Id: string }).Id;

    const post = await req(
      `/api/organizations/${orgId}/collections`,
      authJson(s.accessToken, {
        method: "POST",
        body: JSON.stringify({ name: "Engineering", externalId: "ext-1" }),
      }),
    );
    expect(post.status).toBe(200);
    const col = (await post.json()) as { Id: string; Name: string; OrganizationId: string };
    expect(col.Name).toBe("Engineering");
    expect(col.OrganizationId).toBe(orgId);

    const list = await req(`/api/organizations/${orgId}/collections`, {
      headers: { authorization: `Bearer ${s.accessToken}` },
    });
    expect(list.status).toBe(200);
    const listed = (await list.json()) as { Data: Array<{ Id: string }> };
    expect(listed.Data.find((x) => x.Id === col.Id)).toBeTruthy();

    const all = await req("/api/collections", { headers: { authorization: `Bearer ${s.accessToken}` } });
    expect(all.status).toBe(200);
    const allListed = (await all.json()) as { Data: Array<{ Id: string }> };
    expect(allListed.Data.find((x) => x.Id === col.Id)).toBeTruthy();

    const upd = await req(
      `/api/organizations/${orgId}/collections/${col.Id}`,
      authJson(s.accessToken, {
        method: "PUT",
        body: JSON.stringify({ name: "Eng Renamed", externalId: "ext-2" }),
      }),
    );
    expect(upd.status).toBe(200);
    expect(((await upd.json()) as { Name: string; ExternalId: string }).Name).toBe("Eng Renamed");

    const del = await req(`/api/organizations/${orgId}/collections/${col.Id}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${s.accessToken}` },
    });
    expect(del.status).toBe(200);

    const after = await req(`/api/organizations/${orgId}/collections/${col.Id}`, {
      headers: { authorization: `Bearer ${s.accessToken}` },
    });
    expect(after.status).toBe(404);
  });

  it("non-member cannot create a collection in someone else's org", async () => {
    const owner = await loggedInUser("d");
    const intruder = await loggedInUser("e");

    const create = await req(
      "/api/organizations",
      authJson(owner.accessToken, {
        method: "POST",
        body: JSON.stringify({ name: "Closed", billingEmail: "owner@d.test", key: "k" }),
      }),
    );
    const orgId = ((await create.json()) as { Id: string }).Id;

    const attempt = await req(
      `/api/organizations/${orgId}/collections`,
      authJson(intruder.accessToken, {
        method: "POST",
        body: JSON.stringify({ name: "Sneaky" }),
      }),
    );
    expect(attempt.status).toBe(404);
  });

  it("/api/sync returns the user's collections", async () => {
    const create = await req(
      "/api/organizations",
      authJson(s.accessToken, {
        method: "POST",
        body: JSON.stringify({ name: "SyncCols", billingEmail: "sync@x.test", key: "k" }),
      }),
    );
    const orgId = ((await create.json()) as { Id: string }).Id;
    await req(
      `/api/organizations/${orgId}/collections`,
      authJson(s.accessToken, {
        method: "POST",
        body: JSON.stringify({ name: "SyncedCol" }),
      }),
    );

    const sync = await req("/api/sync", { headers: { authorization: `Bearer ${s.accessToken}` } });
    const body = (await sync.json()) as { Collections: Array<{ Name: string; OrganizationId: string }> };
    const inSync = body.Collections.find((c) => c.OrganizationId === orgId);
    expect(inSync?.Name).toBe("SyncedCol");
  });
});
