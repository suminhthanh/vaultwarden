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
  f.set("deviceIdentifier", `00000000-0000-4000-8000-000000orgc${Math.floor(Math.random() * 1000)}`);
  f.set("deviceName", "OrgCipherTest");
  f.set("deviceType", "9");
  for (const [k, v] of Object.entries(extra)) f.set(k, v);
  return f;
}

interface Session {
  email: string;
  userId: string;
  accessToken: string;
}

async function loggedIn(suffix: string): Promise<Session> {
  const email = `oc-${suffix}-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
  const hash = new Uint8Array(32);
  for (let i = 0; i < hash.length; i++) hash[i] = (i * 53 + 9) & 0xff;
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
  const profile = await req("/api/accounts/profile", { headers: { authorization: `Bearer ${body.access_token}` } });
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

async function makeOrgWithCollection(token: string): Promise<{ orgId: string; collId: string }> {
  const orgRes = await req(
    "/api/organizations",
    authJson(token, {
      method: "POST",
      body: JSON.stringify({ name: `Acme-${Math.random()}`, billingEmail: "ops@acme.test", key: "k" }),
    }),
  );
  const orgId = ((await orgRes.json()) as { Id: string }).Id;

  const collRes = await req(
    `/api/organizations/${orgId}/collections`,
    authJson(token, { method: "POST", body: JSON.stringify({ name: "Shared" }) }),
  );
  const collId = ((await collRes.json()) as { Id: string }).Id;

  return { orgId, collId };
}

describe("phase 5: org-shared ciphers", () => {
  let owner: Session;
  let member: Session;
  let outsider: Session;
  let orgId: string;
  let collId: string;

  beforeAll(async () => {
    [owner, member, outsider] = await Promise.all([loggedIn("o"), loggedIn("m"), loggedIn("x")]);
    ({ orgId, collId } = await makeOrgWithCollection(owner.accessToken));

    // Add `member` as a confirmed user of the org so they're treated as having access.
    const r = await req("/_test/memberships", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        user_uuid: member.userId,
        org_uuid: orgId,
        akey: "akey-bytes",
        atype: 2,
        status: 2,
      }),
    });
    expect(r.status).toBe(200);
  });

  it("rejects org cipher without collectionIds", async () => {
    const r = await req(
      "/api/ciphers",
      authJson(owner.accessToken, {
        method: "POST",
        body: JSON.stringify({
          type: 1,
          name: "Bad org cipher",
          login: { username: "u", password: "p" },
          organizationId: orgId,
        }),
      }),
    );
    expect(r.status).toBe(400);
    expect(((await r.json()) as { Message: string }).Message).toMatch(/collectionIds/i);
  });

  it("creates an org-owned cipher and links it to a collection", async () => {
    const r = await req(
      "/api/ciphers",
      authJson(owner.accessToken, {
        method: "POST",
        body: JSON.stringify({
          type: 1,
          name: "Shared login",
          login: { username: "shared", password: "secret" },
          organizationId: orgId,
          collectionIds: [collId],
        }),
      }),
    );
    expect(r.status).toBe(200);
    const c = (await r.json()) as { Id: string; OrganizationId: string; CollectionIds: string[] };
    expect(c.OrganizationId).toBe(orgId);
    expect(c.CollectionIds).toContain(collId);
  });

  it("/api/sync surfaces the org cipher to a confirmed member", async () => {
    const sync = await req("/api/sync", { headers: { authorization: `Bearer ${member.accessToken}` } });
    expect(sync.status).toBe(200);
    const body = (await sync.json()) as {
      Ciphers: Array<{ Id: string; OrganizationId: string | null; CollectionIds: string[]; Name: string }>;
    };
    const shared = body.Ciphers.find((c) => c.OrganizationId === orgId);
    expect(shared, "expected member to see the org cipher").toBeTruthy();
    expect(shared!.CollectionIds).toContain(collId);
  });

  it("/api/sync does NOT surface the org cipher to an outsider", async () => {
    const sync = await req("/api/sync", { headers: { authorization: `Bearer ${outsider.accessToken}` } });
    const body = (await sync.json()) as { Ciphers: Array<{ OrganizationId: string | null }> };
    expect(body.Ciphers.find((c) => c.OrganizationId === orgId)).toBeUndefined();
  });

  it("non-member gets 404 trying to read the org cipher directly", async () => {
    const list = await req("/api/sync", { headers: { authorization: `Bearer ${owner.accessToken}` } });
    const sharedId = ((await list.json()) as { Ciphers: Array<{ Id: string; OrganizationId: string | null }> }).Ciphers
      .find((c) => c.OrganizationId === orgId)!.Id;

    const peek = await req(`/api/ciphers/${sharedId}`, {
      headers: { authorization: `Bearer ${outsider.accessToken}` },
    });
    expect(peek.status).toBe(404);
  });
});
