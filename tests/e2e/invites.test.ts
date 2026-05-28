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
  f.set("deviceIdentifier", `00000000-0000-4000-8000-0000inv${Math.floor(Math.random() * 100000).toString().padStart(5, "0")}`);
  f.set("deviceName", "InviteTest");
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
  const email = `inv-${suffix}-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
  const hash = new Uint8Array(32);
  for (let i = 0; i < hash.length; i++) hash[i] = (i * 59 + 13) & 0xff;
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

describe("phase 5: org invite/accept/confirm", () => {
  let owner: Session;
  let invitee: Session;
  let orgId: string;

  beforeAll(async () => {
    [owner, invitee] = await Promise.all([loggedIn("o"), loggedIn("i")]);
    const r = await req(
      "/api/organizations",
      authJson(owner.accessToken, {
        method: "POST",
        body: JSON.stringify({ name: `Acme-${Date.now()}`, billingEmail: "ops@acme.test", key: "k" }),
      }),
    );
    orgId = ((await r.json()) as { Id: string }).Id;
  });

  it("invite -> accept -> confirm round-trip", async () => {
    // Invite
    const inv = await req(
      `/api/organizations/${orgId}/users/invite`,
      authJson(owner.accessToken, { method: "POST", body: JSON.stringify({ emails: [invitee.email], type: 2 }) }),
    );
    expect(inv.status).toBe(200);
    expect(((await inv.json()) as { Invited: number }).Invited).toBe(1);

    // List members so we can grab the membership ID
    const list = await req(`/api/organizations/${orgId}/users`, {
      headers: { authorization: `Bearer ${owner.accessToken}` },
    });
    expect(list.status).toBe(200);
    const members = (await list.json()) as { Data: Array<{ Id: string; UserId: string; Status: number }> };
    const me = members.Data.find((m) => m.UserId === invitee.userId);
    expect(me).toBeTruthy();
    expect(me!.Status).toBe(0);

    // Invitee accepts
    const accept = await req(
      `/api/organizations/${orgId}/users/${me!.Id}/accept`,
      authJson(invitee.accessToken, { method: "POST", body: JSON.stringify({}) }),
    );
    expect(accept.status).toBe(200);

    // Owner confirms with the encrypted org key
    const confirm = await req(
      `/api/organizations/${orgId}/users/${me!.Id}/confirm`,
      authJson(owner.accessToken, {
        method: "POST",
        body: JSON.stringify({ key: "encrypted-org-key-for-invitee" }),
      }),
    );
    expect(confirm.status).toBe(200);

    // Sync should now expose the org to the invitee
    const sync = await req("/api/sync", { headers: { authorization: `Bearer ${invitee.accessToken}` } });
    const synced = (await sync.json()) as { Profile: { Organizations: Array<{ Id: string; Status: number }> } };
    const inProfile = synced.Profile.Organizations.find((o) => o.Id === orgId);
    expect(inProfile?.Status).toBe(2);
  });

  it("non-owner cannot invite", async () => {
    const stranger = await loggedIn("s");
    const r = await req(
      `/api/organizations/${orgId}/users/invite`,
      authJson(stranger.accessToken, { method: "POST", body: JSON.stringify({ emails: ["someone@x.test"] }) }),
    );
    expect(r.status).toBe(404);
  });

  it("invitee cannot accept someone else's invite", async () => {
    const victim = await loggedIn("v");
    const inviteBody = await req(
      `/api/organizations/${orgId}/users/invite`,
      authJson(owner.accessToken, { method: "POST", body: JSON.stringify({ emails: [victim.email], type: 2 }) }),
    );
    expect(inviteBody.status).toBe(200);

    const list = await req(`/api/organizations/${orgId}/users`, {
      headers: { authorization: `Bearer ${owner.accessToken}` },
    });
    const members = (await list.json()) as { Data: Array<{ Id: string; UserId: string }> };
    const victimMembership = members.Data.find((m) => m.UserId === victim.userId)!;

    const intruder = await loggedIn("z");
    const bad = await req(
      `/api/organizations/${orgId}/users/${victimMembership.Id}/accept`,
      authJson(intruder.accessToken, { method: "POST", body: JSON.stringify({}) }),
    );
    expect(bad.status).toBe(403);
  });

  it("can't confirm before accept", async () => {
    const target = await loggedIn("t");
    await req(
      `/api/organizations/${orgId}/users/invite`,
      authJson(owner.accessToken, { method: "POST", body: JSON.stringify({ emails: [target.email], type: 2 }) }),
    );
    const list = await req(`/api/organizations/${orgId}/users`, {
      headers: { authorization: `Bearer ${owner.accessToken}` },
    });
    const members = (await list.json()) as { Data: Array<{ Id: string; UserId: string }> };
    const m = members.Data.find((x) => x.UserId === target.userId)!;

    const bad = await req(
      `/api/organizations/${orgId}/users/${m.Id}/confirm`,
      authJson(owner.accessToken, { method: "POST", body: JSON.stringify({ key: "k" }) }),
    );
    expect(bad.status).toBe(400);
  });
});
