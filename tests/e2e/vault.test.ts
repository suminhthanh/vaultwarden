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
  f.set("deviceIdentifier", "00000000-0000-4000-8000-000000fffff1");
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
  const email = `crud-${suffix}-${Date.now()}@example.com`;
  const hash = new Uint8Array(32);
  for (let i = 0; i < hash.length; i++) hash[i] = (i * 17 + suffix.length) & 0xff;
  let bin = "";
  for (const b of hash) bin += String.fromCharCode(b);
  const hashB64 = Buffer.from(bin, "binary").toString("base64");

  const reg = await req("/api/accounts/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, masterPasswordHash: hashB64, key: "0.k" }),
  });
  expect(reg.status).toBe(200);

  const login = await req("/identity/connect/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: tokenForm({ username: email, password: hashB64 }).toString(),
  });
  expect(login.status).toBe(200);
  const body = (await login.json()) as { access_token: string };

  const profile = await req("/api/accounts/profile", { headers: { authorization: `Bearer ${body.access_token}` } });
  const p = (await profile.json()) as { Id: string };
  return { email, userId: p.Id, accessToken: body.access_token };
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

describe("phase 2: /api/ciphers CRUD", () => {
  let s: Session;
  beforeAll(async () => {
    s = await loggedInUser("ciph");
  });

  it("create -> get -> list -> update -> soft-delete -> restore -> hard-delete", async () => {
    const create = await req(
      "/api/ciphers",
      authJson(s.accessToken, {
        method: "POST",
        body: JSON.stringify({
          type: 1,
          name: "Bank",
          notes: "checking",
          login: { username: "alice", password: "p" },
          favorite: true,
          fields: [{ name: "pin", value: "1234", type: 1 }],
        }),
      }),
    );
    expect(create.status).toBe(200);
    const c = (await create.json()) as Record<string, any>;
    expect(c.Id).toMatch(/^[0-9a-f-]{36}$/);
    expect(c.Object).toBe("cipherDetails");
    expect(c.Type).toBe(1);
    expect(c.Name).toBe("Bank");
    expect(c.Login).toEqual({ username: "alice", password: "p" });
    expect(c.Favorite).toBe(true);
    const id = c.Id as string;

    const got = await req(`/api/ciphers/${id}`, { headers: { authorization: `Bearer ${s.accessToken}` } });
    expect(got.status).toBe(200);
    expect(((await got.json()) as { Id: string }).Id).toBe(id);

    const list = await req("/api/ciphers", { headers: { authorization: `Bearer ${s.accessToken}` } });
    expect(list.status).toBe(200);
    const listed = (await list.json()) as { Data: Array<{ Id: string }> };
    expect(listed.Data.find((x) => x.Id === id)).toBeTruthy();

    const upd = await req(
      `/api/ciphers/${id}`,
      authJson(s.accessToken, {
        method: "PUT",
        body: JSON.stringify({
          type: 1,
          name: "Bank renamed",
          login: { username: "alice", password: "p2" },
          favorite: false,
        }),
      }),
    );
    expect(upd.status).toBe(200);
    const updated = (await upd.json()) as Record<string, any>;
    expect(updated.Name).toBe("Bank renamed");
    expect(updated.Login.password).toBe("p2");
    expect(updated.Favorite).toBe(false);

    const soft = await req(`/api/ciphers/${id}/delete`, {
      method: "PUT",
      headers: { authorization: `Bearer ${s.accessToken}` },
    });
    expect(soft.status).toBe(200);
    const afterSoft = await req(`/api/ciphers/${id}`, {
      headers: { authorization: `Bearer ${s.accessToken}` },
    });
    expect(afterSoft.status).toBe(200);
    expect(((await afterSoft.json()) as { DeletedDate: string | null }).DeletedDate).not.toBeNull();

    const restore = await req(`/api/ciphers/${id}/restore`, {
      method: "PUT",
      headers: { authorization: `Bearer ${s.accessToken}` },
    });
    expect(restore.status).toBe(200);
    const restored = (await restore.json()) as { DeletedDate: string | null };
    expect(restored.DeletedDate).toBeNull();

    const hard = await req(`/api/ciphers/${id}/delete-admin`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${s.accessToken}` },
    });
    expect(hard.status).toBe(200);

    const after = await req(`/api/ciphers/${id}`, { headers: { authorization: `Bearer ${s.accessToken}` } });
    expect(after.status).toBe(404);
  });

  it("rejects access to another user's cipher", async () => {
    const other = await loggedInUser("intruder");

    const create = await req(
      "/api/ciphers",
      authJson(s.accessToken, {
        method: "POST",
        body: JSON.stringify({ type: 1, name: "Private", login: { username: "x", password: "y" } }),
      }),
    );
    const { Id } = (await create.json()) as { Id: string };

    const got = await req(`/api/ciphers/${Id}`, { headers: { authorization: `Bearer ${other.accessToken}` } });
    expect(got.status).toBe(404);

    await req(`/api/ciphers/${Id}/delete-admin`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${s.accessToken}` },
    });
  });
});

describe("phase 2: /api/folders CRUD", () => {
  let s: Session;
  beforeAll(async () => {
    s = await loggedInUser("fld");
  });

  it("create, get, list, update, delete", async () => {
    const create = await req(
      "/api/folders",
      authJson(s.accessToken, { method: "POST", body: JSON.stringify({ name: "Personal" }) }),
    );
    expect(create.status).toBe(200);
    const f = (await create.json()) as { Id: string; Name: string; Object: string };
    expect(f.Object).toBe("folder");
    expect(f.Name).toBe("Personal");

    const got = await req(`/api/folders/${f.Id}`, { headers: { authorization: `Bearer ${s.accessToken}` } });
    expect(got.status).toBe(200);

    const list = await req("/api/folders", { headers: { authorization: `Bearer ${s.accessToken}` } });
    expect(list.status).toBe(200);
    const listed = (await list.json()) as { Data: Array<{ Id: string }> };
    expect(listed.Data.find((x) => x.Id === f.Id)).toBeTruthy();

    const upd = await req(
      `/api/folders/${f.Id}`,
      authJson(s.accessToken, { method: "PUT", body: JSON.stringify({ name: "Work" }) }),
    );
    expect(upd.status).toBe(200);
    expect(((await upd.json()) as { Name: string }).Name).toBe("Work");

    const del = await req(`/api/folders/${f.Id}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${s.accessToken}` },
    });
    expect(del.status).toBe(200);
  });
});

describe("phase 2: GET /api/sync", () => {
  let s: Session;
  beforeAll(async () => {
    s = await loggedInUser("sync");
  });

  it("returns profile + folders + ciphers in one bundle", async () => {
    const folder = await req(
      "/api/folders",
      authJson(s.accessToken, { method: "POST", body: JSON.stringify({ name: "Stuff" }) }),
    );
    const fId = ((await folder.json()) as { Id: string }).Id;

    const cipher = await req(
      "/api/ciphers",
      authJson(s.accessToken, {
        method: "POST",
        body: JSON.stringify({
          type: 1,
          name: "Email",
          login: { username: "u", password: "p" },
        }),
      }),
    );
    const cId = ((await cipher.json()) as { Id: string }).Id;

    const sync = await req("/api/sync", { headers: { authorization: `Bearer ${s.accessToken}` } });
    expect(sync.status).toBe(200);
    const body = (await sync.json()) as {
      Object: string;
      Profile: { Id: string; Email: string };
      Folders: Array<{ Id: string }>;
      Ciphers: Array<{ Id: string; Type: number }>;
      Domains: { Object: string };
    };
    expect(body.Object).toBe("sync");
    expect(body.Profile.Email).toBe(s.email);
    expect(body.Folders.find((f) => f.Id === fId)).toBeTruthy();
    expect(body.Ciphers.find((c) => c.Id === cId)).toBeTruthy();
    expect(body.Domains.Object).toBe("domains");

    await req(`/api/ciphers/${cId}/delete-admin`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${s.accessToken}` },
    });
    await req(`/api/folders/${fId}`, { method: "DELETE", headers: { authorization: `Bearer ${s.accessToken}` } });
  });

  it("requires authentication", async () => {
    const r = await req("/api/sync");
    expect(r.status).toBe(401);
  });
});
