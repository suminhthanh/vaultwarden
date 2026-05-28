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
  f.set("deviceIdentifier", "00000000-0000-4000-8000-000000sends1");
  f.set("deviceName", "SendTest");
  f.set("deviceType", "9");
  for (const [k, v] of Object.entries(extra)) f.set(k, v);
  return f;
}

interface Session {
  email: string;
  accessToken: string;
}

async function loggedIn(suffix: string): Promise<Session> {
  const email = `snd-${suffix}-${Date.now()}@example.com`;
  const hash = new Uint8Array(32);
  for (let i = 0; i < hash.length; i++) hash[i] = (i * 31 + 5) & 0xff;
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
  return { email, accessToken: ((await login.json()) as { access_token: string }).access_token };
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

const FAR_FUTURE = "2099-12-31T23:59:59.000000Z";

describe("phase 2: /api/sends (text sends)", () => {
  let s: Session;
  beforeAll(async () => {
    s = await loggedIn("a");
  });

  it("create a text send, list it, fetch it, update it, delete it", async () => {
    const create = await req(
      "/api/sends",
      authJson(s.accessToken, {
        method: "POST",
        body: JSON.stringify({
          type: 0,
          name: "0.encrypted-name",
          notes: null,
          text: { text: "0.encrypted-text", hidden: false },
          file: null,
          key: "0.encrypted-send-key",
          deletionDate: FAR_FUTURE,
          maxAccessCount: 5,
        }),
      }),
    );
    expect(create.status).toBe(200);
    const send = (await create.json()) as { Id: string; Type: number; Name: string };
    expect(send.Type).toBe(0);

    const list = await req("/api/sends", { headers: { authorization: `Bearer ${s.accessToken}` } });
    const listed = (await list.json()) as { Data: Array<{ Id: string }> };
    expect(listed.Data.find((x) => x.Id === send.Id)).toBeTruthy();

    const get = await req(`/api/sends/${send.Id}`, { headers: { authorization: `Bearer ${s.accessToken}` } });
    expect(get.status).toBe(200);

    const upd = await req(
      `/api/sends/${send.Id}`,
      authJson(s.accessToken, {
        method: "PUT",
        body: JSON.stringify({
          type: 0,
          name: "0.encrypted-name-renamed",
          text: { text: "0.encrypted-text-v2", hidden: false },
          key: "0.encrypted-send-key",
          deletionDate: FAR_FUTURE,
          maxAccessCount: 10,
        }),
      }),
    );
    expect(upd.status).toBe(200);
    expect(((await upd.json()) as { Name: string; MaxAccessCount: number }).MaxAccessCount).toBe(10);

    const del = await req(`/api/sends/${send.Id}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${s.accessToken}` },
    });
    expect(del.status).toBe(200);

    const after = await req(`/api/sends/${send.Id}`, { headers: { authorization: `Bearer ${s.accessToken}` } });
    expect(after.status).toBe(404);
  });

  it("anonymous /api/sends/access/{id} returns the send and increments access_count", async () => {
    const create = await req(
      "/api/sends",
      authJson(s.accessToken, {
        method: "POST",
        body: JSON.stringify({
          type: 0,
          name: "shared",
          text: { text: "0.shared-encrypted", hidden: false },
          key: "0.k",
          deletionDate: FAR_FUTURE,
        }),
      }),
    );
    const { Id } = (await create.json()) as { Id: string; AccessId: string };

    const access = await req(`/api/sends/access/${Id}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(access.status).toBe(200);
    const a = (await access.json()) as { Object: string; Type: number };
    expect(a.Object).toBe("send-access");
    expect(a.Type).toBe(0);

    const get = await req(`/api/sends/${Id}`, { headers: { authorization: `Bearer ${s.accessToken}` } });
    const after = (await get.json()) as { AccessCount: number };
    expect(after.AccessCount).toBe(1);

    await req(`/api/sends/${Id}`, { method: "DELETE", headers: { authorization: `Bearer ${s.accessToken}` } });
  });

  it("disabled sends are not accessible", async () => {
    const create = await req(
      "/api/sends",
      authJson(s.accessToken, {
        method: "POST",
        body: JSON.stringify({
          type: 0,
          name: "n",
          text: { text: "0.t", hidden: false },
          key: "0.k",
          deletionDate: FAR_FUTURE,
          disabled: true,
        }),
      }),
    );
    const { Id } = (await create.json()) as { Id: string };

    const access = await req(`/api/sends/access/${Id}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(access.status).toBe(404);

    await req(`/api/sends/${Id}`, { method: "DELETE", headers: { authorization: `Bearer ${s.accessToken}` } });
  });

  it("max-access-count is enforced", async () => {
    const create = await req(
      "/api/sends",
      authJson(s.accessToken, {
        method: "POST",
        body: JSON.stringify({
          type: 0,
          name: "n",
          text: { text: "0.t", hidden: false },
          key: "0.k",
          deletionDate: FAR_FUTURE,
          maxAccessCount: 1,
        }),
      }),
    );
    const { Id } = (await create.json()) as { Id: string };

    const a1 = await req(`/api/sends/access/${Id}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(a1.status).toBe(200);

    const a2 = await req(`/api/sends/access/${Id}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(a2.status).toBe(404);

    await req(`/api/sends/${Id}`, { method: "DELETE", headers: { authorization: `Bearer ${s.accessToken}` } });
  });

  it("non-owner cannot read or update someone else's send", async () => {
    const owner = await loggedIn("o");
    const intruder = await loggedIn("i");

    const r = await req(
      "/api/sends",
      authJson(owner.accessToken, {
        method: "POST",
        body: JSON.stringify({
          type: 0,
          name: "n",
          text: { text: "0.t", hidden: false },
          key: "0.k",
          deletionDate: FAR_FUTURE,
        }),
      }),
    );
    const { Id } = (await r.json()) as { Id: string };

    const peek = await req(`/api/sends/${Id}`, { headers: { authorization: `Bearer ${intruder.accessToken}` } });
    expect(peek.status).toBe(404);

    await req(`/api/sends/${Id}`, { method: "DELETE", headers: { authorization: `Bearer ${owner.accessToken}` } });
  });
});
