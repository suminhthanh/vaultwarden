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
  f.set("deviceIdentifier", "00000000-0000-4000-8000-00000000atta");
  f.set("deviceName", "AttachTest");
  f.set("deviceType", "9");
  for (const [k, v] of Object.entries(extra)) f.set(k, v);
  return f;
}

interface Session {
  email: string;
  accessToken: string;
}

async function loggedIn(suffix: string): Promise<Session> {
  const email = `att-${suffix}-${Date.now()}@example.com`;
  const hash = new Uint8Array(32);
  for (let i = 0; i < hash.length; i++) hash[i] = (i * 29 + 7) & 0xff;
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

async function createCipher(token: string) {
  const r = await req("/api/ciphers", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
    body: JSON.stringify({
      type: 1,
      name: "AttachHost",
      login: { username: "u", password: "p" },
    }),
  });
  expect(r.status).toBe(200);
  return ((await r.json()) as { Id: string }).Id;
}

describe("phase 2: attachment upload to R2", () => {
  let s: Session;
  let cipherId: string;
  beforeAll(async () => {
    s = await loggedIn("flow");
    cipherId = await createCipher(s.accessToken);
  });

  it("v2 init -> upload -> get metadata -> download bytes -> delete", async () => {
    const fileBytes = new Uint8Array(64);
    for (let i = 0; i < fileBytes.length; i++) fileBytes[i] = (i * 5 + 11) & 0xff;

    const init = await req(`/api/ciphers/${cipherId}/attachment/v2`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${s.accessToken}` },
      body: JSON.stringify({
        key: "0.encrypted-attachment-key",
        fileName: "0.encrypted-name",
        fileSize: fileBytes.length,
      }),
    });
    expect(init.status).toBe(200);
    const initBody = (await init.json()) as { AttachmentId: string; Url: string; Object: string };
    expect(initBody.Object).toBe("attachment-fileUpload");
    expect(initBody.Url).toContain(`/api/ciphers/${cipherId}/attachment/${initBody.AttachmentId}`);

    const attId = initBody.AttachmentId;

    const upload = await req(`/api/ciphers/${cipherId}/attachment/${attId}`, {
      method: "POST",
      headers: { authorization: `Bearer ${s.accessToken}`, "content-type": "application/octet-stream" },
      body: fileBytes,
    });
    expect(upload.status).toBe(200);

    const meta = await req(`/api/ciphers/${cipherId}/attachment/${attId}`, {
      headers: { authorization: `Bearer ${s.accessToken}` },
    });
    expect(meta.status).toBe(200);
    const m = (await meta.json()) as { Object: string; Id: string; Size: string; FileName: string; Url: string };
    expect(m.Object).toBe("attachment");
    expect(m.Id).toBe(attId);
    expect(m.Size).toBe(String(fileBytes.length));
    expect(m.FileName).toBe("0.encrypted-name");

    const download = await req(`/api/ciphers/${cipherId}/attachment/${attId}/file`, {
      headers: { authorization: `Bearer ${s.accessToken}` },
    });
    expect(download.status).toBe(200);
    const got = new Uint8Array(await download.arrayBuffer());
    expect(got.length).toBe(fileBytes.length);
    for (let i = 0; i < got.length; i++) expect(got[i]).toBe(fileBytes[i]);

    const del = await req(`/api/ciphers/${cipherId}/attachment/${attId}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${s.accessToken}` },
    });
    expect(del.status).toBe(200);

    const after = await req(`/api/ciphers/${cipherId}/attachment/${attId}`, {
      headers: { authorization: `Bearer ${s.accessToken}` },
    });
    expect(after.status).toBe(404);
  });

  it("rejects body with mismatched size", async () => {
    const init = await req(`/api/ciphers/${cipherId}/attachment/v2`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${s.accessToken}` },
      body: JSON.stringify({ key: "k", fileName: "n", fileSize: 100 }),
    });
    const { AttachmentId } = (await init.json()) as { AttachmentId: string };

    const tooSmall = new Uint8Array(50);
    const r = await req(`/api/ciphers/${cipherId}/attachment/${AttachmentId}`, {
      method: "POST",
      headers: { authorization: `Bearer ${s.accessToken}`, "content-type": "application/octet-stream" },
      body: tooSmall,
    });
    expect(r.status).toBe(400);

    await req(`/api/ciphers/${cipherId}/attachment/${AttachmentId}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${s.accessToken}` },
    });
  });

  it("non-owner cannot read or upload another user's attachment", async () => {
    const other = await loggedIn("intruder");

    const init = await req(`/api/ciphers/${cipherId}/attachment/v2`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${s.accessToken}` },
      body: JSON.stringify({ key: "k", fileName: "n", fileSize: 4 }),
    });
    const { AttachmentId } = (await init.json()) as { AttachmentId: string };

    const peek = await req(`/api/ciphers/${cipherId}/attachment/${AttachmentId}`, {
      headers: { authorization: `Bearer ${other.accessToken}` },
    });
    expect(peek.status).toBe(404);

    const sneakUpload = await req(`/api/ciphers/${cipherId}/attachment/${AttachmentId}`, {
      method: "POST",
      headers: { authorization: `Bearer ${other.accessToken}`, "content-type": "application/octet-stream" },
      body: new Uint8Array(4),
    });
    expect(sneakUpload.status).toBe(404);

    await req(`/api/ciphers/${cipherId}/attachment/${AttachmentId}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${s.accessToken}` },
    });
  });
});
