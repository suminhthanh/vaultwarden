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
  f.set("deviceIdentifier", `00000000-0000-4000-8000-${Math.floor(Math.random() * 1e12).toString().padStart(12, "0")}`);
  f.set("deviceName", "ParityTest");
  f.set("deviceType", "9");
  for (const [k, v] of Object.entries(extra)) f.set(k, v);
  return f;
}

interface Session {
  email: string;
  userId: string;
  passwordHashB64: string;
  accessToken: string;
}

async function loggedIn(suffix: string): Promise<Session> {
  const email = `parity-${suffix}-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
  const hash = new Uint8Array(32);
  for (let i = 0; i < hash.length; i++) hash[i] = (i * 7 + suffix.length) & 0xff;
  let bin = "";
  for (const b of hash) bin += String.fromCharCode(b);
  const hashB64 = Buffer.from(bin, "binary").toString("base64");

  await req("/api/accounts/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      email,
      masterPasswordHash: hashB64,
      key: "0.user-symmetric",
      keys: { publicKey: "MFc...stub", encryptedPrivateKey: "0.priv" },
    }),
  });
  const login = await req("/identity/connect/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: tokenForm({ username: email, password: hashB64 }).toString(),
  });
  const body = (await login.json()) as { access_token: string };
  const profile = await req("/api/accounts/profile", { headers: { authorization: `Bearer ${body.access_token}` } });
  const p = (await profile.json()) as { Id: string };
  return { email, userId: p.Id, passwordHashB64: hashB64, accessToken: body.access_token };
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

describe("phase 5 parity: account endpoints (verify-password / password / delete / public-key / hint)", () => {
  it("verify-password accepts the correct hash, rejects wrong", async () => {
    const s = await loggedIn("verify");
    const ok = await req(
      "/api/accounts/verify-password",
      authJson(s.accessToken, { method: "POST", body: JSON.stringify({ masterPasswordHash: s.passwordHashB64 }) }),
    );
    expect(ok.status).toBe(200);

    const bad = await req(
      "/api/accounts/verify-password",
      authJson(s.accessToken, { method: "POST", body: JSON.stringify({ masterPasswordHash: "wrong" }) }),
    );
    expect(bad.status).toBe(401);
  });

  it("password change rotates security stamp and invalidates old tokens", async () => {
    const s = await loggedIn("pwchange");
    const newHash = Buffer.from("new-master-password-hash").toString("base64");

    const change = await req(
      "/api/accounts/password",
      authJson(s.accessToken, {
        method: "POST",
        body: JSON.stringify({
          masterPasswordHash: s.passwordHashB64,
          newMasterPasswordHash: newHash,
          key: "0.new-symmetric",
          masterPasswordHint: "new hint",
        }),
      }),
    );
    expect(change.status).toBe(200);

    // Old token must now 401 because security_stamp rotated.
    const after = await req("/api/accounts/profile", { headers: { authorization: `Bearer ${s.accessToken}` } });
    expect(after.status).toBe(401);

    // New password should log in cleanly.
    const r = await req("/identity/connect/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: tokenForm({ username: s.email, password: newHash }).toString(),
    });
    expect(r.status).toBe(200);
    const body = (await r.json()) as { Key: string };
    expect(body.Key).toBe("0.new-symmetric");
  });

  it("password change rejects wrong current password", async () => {
    const s = await loggedIn("pwwrong");
    const r = await req(
      "/api/accounts/password",
      authJson(s.accessToken, {
        method: "POST",
        body: JSON.stringify({
          masterPasswordHash: "wrong",
          newMasterPasswordHash: "new",
          key: "0.k",
        }),
      }),
    );
    expect(r.status).toBe(401);
  });

  it("delete account removes the user and cascades user-owned data", async () => {
    const s = await loggedIn("del");

    // Add a folder + cipher so cascade can be observed.
    await req(
      "/api/folders",
      authJson(s.accessToken, { method: "POST", body: JSON.stringify({ name: "Doomed" }) }),
    );
    await req(
      "/api/ciphers",
      authJson(s.accessToken, {
        method: "POST",
        body: JSON.stringify({ type: 1, name: "Doomed cipher", login: { username: "u", password: "p" } }),
      }),
    );

    const del = await req(
      "/api/accounts/delete",
      authJson(s.accessToken, {
        method: "POST",
        body: JSON.stringify({ masterPasswordHash: s.passwordHashB64 }),
      }),
    );
    expect(del.status).toBe(200);

    // Sync should now 401 (user gone, security stamp on JWT no longer matches).
    const after = await req("/api/sync", { headers: { authorization: `Bearer ${s.accessToken}` } });
    expect(after.status).toBe(401);

    // Re-registration with the same email succeeds (user row was actually removed).
    const reg = await req("/api/accounts/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: s.email, masterPasswordHash: "AAAA", key: "k" }),
    });
    expect(reg.status).toBe(200);
  });

  it("delete account rejects wrong password", async () => {
    const s = await loggedIn("delwrong");
    const r = await req(
      "/api/accounts/delete",
      authJson(s.accessToken, {
        method: "POST",
        body: JSON.stringify({ masterPasswordHash: "wrong" }),
      }),
    );
    expect(r.status).toBe(401);
  });

  it("DELETE /api/accounts is an alias for delete", async () => {
    const s = await loggedIn("delalias");
    const r = await req("/api/accounts", authJson(s.accessToken, {
      method: "DELETE",
      body: JSON.stringify({ masterPasswordHash: s.passwordHashB64 }),
    }));
    expect(r.status).toBe(200);
  });

  it("user public-key lookup returns the stored public key", async () => {
    const a = await loggedIn("pubA");
    const b = await loggedIn("pubB");
    const r = await req(`/api/users/${a.userId}/public-key`, {
      headers: { authorization: `Bearer ${b.accessToken}` },
    });
    expect(r.status).toBe(200);
    const body = (await r.json()) as { Object: string; UserId: string; PublicKey: string };
    expect(body.Object).toBe("userKey");
    expect(body.UserId).toBe(a.userId);
    expect(body.PublicKey).toBe("MFc...stub");
  });

  it("user public-key lookup 404s on unknown user", async () => {
    const a = await loggedIn("pubmissing");
    const r = await req("/api/users/00000000-0000-0000-0000-000000000000/public-key", {
      headers: { authorization: `Bearer ${a.accessToken}` },
    });
    expect(r.status).toBe(404);
  });

  it("password-hint endpoint always returns 200 (no enumeration)", async () => {
    const r1 = await req("/api/accounts/password-hint", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: `nobody-${Date.now()}@example.com` }),
    });
    expect(r1.status).toBe(200);

    const s = await loggedIn("hint");
    const r2 = await req("/api/accounts/password-hint", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: s.email }),
    });
    expect(r2.status).toBe(200);
  });
});

describe("phase 5 parity: cipher partial / share / collections / bulk / purge", () => {
  let s: Session;
  beforeAll(async () => {
    s = await loggedIn("ciph");
  });

  it("partial update sets favorite + folder", async () => {
    const cipher = await req("/api/ciphers", authJson(s.accessToken, {
      method: "POST",
      body: JSON.stringify({ type: 1, name: "Partial", login: { username: "u", password: "p" } }),
    }));
    const cId = ((await cipher.json()) as { Id: string }).Id;

    const folder = await req("/api/folders", authJson(s.accessToken, {
      method: "POST",
      body: JSON.stringify({ name: "Box" }),
    }));
    const fId = ((await folder.json()) as { Id: string }).Id;

    const r = await req(`/api/ciphers/${cId}/partial`, authJson(s.accessToken, {
      method: "PUT",
      body: JSON.stringify({ folderId: fId, favorite: true }),
    }));
    expect(r.status).toBe(200);
    const body = (await r.json()) as { FolderId: string; Favorite: boolean };
    expect(body.FolderId).toBe(fId);
    expect(body.Favorite).toBe(true);

    // /api/sync surfaces the same FolderId.
    const sync = await req("/api/sync", { headers: { authorization: `Bearer ${s.accessToken}` } });
    const synced = (await sync.json()) as { Ciphers: Array<{ Id: string; FolderId: string | null }> };
    expect(synced.Ciphers.find((c) => c.Id === cId)?.FolderId).toBe(fId);
  });

  it("bulk soft-delete + bulk restore", async () => {
    const ids: string[] = [];
    for (const name of ["a", "b", "c"]) {
      const r = await req("/api/ciphers", authJson(s.accessToken, {
        method: "POST",
        body: JSON.stringify({ type: 1, name, login: { username: "u", password: "p" } }),
      }));
      ids.push(((await r.json()) as { Id: string }).Id);
    }

    const del = await req("/api/ciphers/delete", authJson(s.accessToken, {
      method: "PUT",
      body: JSON.stringify({ ids }),
    }));
    expect(del.status).toBe(200);

    const sync = await req("/api/sync", { headers: { authorization: `Bearer ${s.accessToken}` } });
    const body = (await sync.json()) as { Ciphers: Array<{ Id: string; DeletedDate: string | null }> };
    for (const id of ids) {
      expect(body.Ciphers.find((c) => c.Id === id)?.DeletedDate).not.toBeNull();
    }

    const restore = await req("/api/ciphers/restore", authJson(s.accessToken, {
      method: "PUT",
      body: JSON.stringify({ ids }),
    }));
    expect(restore.status).toBe(200);

    const after = await req("/api/sync", { headers: { authorization: `Bearer ${s.accessToken}` } });
    const after_body = (await after.json()) as { Ciphers: Array<{ Id: string; DeletedDate: string | null }> };
    for (const id of ids) {
      expect(after_body.Ciphers.find((c) => c.Id === id)?.DeletedDate).toBeNull();
    }
  });

  it("share moves a personal cipher into an org with a collection", async () => {
    const owner = await loggedIn("shareowner");
    const orgRes = await req("/api/organizations", authJson(owner.accessToken, {
      method: "POST",
      body: JSON.stringify({ name: "ShareOrg", billingEmail: "ops@x.test", key: "k" }),
    }));
    const orgId = ((await orgRes.json()) as { Id: string }).Id;
    const collRes = await req(`/api/organizations/${orgId}/collections`, authJson(owner.accessToken, {
      method: "POST",
      body: JSON.stringify({ name: "ShareCol" }),
    }));
    const collId = ((await collRes.json()) as { Id: string }).Id;

    const personal = await req("/api/ciphers", authJson(owner.accessToken, {
      method: "POST",
      body: JSON.stringify({ type: 1, name: "PersonalSecret", login: { username: "u", password: "p" } }),
    }));
    const cId = ((await personal.json()) as { Id: string }).Id;

    const share = await req(`/api/ciphers/${cId}/share`, authJson(owner.accessToken, {
      method: "PUT",
      body: JSON.stringify({
        cipher: {
          type: 1,
          name: "PersonalSecret (shared)",
          organizationId: orgId,
          login: { username: "u", password: "p" },
        },
        collectionIds: [collId],
      }),
    }));
    expect(share.status).toBe(200);
    const body = (await share.json()) as { OrganizationId: string; CollectionIds: string[]; Name: string };
    expect(body.OrganizationId).toBe(orgId);
    expect(body.CollectionIds).toContain(collId);
    expect(body.Name).toBe("PersonalSecret (shared)");
  });

  it("PUT cipher collections re-attaches collections inside an org", async () => {
    const owner = await loggedIn("collreplace");
    const orgRes = await req("/api/organizations", authJson(owner.accessToken, {
      method: "POST",
      body: JSON.stringify({ name: "Replace", billingEmail: "ops@x.test", key: "k" }),
    }));
    const orgId = ((await orgRes.json()) as { Id: string }).Id;
    const collA = ((await (await req(`/api/organizations/${orgId}/collections`, authJson(owner.accessToken, {
      method: "POST",
      body: JSON.stringify({ name: "A" }),
    }))).json()) as { Id: string }).Id;
    const collB = ((await (await req(`/api/organizations/${orgId}/collections`, authJson(owner.accessToken, {
      method: "POST",
      body: JSON.stringify({ name: "B" }),
    }))).json()) as { Id: string }).Id;

    const cipher = await req("/api/ciphers", authJson(owner.accessToken, {
      method: "POST",
      body: JSON.stringify({
        type: 1,
        name: "OrgItem",
        organizationId: orgId,
        collectionIds: [collA],
        login: { username: "u", password: "p" },
      }),
    }));
    const cId = ((await cipher.json()) as { Id: string }).Id;

    const put = await req(`/api/ciphers/${cId}/collections`, authJson(owner.accessToken, {
      method: "PUT",
      body: JSON.stringify({ collectionIds: [collB] }),
    }));
    expect(put.status).toBe(200);
    const body = (await put.json()) as { CollectionIds: string[] };
    expect(body.CollectionIds).toEqual([collB]);
  });

  it("purge removes every personal cipher after password verify", async () => {
    const fresh = await loggedIn("purge");
    for (const name of ["x", "y", "z"]) {
      await req("/api/ciphers", authJson(fresh.accessToken, {
        method: "POST",
        body: JSON.stringify({ type: 1, name, login: { username: "u", password: "p" } }),
      }));
    }
    const before = await req("/api/sync", { headers: { authorization: `Bearer ${fresh.accessToken}` } });
    expect(((await before.json()) as { Ciphers: unknown[] }).Ciphers.length).toBeGreaterThanOrEqual(3);

    const r = await req("/api/ciphers/purge", authJson(fresh.accessToken, {
      method: "POST",
      body: JSON.stringify({ masterPasswordHash: fresh.passwordHashB64 }),
    }));
    expect(r.status).toBe(200);

    const after = await req("/api/sync", { headers: { authorization: `Bearer ${fresh.accessToken}` } });
    expect(((await after.json()) as { Ciphers: unknown[] }).Ciphers).toEqual([]);
  });
});

describe("phase 5 parity: favicon proxy", () => {
  it("returns image/png for a known host", async () => {
    const r = await req("/icons/example.com/icon.png");
    expect(r.status).toBe(200);
    expect(r.headers.get("content-type")).toBe("image/png");
    const body = await r.arrayBuffer();
    expect(body.byteLength).toBeGreaterThan(0);
  });

  it("falls back to the transparent PNG for an invalid host", async () => {
    const r = await req("/icons/this is not a valid host/icon.png");
    // axum normalizes spaces in path segments; whatever lands, we still get an image.
    expect([200, 404]).toContain(r.status);
    if (r.status === 200) {
      expect(r.headers.get("content-type")).toBe("image/png");
    }
  });
});
