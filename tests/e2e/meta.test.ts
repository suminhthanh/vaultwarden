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
  f.set("deviceIdentifier", "00000000-0000-4000-8000-00000000meta");
  f.set("deviceName", "MetaTest");
  f.set("deviceType", "9");
  for (const [k, v] of Object.entries(extra)) f.set(k, v);
  return f;
}

async function loggedIn(suffix: string) {
  const email = `meta-${suffix}-${Date.now()}@example.com`;
  const hash = new Uint8Array(32);
  for (let i = 0; i < hash.length; i++) hash[i] = (i * 5 + 1) & 0xff;
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
  return { email, token: body.access_token };
}

describe("phase 2: /api/config + /api/devices + security stamp + keys + CORS", () => {
  it("GET /api/config is public and returns server metadata", async () => {
    const r = await req("/api/config");
    expect(r.status).toBe(200);
    const c = (await r.json()) as Record<string, any>;
    expect(c.object).toBe("config");
    expect(c.server.name).toBe("Vaultwarden");
    expect(typeof c.version).toBe("string");
    expect(c.environment.api).toMatch(/\/api$/);
  });

  it("GET /api/devices lists devices for the logged-in user", async () => {
    const s = await loggedIn("dev");
    const r = await req("/api/devices", { headers: { authorization: `Bearer ${s.token}` } });
    expect(r.status).toBe(200);
    const list = (await r.json()) as { Object: string; Data: Array<{ Id: string; Name: string; Type: number }> };
    expect(list.Object).toBe("list");
    expect(list.Data.length).toBeGreaterThanOrEqual(1);
    const ours = list.Data.find((d) => d.Id === "00000000-0000-4000-8000-00000000meta");
    expect(ours?.Name).toBe("MetaTest");
    expect(ours?.Type).toBe(9);
  });

  it("POST /api/accounts/security-stamp invalidates the existing JWT", async () => {
    const s = await loggedIn("stamp");

    const before = await req("/api/accounts/profile", { headers: { authorization: `Bearer ${s.token}` } });
    expect(before.status).toBe(200);

    const rotate = await req("/api/accounts/security-stamp", {
      method: "POST",
      headers: { authorization: `Bearer ${s.token}` },
    });
    expect(rotate.status).toBe(200);

    const after = await req("/api/accounts/profile", { headers: { authorization: `Bearer ${s.token}` } });
    expect(after.status).toBe(401);
  });

  it("POST /api/accounts/keys stores RSA key pair", async () => {
    const s = await loggedIn("keys");
    const r = await req("/api/accounts/keys", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${s.token}` },
      body: JSON.stringify({ publicKey: "pub-stub", encryptedPrivateKey: "priv-stub" }),
    });
    expect(r.status).toBe(200);
    const body = (await r.json()) as { Object: string; PublicKey: string; PrivateKey: string };
    expect(body.Object).toBe("keys");
    expect(body.PublicKey).toBe("pub-stub");
    expect(body.PrivateKey).toBe("priv-stub");
  });

  it("CORS preflight allows Authorization header", async () => {
    const r = await req("/api/sync", {
      method: "OPTIONS",
      headers: {
        origin: "https://vault.example.com",
        "access-control-request-method": "GET",
        "access-control-request-headers": "authorization,content-type",
      },
    });
    expect(r.status).toBeLessThan(400);
    const allowedHeaders = (r.headers.get("access-control-allow-headers") ?? "").toLowerCase();
    expect(allowedHeaders).toContain("authorization");
  });

  it("security headers are present on responses", async () => {
    const r = await req("/api/config");
    expect(r.headers.get("x-content-type-options")).toBe("nosniff");
    expect(r.headers.get("referrer-policy")).toBe("same-origin");
  });
});
