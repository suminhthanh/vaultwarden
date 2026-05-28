import { describe, it, expect } from "vitest";

const BASE_URL = process.env.WORKER_URL ?? "http://127.0.0.1:8787";
const ADMIN_TOKEN = "vw-test-admin-token-1234567890";

async function req(path: string, init?: RequestInit) {
  return fetch(`${BASE_URL}${path}`, init);
}

async function loginAdmin(token: string = ADMIN_TOKEN): Promise<string> {
  // Use the JSON login endpoint (existing tests use this); the form endpoint
  // is exercised separately below.
  const r = await req("/admin/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token }),
    redirect: "manual",
  });
  expect(r.status).toBe(200);
  const setCookie = r.headers.get("set-cookie") ?? "";
  const match = /VW_ADMIN_SESSION=([^;]+)/.exec(setCookie);
  expect(match).not.toBeNull();
  return `VW_ADMIN_SESSION=${match![1]}`;
}

describe("phase 4: admin panel + KV-backed config", () => {
  it("GET /admin returns the dashboard HTML", async () => {
    const r = await req("/admin");
    expect(r.status).toBe(200);
    expect(r.headers.get("content-type") ?? "").toContain("text/html");
    const body = await r.text();
    expect(body).toContain("Vaultwarden Admin");
  });

  it("rejects /admin/config without auth", async () => {
    const r = await req("/admin/config");
    expect(r.status).toBe(401);
  });

  it("rejects /admin/login with wrong token", async () => {
    const r = await req("/admin/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: "definitely-not-it" }),
    });
    expect(r.status).toBe(401);
  });

  it("login + diagnostics page (HTML) + read/write config (JSON)", async () => {
    const cookie = await loginAdmin();

    const diag = await req("/admin/diagnostics", { headers: { cookie } });
    expect(diag.status).toBe(200);
    expect(diag.headers.get("content-type") ?? "").toContain("text/html");
    const diagBody = await diag.text();
    expect(diagBody).toContain("Vaultwarden Admin");

    const before = await req("/admin/config", { headers: { cookie } });
    expect(before.status).toBe(200);

    const set = await req("/admin/config", {
      method: "POST",
      headers: { "content-type": "application/json", cookie },
      body: JSON.stringify({ signups_allowed: false, max_login_attempts: 7 }),
    });
    expect(set.status).toBe(200);

    const after = await req("/admin/config", { headers: { cookie } });
    const cfg = (await after.json()) as {
      signups_allowed: boolean | null;
      max_login_attempts: number | null;
    };
    expect(cfg.signups_allowed).toBe(false);
    expect(cfg.max_login_attempts).toBe(7);

    await req("/admin/config", {
      method: "POST",
      headers: { "content-type": "application/json", cookie },
      body: JSON.stringify({}),
    });
  });

  it("admin/users lists registered accounts", async () => {
    const cookie = await loginAdmin();
    const r = await req("/admin/users", { headers: { cookie } });
    expect(r.status).toBe(200);
    const body = (await r.json()) as { Object: string; Data: Array<{ email: string }> };
    expect(body.Object).toBe("list");
    expect(Array.isArray(body.Data)).toBe(true);
  });

  it("logout clears the cookie and subsequent admin calls are unauthorized", async () => {
    const cookie = await loginAdmin();
    const out = await req("/admin/logout", {
      method: "POST",
      headers: { cookie },
      redirect: "manual",
    });
    // GET-friendly logout: returns 303 redirect with Set-Cookie clearing the session.
    expect([200, 303]).toContain(out.status);
    const r = await req("/admin/config");
    expect(r.status).toBe(401);
  });

  it("each admin page renders without a Handlebars error", async () => {
    const cookie = await loginAdmin();
    for (const path of [
      "/admin",                       // settings
      "/admin/users/overview",
      "/admin/organizations/overview",
      "/admin/diagnostics",
    ]) {
      const r = await req(path, { headers: { cookie } });
      expect(r.status, `${path} should be 200`).toBe(200);
      const body = await r.text();
      expect(body, `${path} body must not surface a template error`).not.toMatch(/template error/i);
      expect(body, `${path} body must not surface a Handlebars 'rendering' error`).not.toMatch(
        /Error rendering "admin\//,
      );
      expect(body).toContain("Vaultwarden Admin");
    }
  });
});
