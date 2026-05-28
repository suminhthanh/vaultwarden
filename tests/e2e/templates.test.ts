import { describe, it, expect } from "vitest";

const BASE_URL = process.env.WORKER_URL ?? "http://127.0.0.1:8787";

async function req(path: string, init?: RequestInit) {
  return fetch(`${BASE_URL}${path}`, init);
}

describe("phase 4: embedded Handlebars templates", () => {
  it("renders welcome.hbs (text) with the {{url}} substituted", async () => {
    const r = await req("/_test/mail/render/email/welcome", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url: "https://vault.example.com" }),
    });
    expect(r.status).toBe(200);
    const body = (await r.json()) as { subject: string; body: string };
    expect(body.subject).toBe("Welcome");
    expect(body.body).toContain("Thank you for creating an account at https://vault.example.com");
    expect(body.body).toContain("Github: https://github.com/dani-garcia/vaultwarden");
  });

  it("renders welcome.html.hbs with the email_header partial included", async () => {
    const r = await req("/_test/mail/render/email/welcome.html", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url: "https://vault.example.com", img_src: "https://vault.example.com/img/" }),
    });
    expect(r.status).toBe(200);
    const body = (await r.json()) as { subject: string; body: string };
    expect(body.subject).toBe("Welcome");
    expect(body.body).toContain("<!DOCTYPE html");
    expect(body.body).toContain('alt="Vaultwarden"');
    expect(body.body).toContain("https://vault.example.com");
  });

  it("renders verify_email.hbs (text) with token substitution", async () => {
    const r = await req("/_test/mail/render/email/verify_email", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        url: "https://vault.example.com",
        token: "tok-abc-123",
        user_id: "uid-1",
        link: "https://vault.example.com/verify-email?token=tok-abc-123",
      }),
    });
    expect(r.status).toBe(200);
    const body = (await r.json()) as { subject: string; body: string };
    expect(body.subject.length).toBeGreaterThan(0);
    expect(body.body).toContain("vault.example.com");
  });

  it("returns an error for unknown templates", async () => {
    const r = await req("/_test/mail/render/email/does_not_exist", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(r.status).toBe(500);
  });
});
