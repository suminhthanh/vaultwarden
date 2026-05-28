import { describe, it, expect } from "vitest";

const BASE_URL = process.env.WORKER_URL ?? "http://127.0.0.1:8787";

async function req(path: string, init?: RequestInit) {
  return fetch(`${BASE_URL}${path}`, init);
}

describe("phase 4: HTTP email provider", () => {
  it("LogProvider (default in dev) accepts a message and reports success", async () => {
    const r = await req("/_test/mail/send", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        to: "alice@example.com",
        subject: "Welcome to Vaultwarden",
        text: "This is a test email from the worker.",
      }),
    });
    expect(r.status).toBe(200);
    const body = (await r.json()) as { ok: boolean };
    expect(body.ok).toBe(true);
  });

  it("provider call survives valid input but missing fields fail at the boundary", async () => {
    const r = await req("/_test/mail/send", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ to: "bob@example.com" }),
    });
    expect(r.status).toBeGreaterThanOrEqual(400);
  });
});
