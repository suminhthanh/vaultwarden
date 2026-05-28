import { describe, it, expect } from "vitest";

const BASE_URL = process.env.WORKER_URL ?? "http://127.0.0.1:8787";

async function req(path: string, init?: RequestInit) {
  return fetch(`${BASE_URL}${path}`, init);
}

function tokenForm(extra: Record<string, string>): URLSearchParams {
  const f = new URLSearchParams();
  f.set("grant_type", "password");
  f.set("scope", "api offline_access");
  f.set("client_id", "web");
  f.set("deviceIdentifier", "00000000-0000-4000-8000-00000000rate");
  f.set("deviceName", "RateTest");
  f.set("deviceType", "9");
  for (const [k, v] of Object.entries(extra)) f.set(k, v);
  return f;
}

describe("phase 4: KV-backed rate limiting", () => {
  it("login attempts from a high-volume IP eventually return 429", async () => {
    // Use a unique CF-Connecting-IP per test so we don't trip the production limit
    // for other tests sharing the worker. The KV bucket is keyed on this header.
    const ip = `203.0.113.${Math.floor(Math.random() * 254) + 1}`;

    let firstRateLimited = -1;
    for (let i = 0; i < 250; i++) {
      const res = await req("/identity/connect/token", {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          "cf-connecting-ip": ip,
        },
        body: tokenForm({ username: "nobody@x.test", password: "x" }).toString(),
      });
      if (res.status === 429) {
        firstRateLimited = i;
        const body = (await res.json()) as { error: string };
        expect(body.error).toBe("rate_limited");
        break;
      }
      // Drain the body so we don't leak.
      await res.text();
    }
    expect(firstRateLimited).toBeGreaterThanOrEqual(0);
    // Should kick in well before we walk the full window quota.
    expect(firstRateLimited).toBeLessThan(220);
  });

  it("a fresh IP is not rate-limited just because another IP was", async () => {
    const aggressorIp = `203.0.113.${Math.floor(Math.random() * 254) + 1}`;
    for (let i = 0; i < 220; i++) {
      const r = await req("/identity/connect/token", {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          "cf-connecting-ip": aggressorIp,
        },
        body: tokenForm({ username: "x@y.z", password: "x" }).toString(),
      });
      await r.text();
      if (r.status === 429) break;
    }

    const cleanIp = `198.51.100.${Math.floor(Math.random() * 254) + 1}`;
    const r = await req("/identity/connect/token", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "cf-connecting-ip": cleanIp,
      },
      body: tokenForm({ username: "nope@x.test", password: "wrong" }).toString(),
    });
    // Should be invalid_grant (400), not 429.
    expect(r.status).toBe(400);
  });
});
