import { describe, it, expect } from "vitest";

const BASE_URL = process.env.WORKER_URL ?? "http://127.0.0.1:8787";

async function req(path: string, init?: RequestInit) {
  return fetch(`${BASE_URL}${path}`, init);
}

function decodeJwtPayload(token: string): Record<string, unknown> {
  const parts = token.split(".");
  expect(parts).toHaveLength(3);
  const padded = parts[1] + "=".repeat((4 - (parts[1].length % 4)) % 4);
  const json = Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf-8");
  return JSON.parse(json);
}

describe("phase 2: JWT module — encode + decode round-trip in WASM", () => {
  it("encodes RS256 JWT, decodes it back, and the wasm code reads the same claims", async () => {
    const userUuid = "00000000-0000-4000-8000-000000000001";
    const deviceUuid = "00000000-0000-4000-8000-000000000002";

    const res = await req("/_test/jwt/roundtrip", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        user_uuid: userUuid,
        device_uuid: deviceUuid,
        device_atype: 7,
      }),
    });
    expect(res.status).toBe(200);

    const body = (await res.json()) as {
      token: string;
      iss: string;
      sub: string;
      device: string;
      scope: string[];
      expires_in: number;
    };

    expect(body.token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(body.iss).toBe("http://localhost:8787|login");
    expect(body.sub).toBe(userUuid);
    expect(body.device).toBe(deviceUuid);
    expect(body.scope).toEqual(["api", "offline_access"]);
    expect(body.expires_in).toBeGreaterThan(0);
    expect(body.expires_in).toBeLessThanOrEqual(3600);

    const payload = decodeJwtPayload(body.token);
    expect(payload.iss).toBe("http://localhost:8787|login");
    expect(payload.sub).toBe(userUuid);
    expect(payload.devicetype).toBe("7");
    expect(payload.amr).toEqual(["Application"]);
  });
});
