import { describe, it, expect } from "vitest";

const BASE_URL = process.env.WORKER_URL ?? "http://127.0.0.1:8787";

async function get(path: string, init?: RequestInit) {
  return fetch(`${BASE_URL}${path}`, init);
}

describe("phase 0: /alive parity", () => {
  it("GET /alive returns an RFC3339 datetime as a JSON string", async () => {
    const res = await get("/alive");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(typeof body).toBe("string");
    expect(body).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z$/);
  });

  it("GET /api/alive returns the same shape", async () => {
    const res = await get("/api/alive");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(typeof body).toBe("string");
    expect(body).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z$/);
  });

  it("GET /api/now returns an RFC3339 datetime as a JSON string", async () => {
    const res = await get("/api/now");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(typeof body).toBe("string");
    expect(body).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z$/);
  });

  it("GET /api/version returns a non-empty version string", async () => {
    const res = await get("/api/version");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(typeof body).toBe("string");
    expect((body as string).length).toBeGreaterThan(0);
  });
});
