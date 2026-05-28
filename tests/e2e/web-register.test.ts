import { describe, it, expect } from "vitest";

const BASE_URL = process.env.WORKER_URL ?? "http://127.0.0.1:8787";

async function req(path: string, init?: RequestInit) {
  return fetch(`${BASE_URL}${path}`, init);
}

describe("phase 5: web client registration (send-verification + finish)", () => {
  it("send-verification returns a token when SMTP is the LogProvider, then finish creates the user", async () => {
    const email = `webreg-${Date.now()}@example.com`;
    const sendRes = await req("/identity/accounts/register/send-verification-email", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, name: "Web Reg", receiveMarketingEmails: false }),
    });
    expect(sendRes.status).toBe(200);
    const token = (await sendRes.json()) as string;
    expect(typeof token).toBe("string");
    expect(token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);

    const hash = new Uint8Array(32);
    for (let i = 0; i < hash.length; i++) hash[i] = (i * 13 + 7) & 0xff;
    let bin = "";
    for (const b of hash) bin += String.fromCharCode(b);
    const hashB64 = Buffer.from(bin, "binary").toString("base64");

    const finishRes = await req("/identity/accounts/register/finish", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        email,
        name: "Web Reg",
        emailVerificationToken: token,
        masterPasswordHash: hashB64,
        masterPasswordHint: null,
        userSymmetricKey: "0.encrypted-symmetric-key",
        userAsymmetricKeys: {
          publicKey: "MFw...stub",
          encryptedPrivateKey: "0.encrypted-private-key",
        },
        kdf: 0,
        kdfIterations: 600000,
      }),
    });
    expect(finishRes.status).toBe(200);
    const body = (await finishRes.json()) as { Object: string };
    expect(body.Object).toBe("register");

    // Should be able to log in with the credentials we just registered.
    const loginForm = new URLSearchParams();
    loginForm.set("grant_type", "password");
    loginForm.set("scope", "api offline_access");
    loginForm.set("client_id", "web");
    loginForm.set("deviceIdentifier", "00000000-0000-4000-8000-0000webreg01");
    loginForm.set("deviceName", "WebReg");
    loginForm.set("deviceType", "9");
    loginForm.set("username", email);
    loginForm.set("password", hashB64);

    const login = await req("/identity/connect/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: loginForm.toString(),
    });
    expect(login.status).toBe(200);
  });

  it("finish rejects a token whose email doesn't match", async () => {
    const sendRes = await req("/identity/accounts/register/send-verification-email", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: `mismatch-${Date.now()}@example.com` }),
    });
    expect(sendRes.status).toBe(200);
    const token = (await sendRes.json()) as string;

    const r = await req("/identity/accounts/register/finish", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        email: "different@example.com",
        emailVerificationToken: token,
        masterPasswordHash: "AAAA",
        userSymmetricKey: "k",
      }),
    });
    expect(r.status).toBe(400);
    const body = (await r.json()) as { error: string };
    expect(body.error).toBe("invalid_grant");
  });

  it("finish without a token still works (registration without email verification)", async () => {
    const email = `notoken-${Date.now()}@example.com`;
    const r = await req("/identity/accounts/register/finish", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        email,
        masterPasswordHash: "AAAA",
        userSymmetricKey: "0.k",
      }),
    });
    expect(r.status).toBe(200);
  });

  it("rejects empty email on send-verification", async () => {
    const r = await req("/identity/accounts/register/send-verification-email", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "" }),
    });
    expect(r.status).toBe(400);
  });
});
