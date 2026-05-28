import { spawn, type ChildProcess } from "node:child_process";

const PORT = 8787;
const BASE_URL = `http://127.0.0.1:${PORT}`;

let proc: ChildProcess | null = null;

async function waitFor(url: string, timeoutMs: number) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {
      // not ready yet
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`wrangler dev did not become ready at ${url} within ${timeoutMs}ms`);
}

export async function setup() {
  process.env.WORKER_URL = BASE_URL;

  proc = spawn("npx", ["wrangler", "dev", "--env", "", "--port", String(PORT), "--ip", "127.0.0.1"], {
    stdio: ["ignore", "inherit", "inherit"],
    env: { ...process.env, FORCE_COLOR: "0" },
  });

  proc.on("exit", (code) => {
    if (code !== null && code !== 0) {
      console.error(`wrangler dev exited with code ${code}`);
    }
  });

  await waitFor(`${BASE_URL}/alive`, 240_000);
}

export async function teardown() {
  if (proc) {
    proc.kill("SIGTERM");
    await new Promise((r) => setTimeout(r, 500));
    if (!proc.killed) proc.kill("SIGKILL");
  }
}
