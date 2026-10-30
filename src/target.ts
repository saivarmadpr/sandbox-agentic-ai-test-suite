// A running target agent the attacker talks to and the judge inspects. Two
// backends behind one interface: LocalTarget (a child process, for laptop runs
// and tests) and E2bTarget (a sandbox, the real deployment). Swapping them
// changes nothing else in the pipeline.

import { spawn, type ChildProcess } from "node:child_process";
import { copyFileSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const RUNTIME = fileURLToPath(new URL("../templates/target-runtime/server.mjs", import.meta.url));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export interface Target {
  readonly url: string;
  newSession(customerId: string): Promise<string>;
  chat(sessionId: string, message: string): Promise<string>;
  /** Copy the target's SQLite file to `dest` so the judge can read final state. */
  snapshotDb(dest: string): Promise<void>;
  close(): Promise<void>;
}

async function waitForHealth(url: string, label: string, tries = 60): Promise<void> {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(`${url}/health`);
      if (r.ok) return;
    } catch {
      // not up yet
    }
    await sleep(500);
  }
  throw new Error(`${label}: target did not become healthy at ${url}`);
}

async function postJson(url: string, body: unknown): Promise<any> {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`${url} → ${r.status}: ${JSON.stringify(j)}`);
  return j;
}

// ── Local child process ──
export class LocalTarget implements Target {
  readonly url: string;
  private constructor(
    private proc: ChildProcess,
    private dbPath: string,
    port: number,
  ) {
    this.url = `http://127.0.0.1:${port}`;
  }

  static async start(opts: { worldPath: string; dbPath: string; level: string; model: string; port: number }): Promise<LocalTarget> {
    const proc = spawn(
      process.execPath,
      [RUNTIME, "--world", opts.worldPath, "--db", opts.dbPath, "--level", opts.level, "--model", opts.model, "--port", String(opts.port)],
      { stdio: ["ignore", "inherit", "inherit"], env: process.env },
    );
    const target = new LocalTarget(proc, opts.dbPath, opts.port);
    await waitForHealth(target.url, "local");
    return target;
  }

  async newSession(customerId: string): Promise<string> {
    return (await postJson(`${this.url}/session`, { customer_id: customerId })).session_id;
  }
  async chat(sessionId: string, message: string): Promise<string> {
    return (await postJson(`${this.url}/chat`, { session_id: sessionId, message })).reply;
  }
  async snapshotDb(dest: string): Promise<void> {
    copyFileSync(this.dbPath, dest); // same filesystem
  }
  async close(): Promise<void> {
    this.proc.kill("SIGTERM");
  }
}

// ── E2B sandbox ──
// Egress lockdown and a separate gateway sandbox are deferred; the harness
// enforces the request budget. The target sandbox only holds the model key.
export class E2bTarget implements Target {
  readonly url: string;
  private constructor(
    private sandbox: any,
    private remoteDb: string,
  ) {
    const host = sandbox.getHost(8080);
    this.url = `https://${host}`;
  }

  static async start(opts: { worldPath: string; level: string; model: string; modelKeyEnv: string }): Promise<E2bTarget> {
    let Sandbox: any;
    try {
      ({ Sandbox } = await import("e2b"));
    } catch {
      throw new Error('E2B backend needs the "e2b" package: run `npm install e2b`.');
    }
    if (!process.env.E2B_API_KEY) throw new Error("E2B backend needs E2B_API_KEY.");
    const modelKey = process.env[opts.modelKeyEnv];
    if (!modelKey) throw new Error(`target model needs ${opts.modelKeyEnv} to pass into the sandbox.`);

    const sandbox = await Sandbox.create({ timeoutMs: 15 * 60_000 });
    await sandbox.files.write("/home/user/server.mjs", readFileSync(RUNTIME, "utf8"));
    await sandbox.files.write("/home/user/world.json", readFileSync(opts.worldPath, "utf8"));
    // Start the runtime in the background; it listens on 8080.
    await sandbox.commands.run(
      `cd /home/user && ${opts.modelKeyEnv}='${modelKey}' GB_MODEL='${opts.model}' nohup node server.mjs --world world.json --db target.db --level ${opts.level} --port 8080 > runtime.log 2>&1 &`,
      { background: true },
    );
    const target = new E2bTarget(sandbox, "/home/user/target.db");
    await waitForHealth(target.url, "e2b");
    return target;
  }

  async newSession(customerId: string): Promise<string> {
    return (await postJson(`${this.url}/session`, { customer_id: customerId })).session_id;
  }
  async chat(sessionId: string, message: string): Promise<string> {
    return (await postJson(`${this.url}/chat`, { session_id: sessionId, message })).reply;
  }
  async snapshotDb(dest: string): Promise<void> {
    const bytes: Uint8Array = await this.sandbox.files.read(this.remoteDb, { format: "bytes" });
    writeFileSync(dest, bytes);
  }
  async close(): Promise<void> {
    await this.sandbox.kill();
  }
}

export function worldModelKeyEnv(model: string): string {
  const provider = model.slice(0, model.indexOf("/")).toLowerCase();
  const map: Record<string, string> = {
    openrouter: "OPENROUTER_API_KEY",
    nim: "NVIDIA_API_KEY",
    openai: "OPENAI_API_KEY",
    together: "TOGETHER_API_KEY",
  };
  return map[provider] ?? "OPENROUTER_API_KEY";
}
