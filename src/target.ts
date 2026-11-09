// A running target agent the attacker talks to and the judge inspects. Two
// backends behind one interface: LocalTarget (a child process, for laptop runs
// and tests) and E2bTarget (a sandbox, the real deployment). Swapping them
// changes nothing else in the pipeline.

import { spawn, type ChildProcess } from "node:child_process";
import { copyFileSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, type AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";

const RUNTIME = fileURLToPath(new URL("../templates/target-runtime/server.mjs", import.meta.url));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Ask the OS for an unused loopback port, so we never collide with whatever
 *  else is running on the machine. */
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address() as AddressInfo;
      srv.close(() => resolve(port));
    });
  });
}

export interface Target {
  readonly url: string;
  newSession(customerId: string): Promise<string>;
  chat(sessionId: string, message: string): Promise<string>;
  /** Copy the target's SQLite file to `dest` so the judge can read final state. */
  snapshotDb(dest: string): Promise<void>;
  close(): Promise<void>;
}

async function waitForHealth(url: string, label: string, headers: Record<string, string> = {}, tries = 60): Promise<void> {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(`${url}/health`, { headers });
      if (r.ok) return;
    } catch {
      // not up yet
    }
    await sleep(500);
  }
  throw new Error(`${label}: target did not become healthy at ${url}`);
}

async function postJson(url: string, body: unknown, headers: Record<string, string> = {}): Promise<any> {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
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

  static async start(opts: { worldPath: string; dbPath: string; level: string; model: string }): Promise<LocalTarget> {
    // ponytail: tiny TOCTOU window between probe and child bind; on collision the
    // health check fails and we kill the child below, so the level errors cleanly
    // instead of leaking a process or talking to a stranger's server.
    const port = await freePort();
    const proc = spawn(
      process.execPath,
      [RUNTIME, "--world", opts.worldPath, "--db", opts.dbPath, "--level", opts.level, "--model", opts.model, "--port", String(port), "--host", "127.0.0.1"],
      { stdio: ["ignore", "inherit", "inherit"], env: process.env },
    );
    const target = new LocalTarget(proc, opts.dbPath, port);
    try {
      await waitForHealth(target.url, "local");
    } catch (e) {
      proc.kill("SIGKILL");
      throw e;
    }
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
  // E2B secures the public sandbox URL behind a per-sandbox traffic token.
  private readonly traffic: Record<string, string>;
  private constructor(
    private sandbox: any,
    private remoteDb: string,
  ) {
    this.url = `https://${sandbox.getHost(8080)}`;
    this.traffic = { "e2b-traffic-access-token": sandbox.trafficAccessToken };
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

    // The base image ships Node 20, which lacks node:sqlite. Install a Node 24
    // static build so the (unchanged) runtime runs exactly as it does locally.
    // ponytail: ~20s per sandbox; bake Node 24 into a custom E2B template if this
    // startup cost ever matters.
    await sandbox.commands.run(
      `set -e; cd /home/user
       V=$(curl -fsSL https://nodejs.org/dist/index.json | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{const j=JSON.parse(d);console.log(j.find(x=>x.version.startsWith("v24."))?.version)})')
       curl -fsSL "https://nodejs.org/dist/$V/node-$V-linux-x64.tar.xz" | tar xJ
       mv "node-$V-linux-x64" node24`,
      { timeoutMs: 120_000 },
    );

    // Start the runtime in the background; it listens on 8080.
    await sandbox.commands.run(
      `cd /home/user && ${opts.modelKeyEnv}='${modelKey}' GB_MODEL='${opts.model}' nohup ./node24/bin/node server.mjs --world world.json --db target.db --level ${opts.level} --port 8080 --host 0.0.0.0 > runtime.log 2>&1 &`,
      { background: true },
    );
    const target = new E2bTarget(sandbox, "/home/user/target.db");
    try {
      await waitForHealth(target.url, "e2b", target.traffic);
    } catch (e) {
      const log = await sandbox.commands.run("cat /home/user/runtime.log 2>&1 || true").catch(() => null);
      await sandbox.kill().catch(() => {});
      const tail = log ? `${log.stdout ?? ""}${log.stderr ?? ""}`.trim().slice(-500) : "";
      throw new Error(`${e instanceof Error ? e.message : String(e)}${tail ? `; runtime.log: ${tail}` : ""}`);
    }
    return target;
  }

  async newSession(customerId: string): Promise<string> {
    return (await postJson(`${this.url}/session`, { customer_id: customerId }, this.traffic)).session_id;
  }
  async chat(sessionId: string, message: string): Promise<string> {
    return (await postJson(`${this.url}/chat`, { session_id: sessionId, message }, this.traffic)).reply;
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
