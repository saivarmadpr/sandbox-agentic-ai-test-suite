// GuardBench web UI: a local dashboard over the run directories. It lists runs,
// starts and stops them by spawning the CLI, and streams each run's
// events.jsonl to the browser as the live reasoning trace. No state of its own
// beyond a small ui.json per run; everything else is the CLI's own output.

import { spawn, type ChildProcess } from "node:child_process";
import { closeSync, copyFileSync, existsSync, mkdirSync, openSync, readFileSync, readSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { basename, join } from "node:path";
import { createInterface } from "node:readline";
import { StringDecoder } from "node:string_decoder";
import { fileURLToPath } from "node:url";
import { LEVELS } from "./config.js";
import { collectSecrets } from "./run.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const CLI = fileURLToPath(new URL("./cli.ts", import.meta.url));
const PAGE = fileURLToPath(new URL("../web/index.html", import.meta.url));
const RUN_FILES = ["config.json", "plan.json", "world.json"];

interface Job {
  child?: ChildProcess;
  phase: "plan" | "run";
  log: { ts: string; text: string }[]; // process output the event log doesn't carry
  done: boolean;
  stopped: boolean;
}
const jobs = new Map<string, Job>();
const isActive = (id: string) => jobs.get(id)?.done === false;

class HttpError extends Error {
  constructor(
    public code: number,
    message: string,
  ) {
    super(message);
  }
}

const readJson = (path: string): any => {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return null;
  }
};
const at = (id: string, file = "") => join(ROOT, id, file);

/** Every run directory under examples/ and runs/, as "base/name" ids. This list
 *  is the allowlist for ids coming from the browser. */
function runDirs(): string[] {
  const out: string[] = [];
  for (const base of ["examples", "runs"]) {
    if (!existsSync(join(ROOT, base))) continue;
    for (const d of readdirSync(join(ROOT, base), { withFileTypes: true })) {
      if (d.isDirectory() && /^[\w-][\w.-]*$/.test(d.name)) out.push(`${base}/${d.name}`);
    }
  }
  return out;
}

const runnable = (id: string) => RUN_FILES.every((f) => existsSync(at(id, f)));

function summary(id: string) {
  const config = readJson(at(id, "config.json"));
  const report = readJson(at(id, "report.json"));
  const meta = readJson(at(id, "ui.json")) ?? {};
  let events = 0;
  let first: string | undefined;
  let last: string | undefined;
  let backend: string | undefined = meta.backend;
  if (existsSync(at(id, "events.jsonl"))) {
    const text = readFileSync(at(id, "events.jsonl"), "utf8");
    const lines = text.split("\n").filter(Boolean);
    events = lines.length;
    first = readTs(lines[0]);
    last = readTs(lines[lines.length - 1]);
    backend ??= /"message":"(local|e2b) target ready/.exec(text)?.[1];
  }
  const job = jobs.get(id);
  const status = isActive(id)
    ? job!.phase === "plan"
      ? "planning"
      : "running"
    : meta.status === "running"
      ? "interrupted" // the UI server went away mid-run
      : (meta.status ?? (report ? "completed" : events ? "interrupted" : "ready"));
  return {
    id,
    scenario: config?.target?.name ?? basename(id),
    status,
    backend: backend ?? null,
    started_at: meta.started_at ?? first ?? report?.created_at ?? null,
    ended_at: isActive(id) ? null : (meta.ended_at ?? last ?? null),
    events,
    levels: (report?.levels ?? []).map((l: any) => ({ level: l.level, asr: l.asr })),
    findings: report ? report.levels.reduce((n: number, l: any) => n + l.hypotheses.filter((h: any) => h.vulnerable).length, 0) : null,
  };
}

function readTs(line: string | undefined): string | undefined {
  try {
    return JSON.parse(line ?? "").ts;
  } catch {
    return undefined;
  }
}

function sources() {
  const prepared = runDirs()
    .filter(runnable)
    .map((id) => ({ id, kind: "prepared", label: readJson(at(id, "config.json"))?.target?.name ?? id }));
  const scen = join(ROOT, "scenarios");
  const yamls = existsSync(scen)
    ? readdirSync(scen)
        .filter((f) => /^[\w-][\w.-]*\.ya?ml$/.test(f))
        .map((f) => ({ id: `scenarios/${f}`, kind: "scenario", label: f }))
    : [];
  return [...prepared, ...yamls];
}

function state() {
  const runs = runDirs()
    .map(summary)
    .filter((r) => r.status !== "ready")
    .sort((a, b) => String(b.started_at).localeCompare(String(a.started_at)));
  return {
    runs,
    sources: sources(),
    levels: LEVELS,
    keys: { openrouter: !!process.env.OPENROUTER_API_KEY, e2b: !!process.env.E2B_API_KEY },
  };
}

// ── Starting and stopping runs ──

const secrets = () => collectSecrets().filter((s) => s.length >= 6);
function clean(line: string): string {
  let out = line.replace(/\x1b\[[0-9;]*m/g, "").trimEnd();
  for (const s of secrets()) out = out.split(s).join("«redacted»");
  return out;
}

function writeMeta(id: string, patch: Record<string, unknown>): void {
  writeFileSync(at(id, "ui.json"), JSON.stringify({ ...readJson(at(id, "ui.json")), ...patch }, null, 2));
}

/** Run one CLI command for a job. The child leads its own process group so
 *  stopping the run also takes down the target runtime it spawned. */
function exec(job: Job, args: string[], onExit: (code: number) => void): void {
  const child = spawn(process.execPath, [...process.execArgv, CLI, ...args], {
    cwd: ROOT,
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  job.child = child;
  const note = (text: string) => text && job.log.push({ ts: new Date().toISOString(), text });
  // During a run, stdout only repeats events.jsonl; during planning it is the only trace.
  createInterface({ input: child.stdout! }).on("line", (l) => job.phase === "plan" && note(clean(l)));
  createInterface({ input: child.stderr! }).on("line", (l) => note(clean(l)));
  let settled = false;
  const settle = (code: number) => {
    if (settled) return;
    settled = true;
    onExit(code);
  };
  child.on("error", (e) => (note(`could not start: ${e.message}`), settle(1)));
  child.on("exit", (code) => settle(code ?? 1));
}

function startRun(body: any): string {
  const source = sources().find((s) => s.id === body?.source);
  if (!source) throw new HttpError(400, "Pick a scenario to run.");
  const backend = body.backend;
  if (backend !== "local" && backend !== "e2b") throw new HttpError(400, 'Backend must be "local" or "e2b".');
  if (backend === "e2b" && !process.env.E2B_API_KEY) throw new HttpError(400, "E2B_API_KEY is not set in .env.");
  const levels = LEVELS.filter((l) => Array.isArray(body.levels) && body.levels.includes(l));
  if (levels.length === 0) throw new HttpError(400, "Pick at least one hardening level.");
  const budget = Number(body.max_requests);
  if (!Number.isInteger(budget) || budget < 1 || budget > 1000) throw new HttpError(400, "Request budget must be 1–1000.");

  // Each run gets its own directory, so earlier results are never overwritten.
  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace("T", "-").slice(0, 15);
  const slug = basename(source.id)
    .replace(/\.ya?ml$/, "")
    .replace(/^\d{8}-\d{6}-/, "")
    .replace(/-(local|e2b)$/, "");
  const id = `runs/${stamp}-${slug}-${backend}`;
  if (existsSync(at(id))) throw new HttpError(409, "A run with this name just started. Try again in a second.");
  mkdirSync(at(id), { recursive: true });

  const job: Job = { phase: source.kind === "scenario" ? "plan" : "run", log: [], done: false, stopped: false };
  jobs.set(id, job);
  writeMeta(id, { source: source.id, backend, started_at: new Date().toISOString(), status: "running" });

  const finish = (code: number) => {
    job.done = true;
    writeMeta(id, { ended_at: new Date().toISOString(), status: job.stopped ? "stopped" : code === 0 ? "completed" : "failed" });
  };
  const attack = () => {
    const config = readJson(at(id, "config.json"));
    config.target.levels = levels;
    config.constraints.max_requests = budget;
    writeFileSync(at(id, "config.json"), JSON.stringify(config, null, 2));
    job.phase = "run";
    exec(job, ["run", id, "--backend", backend], finish);
  };

  if (source.kind === "scenario") {
    exec(job, ["plan", source.id, "--out", id], (code) => (code === 0 && !job.stopped ? attack() : finish(code)));
  } else {
    for (const f of RUN_FILES) copyFileSync(at(source.id, f), at(id, f));
    attack();
  }
  return id;
}

function stopRun(id: string): void {
  const job = jobs.get(id);
  if (!job || job.done || !job.child?.pid) throw new HttpError(409, "This run is not active.");
  job.stopped = true;
  // ponytail: kills the local process group; an E2B sandbox is left to its own
  // 15-minute timeout. Kill it via the SDK here if stranded sandboxes matter.
  try {
    process.kill(-job.child.pid, "SIGTERM");
  } catch {
    job.child.kill("SIGTERM");
  }
}

// ── Live stream ──

/** Server-sent events: the run's events.jsonl from the top, then new lines as
 *  they are appended, until the run is over. Finished runs replay and close. */
function stream(id: string, res: ServerResponse): void {
  res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-store", Connection: "keep-alive" });
  const file = at(id, "events.jsonl");
  const decoder = new StringDecoder("utf8");
  let offset = 0;
  let carry = "";
  let logIdx = 0;
  const send = (event: string, data: string) => res.write(`event: ${event}\ndata: ${data}\n\n`);

  const tick = () => {
    const active = isActive(id); // sampled first, so the last lines are drained after exit
    const size = existsSync(file) ? statSync(file).size : 0;
    if (size > offset) {
      const buf = Buffer.alloc(size - offset);
      const fd = openSync(file, "r");
      readSync(fd, buf, 0, buf.length, offset);
      closeSync(fd);
      offset = size;
      const parts = (carry + decoder.write(buf)).split("\n");
      carry = parts.pop() ?? "";
      for (const line of parts) if (line) send("ev", line);
    }
    const job = jobs.get(id);
    for (; job && logIdx < job.log.length; logIdx++) send("log", JSON.stringify(job.log[logIdx]));
    if (!active) {
      send("end", JSON.stringify({ status: summary(id).status }));
      clearInterval(timer);
      res.end();
    }
  };
  // ponytail: polls the file every 300ms per viewer; switch to fs.watch if many
  // people ever watch at once.
  const timer = setInterval(tick, 300);
  res.on("close", () => clearInterval(timer));
  tick();
}

// ── HTTP ──

/** Loopback only, and no cross-site requests: this server can spawn processes. */
function trusted(req: IncomingMessage): boolean {
  const host = req.headers.host ?? "";
  if (!/^(127\.0\.0\.1|localhost)(:\d+)?$/.test(host)) return false;
  const origin = req.headers.origin;
  return !origin || origin === `http://${host}`;
}

function readBody(req: IncomingMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    let b = "";
    req.on("data", (c) => {
      b += c;
      if (b.length > 65536) reject(new HttpError(413, "Request too large."));
    });
    req.on("end", () => {
      try {
        resolve(b ? JSON.parse(b) : {});
      } catch {
        reject(new HttpError(400, "Body must be JSON."));
      }
    });
  });
}

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const json = (code: number, obj: unknown) => {
    res.writeHead(code, { "Content-Type": "application/json", "Cache-Control": "no-store" });
    res.end(JSON.stringify(obj));
  };
  try {
    if (!trusted(req)) throw new HttpError(403, "Forbidden.");
    const path = new URL(req.url ?? "/", "http://localhost").pathname;
    const get = req.method === "GET";
    const post = req.method === "POST";

    if (get && path === "/") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
      res.end(readFileSync(PAGE));
      return;
    }
    if (get && path === "/api/state") return json(200, state());
    if (post && path === "/api/runs") return json(200, { id: startRun(await readBody(req)) });

    const m = /^\/api\/runs\/((?:examples|runs)\/[^/]+)(\/stream|\/stop)?$/.exec(path);
    if (m && runDirs().includes(m[1])) {
      const [, id, action] = m;
      if (get && action === "/stream") return stream(id, res);
      if (post && action === "/stop") return stopRun(id), json(200, { ok: true });
      if (get && !action) {
        const hypotheses = (readJson(at(id, "plan.json"))?.hypotheses ?? []).map((h: any) => ({
          id: h.id,
          invariant: h.invariant,
          category: h.category,
          title: h.title,
        }));
        return json(200, { summary: summary(id), report: readJson(at(id, "report.json")), hypotheses });
      }
    }
    throw new HttpError(404, "Not found.");
  } catch (e) {
    json(e instanceof HttpError ? e.code : 500, { error: e instanceof Error ? e.message : String(e) });
  }
}

export function serveUi(port: number): void {
  const server = createServer(handle);
  // Take active runs down with the server instead of orphaning them.
  const stopAll = () => {
    for (const id of jobs.keys()) {
      try {
        if (isActive(id)) stopRun(id);
      } catch {
        // already gone
      }
    }
  };
  process.on("SIGINT", () => (stopAll(), process.exit(0)));
  process.on("SIGTERM", () => (stopAll(), process.exit(0)));
  server.listen(port, "127.0.0.1", () => console.log(`GuardBench UI at http://127.0.0.1:${port}`));
}
