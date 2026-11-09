#!/usr/bin/env -S npx tsx
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs, parseEnv } from "node:util";
import { loadConfig, parseConfig, type Config } from "./config.js";
import { makeLlm } from "./llm.js";
import { runPlanner } from "./planner.js";
import type { Plan } from "./plan.js";
import { runScenario } from "./run.js";
import { printSummary } from "./report.js";
import { WorldSchema } from "./world.js";

const USAGE = `Usage:
  guardbench plan <scenario.yaml> [--out <dir>]        Generate plan.json + world.json
  guardbench run  <dir> [--backend local|e2b]          Attack the target and score it
     <dir> must contain world.json + plan.json (+ config.json). Defaults to --backend local.
  guardbench ui   [--port 4173]                        Open the dashboard (start runs, watch the live trace)`;

const tag = (label: string) => `\x1b[36m[${label.padEnd(5)}]\x1b[0m`;

function loadEnv(): void {
  // Non-empty values in the project's .env win over shell variables.
  if (existsSync(".env")) {
    for (const [k, v] of Object.entries(parseEnv(readFileSync(".env", "utf8")))) if (v) process.env[k] = v;
  }
}

async function plan(args: string[]): Promise<void> {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: { out: { type: "string" } } });
  if (positionals.length !== 1) throw new Error(USAGE);

  const config = loadConfig(positionals[0]);
  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace("T", "-").slice(0, 15);
  const slug = config.target.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  const dir = values.out ?? join("runs", `${stamp}-${slug}`);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "config.json"), JSON.stringify(config, null, 2));
  const transcript = join(dir, "planner-transcript.jsonl");

  console.log(`${tag("plan")} ${config.target.name} · planner ${config.models.planner} · out ${dir}`);
  const result = await runPlanner(config, makeLlm(config.models.planner, "planning"), {
    log: (line) => console.log(`${tag("plan")} ${line}`),
    onAttempt: (a) => appendFileSync(transcript, JSON.stringify({ ts: new Date().toISOString(), ...a }) + "\n"),
  });

  writeFileSync(join(dir, "plan.json"), JSON.stringify(result.plan, null, 2));
  writeFileSync(join(dir, "world.json"), JSON.stringify(result.world, null, 2));
  console.log(`${tag("done")} wrote ${join(dir, "plan.json")} and ${join(dir, "world.json")}`);
}

async function run(args: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: { backend: { type: "string", default: "local" } },
  });
  if (positionals.length !== 1) throw new Error(USAGE);
  const backend = values.backend;
  if (backend !== "local" && backend !== "e2b") throw new Error('--backend must be "local" or "e2b"');

  const dir = positionals[0];
  const config: Config = parseConfig(JSON.parse(readFileSync(join(dir, "config.json"), "utf8")));
  const plan: Plan = JSON.parse(readFileSync(join(dir, "plan.json"), "utf8"));
  const worldPath = join(dir, "world.json");
  const world = WorldSchema.parse(JSON.parse(readFileSync(worldPath, "utf8")));
  const eventsFile = join(dir, "events.jsonl");
  writeFileSync(eventsFile, "");

  const report = await runScenario({ config, plan, world, worldPath, runDir: dir, backend, eventsFile });
  writeFileSync(join(dir, "report.json"), JSON.stringify(report, null, 2));
  printSummary(report, (s) => console.log(s));
  console.log(`${tag("done")} wrote ${join(dir, "report.json")} and ${eventsFile}`);
}

async function main(): Promise<void> {
  loadEnv();
  const [command, ...rest] = process.argv.slice(2);
  if (command === "plan") return plan(rest);
  if (command === "run") return run(rest);
  if (command === "ui") {
    const { values } = parseArgs({ args: rest, options: { port: { type: "string", default: "4173" } } });
    return (await import("./ui.js")).serveUi(Number(values.port));
  }
  console.log(USAGE);
  process.exitCode = command ? 1 : 0;
}

main().catch((e: unknown) => {
  console.error(`${tag("error")} ${e instanceof Error ? e.message : String(e)}`);
  process.exitCode = 1;
});
