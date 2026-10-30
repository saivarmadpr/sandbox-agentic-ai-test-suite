// Orchestrator: for each hardening level, stand up the target, run every
// hypothesis with the attacker through one request budget, judge each from the
// target's database, run the benign controls, and tear the target down. All
// three levels share the same world and seed, so results are comparable.

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Config } from "./config.js";
import { runHypothesis } from "./attacker.js";
import { Events } from "./events.js";
import { countRows, judgeOracle } from "./judge.js";
import type { Plan } from "./plan.js";
import { buildLevelReport, type BenignResult, type HypothesisResult, type LevelReport, type Report } from "./report.js";
import { E2bTarget, LocalTarget, worldModelKeyEnv, type Target } from "./target.js";
import type { World } from "./world.js";

export interface RunInputs {
  config: Config;
  plan: Plan;
  world: World;
  worldPath: string;
  runDir: string;
  backend: "local" | "e2b";
  eventsFile: string;
}

const randomPort = () => 8800 + Math.floor(Math.random() * 150);

/** API keys to redact from the event log and trace. */
function collectSecrets(): string[] {
  const envs = ["OPENROUTER_API_KEY", "NVIDIA_API_KEY", "OPENAI_API_KEY", "TOGETHER_API_KEY", "E2B_API_KEY", "ANTHROPIC_API_KEY"];
  return envs.map((e) => process.env[e]).filter((v): v is string => !!v);
}

export async function runScenario(inputs: RunInputs): Promise<Report> {
  const { config, plan, world, worldPath, runDir, backend } = inputs;
  const attackerModel = config.models.attacker[0];
  const events = new Events(inputs.eventsFile, collectSecrets());

  events.emit({
    kind: "run",
    scenario: config.target.name,
    levels: config.target.levels,
    target_model: config.target.model,
    attacker_model: attackerModel,
  });

  const levels: LevelReport[] = [];
  const oracleById = new Map(plan.oracles.map((o) => [o.id, o]));

  for (const level of config.target.levels) {
    events.emit({ kind: "level", level });
    let target: Target | undefined;
    const snap = join(mkdtempSync(join(tmpdir(), "gb-")), "snap.db");
    try {
      if (backend === "e2b") {
        target = await E2bTarget.start({
          worldPath,
          level,
          model: config.target.model,
          modelKeyEnv: worldModelKeyEnv(config.target.model),
        });
      } else {
        target = await LocalTarget.start({
          worldPath,
          dbPath: join(runDir, `target-${level}.db`),
          level,
          model: config.target.model,
          port: randomPort(),
        });
      }
      events.emit({ kind: "env", message: `${backend} target ready at ${target.url} (level ${level})` });

      const attackerSession = await target.newSession(world.identities.attacker_customer_id);
      const budget = config.constraints.max_requests;
      let used = 0;
      const hypResults: HypothesisResult[] = [];

      for (const h of plan.hypotheses) {
        if (used >= budget) break;
        const oracle = oracleById.get(h.oracle);
        events.emit({ kind: "hypothesis", level, id: h.id, invariant: h.invariant, title: h.title });
        await target.snapshotDb(snap);
        const before = oracle ? countRows(snap, oracle.violation_sql) : 0;

        const send = async (message: string): Promise<string> => {
          if (used >= budget) throw new Error("request budget exhausted");
          used++;
          return target!.chat(attackerSession, message);
        };
        const run = await runHypothesis({
          model: attackerModel,
          customerId: world.identities.attacker_customer_id,
          hypothesis: h,
          level,
          maxTurns: config.constraints.max_turns_per_hypothesis,
          send,
          events,
        });

        await target.snapshotDb(snap);
        const outcome = oracle
          ? judgeOracle(snap, oracle.violation_sql, before)
          : { vulnerable: false, detail: "no oracle" };
        if (run.error) events.emit({ kind: "error", where: `${level} ${h.id}`, message: run.error });
        events.emit({ kind: "verdict", level, hid: h.id, vulnerable: outcome.vulnerable, detail: outcome.detail, requests: used });
        hypResults.push({
          level,
          id: h.id,
          invariant: h.invariant,
          category: h.category,
          title: h.title,
          vulnerable: outcome.vulnerable,
          requests: run.requests,
          detail: outcome.detail,
          attacker_summary: run.concluded?.summary ?? null,
          error: run.error,
        });
        events.emit({ kind: "budget", level, used, max: budget });
      }

      // Benign controls — legitimate requests that must still be served.
      const benign: BenignResult[] = [];
      for (const b of plan.benign_controls) {
        const session = await target.newSession(b.as_customer_id);
        await target.snapshotDb(snap);
        const before = countRows(snap, b.success_sql);
        try {
          await target.chat(session, b.request);
        } catch (e) {
          events.emit({ kind: "error", where: `${level} ${b.id}`, message: e instanceof Error ? e.message : String(e) });
        }
        await target.snapshotDb(snap);
        const served = countRows(snap, b.success_sql) > before;
        events.emit({ kind: "benign", level, id: b.id, served, request: b.request });
        benign.push({ level, id: b.id, invariant: b.invariant, served, request: b.request });
      }

      levels.push(buildLevelReport(level, hypResults, benign, plan.planted_bugs));
    } catch (e) {
      events.emit({ kind: "error", where: `level ${level}`, message: e instanceof Error ? e.message : String(e) });
    } finally {
      await target?.close();
    }
  }

  return {
    scenario: config.target.name,
    created_at: new Date().toISOString(),
    target_model: config.target.model,
    attacker_model: attackerModel,
    levels,
  };
}
