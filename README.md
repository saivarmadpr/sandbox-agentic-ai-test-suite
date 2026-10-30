# GuardBench

Scenario-driven agentic red teaming. You describe an agent and what it must never do; GuardBench builds a synthetic version of that agent, turns an attacker agent loose on it, and a separate judge scores every break from the target's own database. The same world is rebuilt at three hardening levels, so you can see how much a guardrail actually changes the attack success rate. Full design: [docs/PLAN.md](docs/PLAN.md).

**Status: working skeleton.** End to end: build a target (local process or E2B sandbox) → attacker agent probes it → ground-truth judge → report + live trace. Quality tuning (planner refusals, more attack tactics, E2B egress lockdown, the wb-red-team dashboard) comes next.

## Setup

Node 22.13+ (uses the built-in `node:sqlite`). `wb-red-team` is installed from GitHub, so you need read access to `votal-ai-hq/ai-red-teaming`.

```bash
npm install
cp .env.example .env   # fill in OPENROUTER_API_KEY (and E2B_API_KEY for the sandbox backend)
```

Models are `provider/model` ids. Providers: `openrouter`, `nim` (NVIDIA), `openai`, `together`. OpenRouter alone reaches Anthropic, NVIDIA and open models, so it is the simplest single key.

## Run the bundled example

Attack the ready-made customer-support target at all three hardening levels, locally:

```bash
npm run guardbench -- run examples/customer-support --backend local
```

You will see a live trace (the attacker's reasoning, each message, the target's reply, the judge's verdict) and a summary:

```
level   ASR    over-refusal   planted-bug recall   requests
L0      100%   0%             33%                  3
L2      0%     0%             0%                   3
```

ASR falling as the level rises is the core signal: the guards are doing the work. Results land in `examples/customer-support/`: `report.json` and `events.jsonl`.

### In an E2B sandbox

The target runtime is a single self-contained Node script, so the sandbox path is identical — only where it runs changes:

```bash
npm run guardbench -- run examples/customer-support --backend e2b    # needs E2B_API_KEY
```

The harness uploads the runtime + `world.json`, starts it, and talks to it over its sandbox URL. Egress lockdown and a separate gateway are still TODO (see the plan); today the harness enforces the request budget.

## Write your own scenario

`guardbench plan <scenario.yaml>` turns a scenario into `plan.json` + `world.json` with an LLM, then you `run` that directory. See `scenarios/customer-support.yaml` for the format. Note: a planner model whose policy permits authorized security testing is required — Anthropic models currently refuse the world-design step.

```bash
npm run guardbench -- plan scenarios/customer-support.yaml --out runs/mine
npm run guardbench -- run runs/mine
```

| File in a run directory | What it is |
|---|---|
| `config.json` | The scenario config with defaults filled in |
| `world.json` | The target's world: tables, seed data, tools, guards per level (L0/L1/L2), canaries |
| `plan.json` | Invariants, hypotheses + tasks (attacker side), oracles + benign controls + planted-bug answer key (judge side) |
| `report.json` | Per-level ASR, over-refusal, planted-bug recall, and every hypothesis verdict |
| `events.jsonl` | The full run trace (same lines shown live) |

## How it fits together

| Piece | File |
|---|---|
| Target runtime (loads a world, runs the agent, enforces guards, logs to SQLite) | [templates/target-runtime/server.mjs](templates/target-runtime/server.mjs) |
| Target backends (local process, E2B sandbox) | [src/target.ts](src/target.ts) |
| Attacker agent loop | [src/attacker.ts](src/attacker.ts) |
| Ground-truth judge | [src/judge.ts](src/judge.ts) |
| Orchestrator | [src/run.ts](src/run.ts) |
| Planner | [src/planner.ts](src/planner.ts) |

## Develop

```bash
npm test            # vitest, uses a fake LLM, no API calls
npm run typecheck
```
