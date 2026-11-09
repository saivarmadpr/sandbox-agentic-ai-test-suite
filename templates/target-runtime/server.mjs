// GuardBench target runtime — the synthetic agent under test.
//
// Self-contained: Node builtins + global fetch only, so it runs identically on
// a laptop and inside an E2B sandbox with `node server.mjs` (no deps, no build).
// It loads a world.json, serves a chat endpoint backed by an LLM tool-calling
// loop, enforces the world's guards at the chosen hardening level, and logs
// every message and tool call to a SQLite file the judge reads out-of-band.
//
// Usage:
//   GB_MODEL=openrouter/anthropic/claude-haiku-5.5 OPENROUTER_API_KEY=... \
//   node server.mjs --world world.json --db target.db --level L1 --port 8080

import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { parseArgs } from "node:util";

const { values } = parseArgs({
  options: {
    world: { type: "string" },
    db: { type: "string", default: "target.db" },
    level: { type: "string", default: "L1" },
    port: { type: "string", default: "8080" },
    host: { type: "string", default: "127.0.0.1" },
    model: { type: "string" },
  },
});
const MODEL = values.model ?? process.env.GB_MODEL;
if (!values.world || !MODEL) {
  console.error("need --world <world.json> and --model/GB_MODEL <provider/model>");
  process.exit(1);
}
const LEVEL = values.level;
const world = JSON.parse(readFileSync(values.world, "utf8"));
const SESSION_PARAM = "session_customer_id";
const MAX_TOOL_ROUNDS = 8;

// ── Provider routing (OpenAI-compatible endpoints) ──
const PROVIDERS = {
  openrouter: { base: "https://openrouter.ai/api/v1", key: "OPENROUTER_API_KEY" },
  nim: { base: "https://integrate.api.nvidia.com/v1", key: "NVIDIA_API_KEY" },
  openai: { base: "https://api.openai.com/v1", key: "OPENAI_API_KEY" },
  together: { base: "https://api.together.xyz/v1", key: "TOGETHER_API_KEY" },
};
const slash = MODEL.indexOf("/");
const providerName = MODEL.slice(0, slash).toLowerCase();
const modelName = MODEL.slice(slash + 1);
const provider = PROVIDERS[providerName];
if (!provider) {
  console.error(`unknown provider "${providerName}"; use one of ${Object.keys(PROVIDERS).join(", ")}`);
  process.exit(1);
}
const apiKey = process.env[provider.key];
if (!apiKey) {
  console.error(`missing ${provider.key} for provider "${providerName}"`);
  process.exit(1);
}

// ── Database: runtime tables + world schema + seed + canaries ──
const db = new DatabaseSync(values.db);
const RUNTIME_SQL = [
  `CREATE TABLE IF NOT EXISTS _messages (id INTEGER PRIMARY KEY, session_id TEXT NOT NULL, customer_id TEXT NOT NULL, role TEXT NOT NULL, content TEXT NOT NULL, ts TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS _tool_calls (id INTEGER PRIMARY KEY, session_id TEXT NOT NULL, customer_id TEXT NOT NULL, tool TEXT NOT NULL, args_json TEXT NOT NULL, result_json TEXT, blocked_by TEXT, ts TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS _canaries (value TEXT PRIMARY KEY, owner_customer_id TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS _sessions (id TEXT PRIMARY KEY, customer_id TEXT NOT NULL)`,
];
for (const sql of RUNTIME_SQL) db.exec(sql);
// Fresh business state each boot, so repeated runs start clean.
for (const sql of world.schema_sql) db.exec(sql.replace(/^CREATE TABLE /i, "CREATE TABLE IF NOT EXISTS "));
const seeded = db.prepare("SELECT count(*) AS n FROM _canaries").get().n;
if (seeded === 0) {
  for (const sql of world.seed_sql) db.exec(sql);
  const ins = db.prepare("INSERT OR REPLACE INTO _canaries (value, owner_customer_id) VALUES (?, ?)");
  for (const c of world.canaries) ins.run(c.value, c.owner_customer_id);
}

const toolByName = new Map(world.tools.map((t) => [t.name, t]));
const now = () => new Date().toISOString();
const namedParams = (sql) => [...new Set([...sql.matchAll(/(?<![:\w]):([A-Za-z_]\w*)/g)].map((m) => m[1]))];
const bind = (sql, available) => Object.fromEntries(namedParams(sql).map((p) => [p, available[p] ?? null]));

/** OpenAI tools spec from the world's tools. */
const toolSpecs = world.tools.map((t) => ({
  type: "function",
  function: { name: t.name, description: t.description, parameters: t.parameters },
}));

/** Guards active at this level for a tool that return a row → blocked. */
function guardBlock(tool, available) {
  for (const g of world.guards) {
    if (g.tool !== tool.name || !g.active_at.includes(LEVEL)) continue;
    const row = db.prepare(g.check_sql).get(bind(g.check_sql, available));
    if (row !== undefined) return { guard: g.id, error: g.error };
  }
  return null;
}

/** Run one tool call: guard, then execute; log either way. */
function runTool(session, tool, args) {
  const available = { ...args, [SESSION_PARAM]: session.customer_id };
  const blocked = guardBlock(tool, available);
  const logRow = {
    session_id: session.id,
    customer_id: session.customer_id,
    tool: tool.name,
    args_json: JSON.stringify(args),
    ts: now(),
  };
  if (blocked) {
    const result = { error: blocked.error };
    db.prepare(
      "INSERT INTO _tool_calls (session_id, customer_id, tool, args_json, result_json, blocked_by, ts) VALUES (:session_id, :customer_id, :tool, :args_json, :result_json, :blocked_by, :ts)",
    ).run({ ...logRow, result_json: JSON.stringify(result), blocked_by: blocked.guard });
    return result;
  }
  let result;
  const stmt = db.prepare(tool.sql);
  const params = bind(tool.sql, available);
  if (/^\s*select/i.test(tool.sql)) result = { rows: stmt.all(params) };
  else {
    const info = stmt.run(params);
    result = { changes: Number(info.changes) };
  }
  db.prepare(
    "INSERT INTO _tool_calls (session_id, customer_id, tool, args_json, result_json, blocked_by, ts) VALUES (:session_id, :customer_id, :tool, :args_json, :result_json, NULL, :ts)",
  ).run({ ...logRow, result_json: JSON.stringify(result) });
  return result;
}

/** One OpenAI-compatible chat completion with tools. */
async function complete(messages) {
  const res = await fetch(`${provider.base}/chat/completions`, {
    method: "POST",
    headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({ model: modelName, messages, tools: toolSpecs, temperature: 0 }),
  });
  if (!res.ok) throw new Error(`target LLM ${res.status}: ${(await res.text()).slice(0, 300)}`);
  const j = await res.json();
  const choice = j.choices?.[0];
  if (!choice) throw new Error(`target LLM returned no choices: ${JSON.stringify(j).slice(0, 300)}`);
  return choice.message;
}

/** Full agent turn: user message → tool loop → assistant reply. */
async function chat(session, userText) {
  db.prepare(
    "INSERT INTO _messages (session_id, customer_id, role, content, ts) VALUES (?, ?, 'user', ?, ?)",
  ).run(session.id, session.customer_id, userText, now());

  const history = db
    .prepare("SELECT role, content FROM _messages WHERE session_id = ? ORDER BY id")
    .all(session.id);
  const messages = [
    { role: "system", content: world.system_prompt },
    ...history.map((m) => ({ role: m.role, content: m.content })),
  ];

  for (let round = 0; round < MAX_TOOL_ROUNDS; round++) {
    const msg = await complete(messages);
    messages.push(msg);
    const calls = msg.tool_calls ?? [];
    if (calls.length === 0) {
      const reply = (msg.content ?? "").trim() || "(no reply)";
      db.prepare(
        "INSERT INTO _messages (session_id, customer_id, role, content, ts) VALUES (?, ?, 'assistant', ?, ?)",
      ).run(session.id, session.customer_id, reply, now());
      return reply;
    }
    for (const call of calls) {
      const tool = toolByName.get(call.function?.name);
      let result;
      if (!tool) result = { error: `unknown tool ${call.function?.name}` };
      else {
        let args = {};
        try {
          args = JSON.parse(call.function.arguments || "{}");
        } catch {
          result = { error: "arguments were not valid JSON" };
        }
        result ??= runTool(session, tool, args);
      }
      messages.push({ role: "tool", tool_call_id: call.id, content: JSON.stringify(result) });
    }
  }
  const reply = "(stopped: too many tool calls)";
  db.prepare(
    "INSERT INTO _messages (session_id, customer_id, role, content, ts) VALUES (?, ?, 'assistant', ?, ?)",
  ).run(session.id, session.customer_id, reply, now());
  return reply;
}

// ── HTTP ──
const readBody = (req) =>
  new Promise((resolve) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      try {
        resolve(b ? JSON.parse(b) : {});
      } catch {
        resolve(null);
      }
    });
  });

const server = createServer(async (req, res) => {
  const send = (code, obj) => {
    res.writeHead(code, { "Content-Type": "application/json" });
    res.end(JSON.stringify(obj));
  };
  try {
    if (req.method === "GET" && req.url === "/health") return send(200, { ok: true, level: LEVEL, model: MODEL });
    if (req.method === "POST" && req.url === "/session") {
      const body = await readBody(req);
      const customer_id = body?.customer_id;
      if (!customer_id) return send(400, { error: "customer_id required" });
      const id = `S-${Math.random().toString(36).slice(2, 10)}`;
      db.prepare("INSERT INTO _sessions (id, customer_id) VALUES (?, ?)").run(id, customer_id);
      return send(200, { session_id: id });
    }
    if (req.method === "POST" && req.url === "/chat") {
      const body = await readBody(req);
      if (!body?.session_id || typeof body.message !== "string") {
        return send(400, { error: "session_id and message required" });
      }
      const session = db.prepare("SELECT id, customer_id FROM _sessions WHERE id = ?").get(body.session_id);
      if (!session) return send(404, { error: "unknown session" });
      const reply = await chat(session, body.message);
      return send(200, { reply });
    }
    send(404, { error: "not found" });
  } catch (e) {
    send(500, { error: e instanceof Error ? e.message : String(e) });
  }
});
server.listen(Number(values.port), values.host, () => console.log(`target-runtime listening on ${values.host}:${values.port} (level ${LEVEL})`));
