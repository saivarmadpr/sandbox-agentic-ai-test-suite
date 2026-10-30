// Typed run events: appended to runs/<id>/events.jsonl and mirrored to the
// terminal as a live reasoning trace. One writer, so the file and the screen
// never disagree. Secrets are redacted centrally here.

import { appendFileSync } from "node:fs";

export type GuardBenchEvent =
  | { kind: "run"; scenario: string; levels: string[]; target_model: string; attacker_model: string }
  | { kind: "env"; message: string }
  | { kind: "level"; level: string }
  | { kind: "hypothesis"; level: string; id: string; invariant: string; title: string }
  | { kind: "think"; level: string; hid: string; text: string }
  | { kind: "msg"; level: string; hid: string; session: string; text: string }
  | { kind: "reply"; level: string; hid: string; ms: number; text: string }
  | { kind: "verdict"; level: string; hid: string; vulnerable: boolean; detail: string; requests: number }
  | { kind: "benign"; level: string; id: string; served: boolean; request: string }
  | { kind: "budget"; level: string; used: number; max: number }
  | { kind: "error"; where: string; message: string };

const C = {
  dim: "\x1b[2m",
  reset: "\x1b[0m",
  cyan: "\x1b[36m",
  green: "\x1b[32m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  bold: "\x1b[1m",
};
const clip = (s: string, n = 160) => (s.length > n ? s.slice(0, n - 1) + "…" : s).replace(/\s+/g, " ");

export class Events {
  private secrets: string[];
  constructor(
    private file: string,
    secrets: string[] = [],
  ) {
    // Redact API keys and the target URL from both sinks.
    this.secrets = secrets.filter((s) => s && s.length >= 6);
  }

  private redact(s: string): string {
    let out = s;
    for (const sec of this.secrets) out = out.split(sec).join("«redacted»");
    return out;
  }

  emit(e: GuardBenchEvent): void {
    const line = this.redact(JSON.stringify({ ts: new Date().toISOString(), ...e }));
    appendFileSync(this.file, line + "\n");
    const text = this.redact(render(e));
    if (text) console.log(text);
  }
}

function tag(label: string, color: string): string {
  return `${color}[${label.padEnd(9)}]${C.reset}`;
}

function render(e: GuardBenchEvent): string {
  switch (e.kind) {
    case "run":
      return `${tag("run", C.bold)} ${e.scenario} · levels ${e.levels.join(",")} · target ${e.target_model} · attacker ${e.attacker_model}`;
    case "env":
      return `${tag("env", C.cyan)} ${e.message}`;
    case "level":
      return `${tag("level " + e.level, C.bold)} ${"─".repeat(40)}`;
    case "hypothesis":
      return `${tag(e.id, C.yellow)} ${e.invariant} · ${e.title}`;
    case "think":
      return `${tag(e.hid, C.dim)} ${C.dim}think  ${clip(e.text)}${C.reset}`;
    case "msg":
      return `${tag(e.hid, C.cyan)} msg    ${clip(e.text)}`;
    case "reply":
      return `${tag(e.hid, C.dim)} reply  ${C.dim}(${e.ms}ms) ${clip(e.text)}${C.reset}`;
    case "verdict":
      return e.vulnerable
        ? `${tag(e.hid, C.red)} ${C.red}VULNERABLE${C.reset} ${e.detail} (req ${e.requests})`
        : `${tag(e.hid, C.green)} ${C.green}held${C.reset} ${e.detail} (req ${e.requests})`;
    case "benign":
      return e.served
        ? `${tag(e.id, C.green)} benign served: ${clip(e.request, 80)}`
        : `${tag(e.id, C.yellow)} benign REFUSED (over-refusal): ${clip(e.request, 80)}`;
    case "budget":
      return `${tag("budget", C.dim)} ${C.dim}${e.used}/${e.max} requests${C.reset}`;
    case "error":
      return `${tag("error", C.red)} ${e.where}: ${e.message}`;
  }
}
