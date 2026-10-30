import { readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { z } from "zod";

export const LEVELS = ["L0", "L1", "L2"] as const;
export type Level = (typeof LEVELS)[number];

/** "provider/model", split on the first slash so OpenRouter ids like
 *  "openrouter/anthropic/claude-sonnet-4.5" keep their inner slash. */
const modelId = z
  .string()
  .regex(/^[a-z0-9_-]+\/.+$/i, 'must be "provider/model", e.g. "anthropic/claude-opus-5-5"');

export const nonEmpty = z.string().trim().min(1, "must not be empty");

const ConfigSchema = z
  .object({
    target: z
      .object({
        name: nonEmpty,
        description: nonEmpty,
        model: modelId,
        levels: z.array(z.enum(LEVELS)).nonempty().default([...LEVELS]),
      })
      .strict(),
    scenario: nonEmpty,
    expected_behavior: nonEmpty,
    // Guardrail shapes are pinned down in M3; until then accept "none" or any {type, ...}.
    guardrails: z
      .array(z.union([z.literal("none"), z.object({ type: nonEmpty }).passthrough()]))
      .nonempty()
      .default(["none"]),
    models: z
      .object({
        planner: modelId.default("anthropic/claude-opus-5-5"),
        attacker: z
          .union([modelId, z.array(modelId).nonempty()])
          .default("anthropic/claude-sonnet-5-5")
          .transform((v) => (Array.isArray(v) ? v : [v])),
        judge: modelId.default("anthropic/claude-opus-5-5"),
      })
      .strict()
      .default({}),
    constraints: z
      .object({
        max_requests: z.number().int().positive().default(500),
        max_duration_minutes: z.number().positive().default(60),
        max_cost_usd: z.number().positive().default(25),
        max_turns_per_hypothesis: z.number().int().positive().default(30),
        parallel_hypotheses: z.number().int().positive().default(4),
      })
      .strict()
      .default({}),
  })
  .strict()
  .superRefine((c, ctx) => {
    // The judge must not grade its own attacks.
    if (c.models.attacker.includes(c.models.judge)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["models", "judge"],
        message: `judge model "${c.models.judge}" is also an attacker model; use a different model`,
      });
    }
  });

export type Config = z.infer<typeof ConfigSchema>;

export function parseConfig(raw: unknown): Config {
  const result = ConfigSchema.safeParse(raw);
  if (!result.success) {
    const lines = result.error.issues.map(
      (i) => `  - ${i.path.join(".") || "(root)"}: ${i.message}`,
    );
    throw new Error(`Invalid scenario config:\n${lines.join("\n")}`);
  }
  return result.data;
}

export function loadConfig(path: string): Config {
  return parseConfig(parseYaml(readFileSync(path, "utf8")));
}

export function splitModelId(id: string): { provider: string; model: string } {
  const i = id.indexOf("/");
  return { provider: id.slice(0, i).toLowerCase(), model: id.slice(i + 1) };
}
