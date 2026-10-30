import { getLlmProvider, type ChatMessage } from "wb-red-team/lib/llm-provider.js";
import type { Config as WbConfig } from "wb-red-team/lib/types.js";
import type { ZodType, ZodTypeDef } from "zod";
import { splitModelId } from "./config.js";

export type { ChatMessage };
export type Llm = (messages: ChatMessage[], maxTokens: number) => Promise<string>;

/** An Llm backed by wb-red-team's providers (anthropic, openai, openrouter,
 *  together, nim, ...). Model ids are "provider/model". */
export function makeLlm(modelId: string, phase: string): Llm {
  const { provider, model } = splitModelId(modelId);
  // wb-red-team's factory only reads attackConfig.llmProvider on this path.
  const p = getLlmProvider({ attackConfig: { llmProvider: provider } } as unknown as WbConfig);
  return (messages, maxTokens) => p.chat({ model, messages, maxTokens, phase });
}

/** First top-level JSON object in a reply, ignoring prose and ``` fences. */
export function extractJsonObject(text: string): unknown {
  const start = text.indexOf("{");
  if (start < 0) throw new Error("no JSON object found");
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (c === "\\") escaped = true;
      else if (c === '"') inString = false;
    } else if (c === '"') inString = true;
    else if (c === "{") depth++;
    else if (c === "}" && --depth === 0) return JSON.parse(text.slice(start, i + 1));
  }
  throw new Error("JSON object is cut off (reply may have hit the token limit)");
}

export interface Attempt {
  step: string;
  attempt: number;
  reply: string;
  problems: string[];
}

/** Ask for JSON, validate with the schema and `check`, and on failure send the
 *  problems back to the model and retry. Throws after `attempts` failures. */
export async function askJson<T>(
  llm: Llm,
  opts: {
    step: string;
    system: string;
    user: string;
    schema: ZodType<T, ZodTypeDef, unknown>;
    check?: (value: T) => string[];
    maxTokens: number;
    attempts?: number;
    onAttempt?: (a: Attempt) => void;
  },
): Promise<T> {
  const attempts = opts.attempts ?? 3;
  const messages: ChatMessage[] = [
    { role: "system", content: opts.system },
    { role: "user", content: opts.user },
  ];
  let problems: string[] = [];
  for (let attempt = 1; attempt <= attempts; attempt++) {
    const reply = await llm(messages, opts.maxTokens);
    if (!reply.trim()) {
      // wb-red-team's providers return "" when the model refuses or a content
      // filter blocks the request; retrying the same request won't change that.
      opts.onAttempt?.({ step: opts.step, attempt, reply, problems: ["empty reply"] });
      throw new Error(
        `${opts.step}: the model returned an empty reply. This usually means the provider refused or filtered the request (a usage-policy block), so it was not retried. Try a different model for this step.`,
      );
    }
    let value: T | undefined;
    try {
      const parsed = opts.schema.safeParse(extractJsonObject(reply));
      if (parsed.success) {
        value = parsed.data;
        problems = opts.check ? opts.check(value) : [];
      } else {
        problems = parsed.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`);
      }
    } catch (e) {
      problems = [`reply is not valid JSON: ${e instanceof Error ? e.message : String(e)}`];
    }
    opts.onAttempt?.({ step: opts.step, attempt, reply, problems });
    if (problems.length === 0 && value !== undefined) return value;
    messages.push(
      { role: "assistant", content: reply },
      {
        role: "user",
        content: `That JSON has these problems:\n- ${problems.join("\n- ")}\n\nReturn the complete corrected JSON object only.`,
      },
    );
  }
  throw new Error(`${opts.step}: still invalid after ${attempts} attempts:\n- ${problems.join("\n- ")}`);
}
