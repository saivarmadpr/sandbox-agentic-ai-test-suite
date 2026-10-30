// Model-agnostic tool-calling over OpenAI-compatible endpoints. wb-red-team's
// provider returns plain text only; the attacker (and the target runtime) need
// tool calls, so this is the small client the plan called the M1 blocker.

import { splitModelId } from "./config.js";

const PROVIDERS: Record<string, { base: string; keyEnv: string }> = {
  openrouter: { base: "https://openrouter.ai/api/v1", keyEnv: "OPENROUTER_API_KEY" },
  nim: { base: "https://integrate.api.nvidia.com/v1", keyEnv: "NVIDIA_API_KEY" },
  openai: { base: "https://api.openai.com/v1", keyEnv: "OPENAI_API_KEY" },
  together: { base: "https://api.together.xyz/v1", keyEnv: "TOGETHER_API_KEY" },
};

export interface ToolSpec {
  type: "function";
  function: { name: string; description: string; parameters: Record<string, unknown> };
}

export interface ToolCall {
  id: string;
  function: { name: string; arguments: string };
}

export interface AssistantMessage {
  role: "assistant";
  content: string | null;
  tool_calls?: ToolCall[];
  refusal?: string | null;
}

type Message =
  | { role: "system" | "user"; content: string }
  | AssistantMessage
  | { role: "tool"; tool_call_id: string; content: string };

export function route(modelId: string): { base: string; apiKey: string; model: string } {
  const { provider, model } = splitModelId(modelId);
  const p = PROVIDERS[provider];
  if (!p) throw new Error(`unknown provider "${provider}"; use ${Object.keys(PROVIDERS).join(", ")}`);
  const apiKey = process.env[p.keyEnv];
  if (!apiKey) throw new Error(`missing ${p.keyEnv} for provider "${provider}"`);
  return { base: p.base, apiKey, model };
}

/** One tool-enabled completion. Throws on a provider refusal (empty/filtered),
 *  which no retry would fix. */
export async function chatWithTools(
  modelId: string,
  messages: Message[],
  tools: ToolSpec[],
): Promise<AssistantMessage> {
  const { base, apiKey, model } = route(modelId);
  const res = await fetch(`${base}/chat/completions`, {
    method: "POST",
    headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({ model, messages, tools, tool_choice: "auto", temperature: 0 }),
  });
  if (!res.ok) throw new Error(`${modelId} ${res.status}: ${(await res.text()).slice(0, 300)}`);
  const j = (await res.json()) as {
    choices?: { message: AssistantMessage; finish_reason?: string }[];
  };
  const choice = j.choices?.[0];
  if (!choice) throw new Error(`${modelId} returned no choices`);
  const msg = choice.message;
  if (choice.finish_reason === "content_filter" || msg.refusal) {
    throw new Error(`${modelId} refused: ${msg.refusal ?? "content filter"}`);
  }
  return msg;
}

export type { Message };
