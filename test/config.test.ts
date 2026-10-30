import { describe, expect, it } from "vitest";
import { loadConfig, parseConfig, splitModelId } from "../src/config.js";

const minimal = {
  target: { name: "Bot", description: "Does things", model: "anthropic/claude-haiku-5-5" },
  scenario: "Try to break it",
  expected_behavior: "It stays safe",
};

describe("config", () => {
  it("loads the example scenario", () => {
    const c = loadConfig("scenarios/customer-support.yaml");
    expect(c.target.levels).toEqual(["L0", "L1", "L2"]);
    expect(c.models.attacker).toEqual(["anthropic/claude-sonnet-5-5"]);
    expect(c.constraints.max_cost_usd).toBe(25);
  });

  it("fills defaults on a minimal config", () => {
    const c = parseConfig(minimal);
    expect(c.guardrails).toEqual(["none"]);
    expect(c.models.planner).toBe("anthropic/claude-opus-5-5");
    expect(c.models.attacker).toEqual(["anthropic/claude-sonnet-5-5"]);
  });

  it("rejects unknown keys, so typos fail loudly", () => {
    expect(() => parseConfig({ ...minimal, expected_behaviour: "x" })).toThrow(/expected_behaviour/);
  });

  it("rejects missing required fields with their path", () => {
    const { scenario: _, ...noScenario } = minimal;
    expect(() => parseConfig(noScenario)).toThrow(/scenario/);
  });

  it("rejects a judge that is also an attacker", () => {
    expect(() =>
      parseConfig({ ...minimal, models: { attacker: "openai/gpt-5", judge: "openai/gpt-5" } }),
    ).toThrow(/models\.judge/);
  });

  it("rejects model ids without a provider", () => {
    expect(() => parseConfig({ ...minimal, target: { ...minimal.target, model: "gpt-5" } })).toThrow(
      /provider\/model/,
    );
  });

  it("splits model ids on the first slash only", () => {
    expect(splitModelId("openrouter/anthropic/claude-sonnet-4.5")).toEqual({
      provider: "openrouter",
      model: "anthropic/claude-sonnet-4.5",
    });
  });
});
