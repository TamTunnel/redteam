import { describe, it, expect, vi } from "vitest";
import { AttackAgent, maybeAttack } from "../../src/llm/attack-agent.js";
import type { LlmProvider } from "../../src/llm/providers.js";
import type { Finding } from "../../src/findings.js";

const CODE = [
  "const express = require('express');",
  "const app = express();",
  "app.get('/user/:id', (req, res) => {",
  "  const user = db.get(req.params.id);",
  "  res.json(user);",
  "});",
].join("\n");

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: "js-dangerous-fn",
    severity: "high",
    file: "app.js",
    line: 4,
    col: 10,
    message: "Possible unsafe call",
    snippet: "  const user = db.get(req.params.id);",
    source: "ast",
    ...overrides,
  };
}

const readFile = async (_path: string): Promise<string> => CODE;

/** Fake provider serving canned responses in order (last one repeats). */
function fakeProvider(responses: string[]) {
  const queue = [...responses];
  const complete = vi.fn(async (_prompt: string): Promise<string> => {
    const next = queue.length > 1 ? queue.shift()! : queue[0];
    return next;
  });
  const provider = { name: "fake", complete } as LlmProvider;
  return { provider, complete };
}

const verdictJson = (verdict: string, reason: string, newFindings: unknown[] = []) =>
  JSON.stringify({ verdict, reason, newFindings });

describe("AttackAgent", () => {
  it("passes a confirmed finding through unchanged", async () => {
    const { provider, complete } = fakeProvider([
      verdictJson("confirm", "User input reaches db.get with no validation."),
    ]);
    const agent = new AttackAgent({ provider });
    const f = finding();

    const result = await agent.analyze([f], readFile);

    expect(complete).toHaveBeenCalledTimes(1);
    expect(result.findings).toEqual([f]);
    expect(result.dismissed).toEqual([]);
    expect(result.notice).toBeUndefined();

    const prompt = complete.mock.calls[0][0] as string;
    expect(prompt).toContain("Possible unsafe call");
    expect(prompt).toContain("4:   const user = db.get(req.params.id);");
    expect(prompt).toContain('"verdict"');
    expect(prompt).toContain('"newFindings"');
  });

  it("records a dismissal with the model's reason", async () => {
    const { provider } = fakeProvider([
      verdictJson("dismiss", "req.params.id is allow-listed by middleware above."),
    ]);
    const agent = new AttackAgent({ provider });

    const result = await agent.analyze([finding()], readFile);

    expect(result.findings).toEqual([]);
    expect(result.dismissed).toEqual([
      {
        ruleId: "js-dangerous-fn",
        file: "app.js",
        line: 4,
        reason: "req.params.id is allow-listed by middleware above.",
      },
    ]);
  });

  it("tolerates markdown-fenced JSON in the model response", async () => {
    const { provider } = fakeProvider([
      'Here is my review:\n```json\n' +
        verdictJson("dismiss", "safe wrapper") +
        '\n```\nThat is all.',
    ]);
    const agent = new AttackAgent({ provider });

    const result = await agent.analyze([finding()], readFile);

    expect(result.findings).toEqual([]);
    expect(result.dismissed).toHaveLength(1);
    expect(result.dismissed[0].reason).toBe("safe wrapper");
  });

  it("turns newFindings into source:\"llm\" Findings with file/line/snippet", async () => {
    const { provider } = fakeProvider([
      verdictJson("confirm", "confirmed", [
        {
          line: 4,
          severity: "high",
          message: "IDOR: any user id can be fetched without an ownership check",
          remediation: "Verify req.user owns the requested id before querying",
        },
        {
          line: 3,
          severity: "critical",
          message: "Missing authentication on route",
          remediation: "Add auth middleware",
        },
      ]),
    ]);
    const agent = new AttackAgent({ provider });

    const result = await agent.analyze([finding()], readFile);

    expect(result.findings).toHaveLength(3);
    const [original, idor, auth] = result.findings;
    expect(original).toEqual(finding());

    for (const nf of [idor, auth]) {
      expect(nf.source).toBe("llm");
      expect(nf.file).toBe("app.js");
      expect(nf.ruleId).toMatch(/^llm-/);
    }
    expect(idor.line).toBe(4);
    expect(idor.severity).toBe("high");
    expect(idor.message).toContain("IDOR");
    expect(idor.snippet).toContain("db.get(req.params.id)");
    expect(idor.remediation).toContain("owns the requested id");
    expect(auth.severity).toBe("critical");
    expect(auth.line).toBe(3);
  });

  it("keeps the static finding and notes the raw output on malformed JSON", async () => {
    const { provider } = fakeProvider(["this is not json at all"]);
    const agent = new AttackAgent({ provider });
    const f = finding();

    const result = await agent.analyze([f], readFile);

    expect(result.findings).toEqual([f]);
    expect(result.dismissed).toEqual([]);
    expect(result.notice).toContain("not valid JSON");
    expect(result.notice).toContain("this is not json at all");
    expect(result.notice).toContain("js-dangerous-fn");
  });

  it("keeps the static finding when the LLM call itself fails", async () => {
    const provider = {
      name: "fake",
      complete: vi.fn().mockRejectedValue(new Error("socket hang up")),
    } as LlmProvider;
    const agent = new AttackAgent({ provider });
    const f = finding();

    const result = await agent.analyze([f], readFile);

    expect(result.findings).toEqual([f]);
    expect(result.notice).toContain("socket hang up");
  });

  it("does not send low/info findings to the LLM; they pass through", async () => {
    const { provider, complete } = fakeProvider([verdictJson("confirm", "real")]);
    const agent = new AttackAgent({ provider });
    const high = finding();
    const low = finding({ ruleId: "low-rule", severity: "low" });
    const info = finding({ ruleId: "info-rule", severity: "info" });

    const result = await agent.analyze([high, low, info], readFile);

    expect(complete).toHaveBeenCalledTimes(1);
    expect(result.findings).toContainEqual(high);
    expect(result.findings).toContainEqual(low);
    expect(result.findings).toContainEqual(info);
  });

  it("caps input at maxFindings, highest severity first", async () => {
    const { provider, complete } = fakeProvider([verdictJson("confirm", "real")]);
    const agent = new AttackAgent({ provider, maxFindings: 2 });
    const mediums = [finding({ ruleId: "m1", severity: "medium" })];
    const highs = [
      finding({ ruleId: "h1", severity: "high" }),
      finding({ ruleId: "h2", severity: "high" }),
      finding({ ruleId: "h3", severity: "high" }),
    ];

    const result = await agent.analyze([...mediums, ...highs], readFile);

    expect(complete).toHaveBeenCalledTimes(2);
    // h1, h2 analyzed (confirmed); h3 and m1 pass through untouched, in place.
    expect(result.findings.map((f) => f.ruleId)).toEqual(["m1", "h1", "h2", "h3"]);
  });

  it("skips newFinding entries with no message and defaults bad severity to medium", async () => {
    const { provider } = fakeProvider([
      verdictJson("confirm", "real", [
        { line: 2, severity: "bogus", message: "  ", remediation: "x" },
        { line: 2, severity: "bogus", message: "Weird default handling", remediation: "" },
      ]),
    ]);
    const agent = new AttackAgent({ provider });

    const result = await agent.analyze([finding()], readFile);

    expect(result.findings).toHaveLength(2);
    expect(result.findings[1].severity).toBe("medium");
    expect(result.findings[1].message).toBe("Weird default handling");
    expect(result.findings[1].remediation).toBeUndefined();
  });
});

describe("maybeAttack", () => {
  it("skips with the one-line notice and identical findings when no provider resolves", async () => {
    const savedAnthropic = process.env.ANTHROPIC_API_KEY;
    const savedOpenai = process.env.OPENAI_API_KEY;
    const savedGeneric = process.env.REDTEAM_LLM_API_KEY;
    const savedProvider = process.env.REDTEAM_LLM_PROVIDER;
    delete process.env.ANTHROPIC_API_KEY;
    delete process.env.OPENAI_API_KEY;
    delete process.env.REDTEAM_LLM_API_KEY;
    delete process.env.REDTEAM_LLM_PROVIDER;
    try {
      const f = finding();
      const result = await maybeAttack([f], readFile);
      expect(result.findings).toEqual([f]);
      expect(result.dismissed).toEqual([]);
      expect(result.notice).toBe(
        "LLM attack-agent skipped: no API key (set ANTHROPIC_API_KEY or OPENAI_API_KEY); static results unaffected.",
      );
    } finally {
      if (savedAnthropic !== undefined) process.env.ANTHROPIC_API_KEY = savedAnthropic;
      if (savedOpenai !== undefined) process.env.OPENAI_API_KEY = savedOpenai;
      if (savedGeneric !== undefined) process.env.REDTEAM_LLM_API_KEY = savedGeneric;
      if (savedProvider !== undefined) process.env.REDTEAM_LLM_PROVIDER = savedProvider;
    }
  });

  it("uses an explicitly passed provider instead of env", async () => {
    const { provider } = fakeProvider([verdictJson("dismiss", "not real")]);
    const result = await maybeAttack([finding()], readFile, { provider });
    expect(result.findings).toEqual([]);
    expect(result.dismissed).toHaveLength(1);
    expect(result.notice).toBeUndefined();
  });
});
