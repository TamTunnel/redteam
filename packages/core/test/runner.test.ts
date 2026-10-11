import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG, type RedteamConfig } from "../src/config.js";
import { matchesGlob, runScan } from "../src/runner.js";

// The classic example AWS key ID; matches the sec-aws-key builtin rule.
const VULN_JS = `// demo app\nconst awsKey = "AKIAIOSFODNN7EXAMPLE";\nmodule.exports = { awsKey };\n`;
const CLEAN_JS = `// nothing to see here\nmodule.exports = { ok: true };\n`;

const LLM_ENV_VARS = [
  "ANTHROPIC_API_KEY",
  "OPENAI_API_KEY",
  "REDTEAM_LLM_API_KEY",
  "REDTEAM_LLM_BASE_URL",
  "REDTEAM_LLM_MODEL",
  "REDTEAM_LLM_PROVIDER",
];

function baseConfig(patch: Partial<RedteamConfig> = {}): RedteamConfig {
  return {
    ...DEFAULT_CONFIG,
    exclude: [...DEFAULT_CONFIG.exclude],
    rules: { ...DEFAULT_CONFIG.rules },
    llm: { ...DEFAULT_CONFIG.llm },
    ...patch,
  };
}

async function makeDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), "redteam-runner-"));
}

/** Run a callback with all LLM env vars removed (offline-safe). */
async function withoutLlmEnv<T>(fn: () => Promise<T>): Promise<T> {
  const saved: Record<string, string | undefined> = {};
  for (const k of LLM_ENV_VARS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  try {
    return await fn();
  } finally {
    for (const k of LLM_ENV_VARS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

describe("runScan", () => {
  it("exits 1 on vulnerable fixtures with failOn medium", async () => {
    const dir = await makeDir();
    await writeFile(join(dir, "app.js"), VULN_JS);
    const result = await withoutLlmEnv(() =>
      runScan({ dir, config: baseConfig({ failOn: "medium", llm: { enabled: false } }) }),
    );
    expect(result.exitCode).toBe(1);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings.some((f) => f.ruleId === "sec-aws-key")).toBe(true);
    expect(result.report).toContain("# Redteam report");
    expect(result.report).toContain("sec-aws-key");
    expect(result.notices).toContain("LLM attack-agent disabled by config.");
  });

  it("exits 0 when findings are below failOn (medium findings vs high threshold)", async () => {
    const dir = await makeDir();
    // eval() is medium (syntactic cap) — below a "high" threshold.
    await writeFile(join(dir, "app.js"), "const r = eval(userInput);\n");
    const result = await withoutLlmEnv(() =>
      runScan({ dir, config: baseConfig({ failOn: "high", llm: { enabled: false } }) }),
    );
    expect(result.exitCode).toBe(0);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
  });

  it("exits 1 when a corroborated high finding meets failOn high", async () => {
    const dir = await makeDir();
    await writeFile(join(dir, "app.js"), VULN_JS);
    const result = await withoutLlmEnv(() =>
      runScan({ dir, config: baseConfig({ failOn: "high", llm: { enabled: false } }) }),
    );
    expect(result.exitCode).toBe(1);
    expect(result.findings.some((f) => f.severity === "high")).toBe(true);
  });

  it("exits 0 with 'No findings.' on a clean dir", async () => {
    const dir = await makeDir();
    await writeFile(join(dir, "app.js"), CLEAN_JS);
    const result = await withoutLlmEnv(() =>
      runScan({ dir, config: baseConfig({ llm: { enabled: false } }) }),
    );
    expect(result.exitCode).toBe(0);
    expect(result.findings).toEqual([]);
    expect(result.report).toContain("No findings.");
  });

  it("pushes the skip notice when LLM is enabled but no API key is set", async () => {
    const dir = await makeDir();
    await writeFile(join(dir, "app.js"), VULN_JS);
    const result = await withoutLlmEnv(() =>
      runScan({ dir, config: baseConfig({ failOn: "medium", llm: { enabled: true } }) }),
    );
    expect(result.notices.some((n) => n.includes("no API key"))).toBe(true);
    // Static results unaffected by the skipped LLM stage.
    expect(result.exitCode).toBe(1);
    expect(result.findings.some((f) => f.ruleId === "sec-aws-key")).toBe(true);
  });

  it("honours exclude globs (node_modules skipped by default)", async () => {
    const dir = await makeDir();
    await mkdir(join(dir, "node_modules", "dep"), { recursive: true });
    await writeFile(join(dir, "node_modules", "dep", "index.js"), VULN_JS);
    await writeFile(join(dir, "app.js"), CLEAN_JS);
    const result = await withoutLlmEnv(() =>
      runScan({ dir, config: baseConfig({ failOn: "medium", llm: { enabled: false } }) }),
    );
    expect(result.exitCode).toBe(0);
    expect(result.findings).toEqual([]);
  });

  it("honours rules.exclude", async () => {
    const dir = await makeDir();
    await writeFile(join(dir, "app.js"), VULN_JS);
    const result = await withoutLlmEnv(() =>
      runScan({
        dir,
        config: baseConfig({
          failOn: "medium",
          llm: { enabled: false },
          rules: { exclude: ["sec-aws-key"] },
        }),
      }),
    );
    expect(result.findings).toEqual([]);
    expect(result.exitCode).toBe(0);
  });

  it("honours rules.include with wildcards", async () => {
    const dir = await makeDir();
    await writeFile(join(dir, "app.js"), VULN_JS);
    const result = await withoutLlmEnv(() =>
      runScan({
        dir,
        config: baseConfig({
          failOn: "medium",
          llm: { enabled: false },
          rules: { include: ["no-such-rule-*"] },
        }),
      }),
    );
    expect(result.findings).toEqual([]);

    const kept = await withoutLlmEnv(() =>
      runScan({
        dir,
        config: baseConfig({
          failOn: "medium",
          llm: { enabled: false },
          rules: { include: ["sec-*"] },
        }),
      }),
    );
    expect(kept.findings.some((f) => f.ruleId === "sec-aws-key")).toBe(true);
  });

  it("renders json and sarif reports for the chosen format", async () => {
    const dir = await makeDir();
    await writeFile(join(dir, "app.js"), VULN_JS);

    const json = await withoutLlmEnv(() =>
      runScan({ dir, config: baseConfig({ llm: { enabled: false }, format: "json" }) }),
    );
    const parsed = JSON.parse(json.report) as { version: string };
    expect(parsed.version).toBe("1.0.0");

    const sarif = await withoutLlmEnv(() =>
      runScan({ dir, config: baseConfig({ llm: { enabled: false }, format: "sarif" }) }),
    );
    const sarifParsed = JSON.parse(sarif.report) as { version: string };
    expect(sarifParsed.version).toBe("2.1.0");
  });
});

describe("matchesGlob", () => {
  it("supports **, *, ?", () => {
    expect(matchesGlob(["node_modules/**"], "node_modules/dep/index.js")).toBe(true);
    expect(matchesGlob(["node_modules/**"], "src/index.js")).toBe(false);
    expect(matchesGlob(["**/*.min.js"], "a/b.min.js")).toBe(true);
    expect(matchesGlob(["**/*.min.js"], "b.min.js")).toBe(true);
    expect(matchesGlob(["**/*.min.js"], "b.js")).toBe(false);
    expect(matchesGlob(["dist/**"], "dist/out.js")).toBe(true);
    expect(matchesGlob(["*.js"], "a.js")).toBe(true);
    expect(matchesGlob(["*.js"], "x/a.js")).toBe(false);
    expect(matchesGlob(["src/?.js"], "src/a.js")).toBe(true);
    expect(matchesGlob(["src/?.js"], "src/ab.js")).toBe(false);
    expect(matchesGlob([], "src/a.js")).toBe(false);
  });
});
