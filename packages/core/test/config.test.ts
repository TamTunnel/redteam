import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  ConfigError,
  DEFAULT_CONFIG,
  loadConfig,
  type RedteamConfig,
} from "../src/config.js";

async function makeDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), "redteam-config-"));
}

describe("loadConfig defaults", () => {
  it("returns defaults when no config files exist", async () => {
    const dir = await makeDir();
    const config = await loadConfig(dir);
    expect(config).toEqual(DEFAULT_CONFIG);
    expect(config.failOn).toBe("high");
    expect(config.format).toBe("markdown");
    expect(config.exclude).toEqual([
      "node_modules/**",
      "dist/**",
      "**/*.min.js",
      "**/vendor/**",
    ]);
    expect(config.llm).toEqual({ enabled: true });
  });

  it("does not let callers mutate DEFAULT_CONFIG", async () => {
    const dir = await makeDir();
    const config = await loadConfig(dir);
    config.exclude.push("evil/**");
    expect(DEFAULT_CONFIG.exclude).not.toContain("evil/**");
  });
});

describe("loadConfig precedence", () => {
  it("overrides > redteam.config.js > .redteamrc.json > defaults", async () => {
    const dir = await makeDir();
    await writeFile(
      join(dir, ".redteamrc.json"),
      JSON.stringify({
        failOn: "medium",
        format: "json",
        exclude: ["build/**"],
        rules: { include: ["sec-*"] },
        llm: { enabled: false },
        someUnknownKey: 123, // must be ignored, not throw
      }),
    );
    await writeFile(
      join(dir, "redteam.config.js"),
      `module.exports = {\n` +
        `  failOn: "low",\n` +
        `  rules: { exclude: ["sec-aws-key"] },\n` +
        `  llm: { provider: "openai" },\n` +
        `};\n`,
    );

    const config = await loadConfig(dir, { format: "sarif" });

    expect(config.failOn).toBe("low"); // js beats rc
    expect(config.format).toBe("sarif"); // overrides beat everything
    expect(config.exclude).toEqual(["build/**"]); // rc beats defaults (shallow)
    expect(config.rules).toEqual({ include: ["sec-*"], exclude: ["sec-aws-key"] }); // key-wise merge
    expect(config.llm).toEqual({ enabled: false, provider: "openai" }); // key-wise merge
  });

  it("supports export default in redteam.config.js when the file is ESM", async () => {
    const dir = await makeDir();
    await writeFile(join(dir, "package.json"), JSON.stringify({ type: "module" }));
    await writeFile(
      join(dir, "redteam.config.js"),
      `export default { failOn: "critical" };\n`,
    );
    const config = await loadConfig(dir);
    expect(config.failOn).toBe("critical");
  });
});

describe("loadConfig validation", () => {
  it("throws ConfigError for an invalid failOn", async () => {
    const dir = await makeDir();
    await writeFile(join(dir, ".redteamrc.json"), JSON.stringify({ failOn: "banana" }));
    await expect(loadConfig(dir)).rejects.toThrow(ConfigError);
    await expect(loadConfig(dir)).rejects.toThrow(/failOn/);
  });

  it("throws ConfigError for an invalid format", async () => {
    const dir = await makeDir();
    await expect(loadConfig(dir, { format: "yaml" as RedteamConfig["format"] })).rejects.toThrow(
      ConfigError,
    );
  });

  it("throws ConfigError for malformed .redteamrc.json", async () => {
    const dir = await makeDir();
    await writeFile(join(dir, ".redteamrc.json"), "{ not json");
    await expect(loadConfig(dir)).rejects.toThrow(ConfigError);
  });

  it("ignores unknown keys without throwing", async () => {
    const dir = await makeDir();
    await writeFile(
      join(dir, ".redteamrc.json"),
      JSON.stringify({ whatever: true, nested: { deep: 1 } }),
    );
    const config = await loadConfig(dir);
    expect(config).toEqual(DEFAULT_CONFIG);
  });
});
