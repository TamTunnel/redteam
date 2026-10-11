import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { SEVERITY_ORDER, type Severity } from "./findings.js";

export interface RedteamConfig {
  failOn: Severity;
  format: "json" | "markdown" | "sarif" | "html";
  exclude: string[];
  rules: { include?: string[]; exclude?: string[] };
  llm: { enabled: boolean; provider?: "anthropic" | "openai" | "openai-compatible" };
}

export const DEFAULT_CONFIG: RedteamConfig = {
  failOn: "high",
  format: "markdown",
  exclude: ["node_modules/**", "dist/**", "**/*.min.js", "**/vendor/**"],
  rules: {},
  llm: { enabled: true },
};

/**
 * Overrides accepted by loadConfig: like Partial<RedteamConfig>, except
 * `llm` also accepts a plain boolean (the CLI's --llm/--no-llm flags and
 * `.redteamrc.json`'s `"llm": false` both flow through here), and
 * `configPath` selects a JS config file explicitly instead of the default
 * `redteam.config.js` lookup.
 */
export interface ConfigOverrides extends Partial<Omit<RedteamConfig, "llm">> {
  llm?: boolean | RedteamConfig["llm"];
  configPath?: string;
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

const FORMATS = ["json", "markdown", "sarif", "html"] as const;

function isSeverity(v: unknown): v is Severity {
  return typeof v === "string" && v in SEVERITY_ORDER;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

/**
 * Merge a config-file patch over the base. Shallow per top-level key,
 * except `rules` and `llm` which merge key-wise. Unknown keys are ignored.
 */
function applyPatch(base: RedteamConfig, patch: Record<string, unknown>): RedteamConfig {
  const out: RedteamConfig = {
    failOn: base.failOn,
    format: base.format,
    exclude: base.exclude,
    rules: { ...base.rules },
    llm: { ...base.llm },
  };
  if (patch.failOn !== undefined) out.failOn = patch.failOn as Severity;
  if (patch.format !== undefined) out.format = patch.format as RedteamConfig["format"];
  if (patch.exclude !== undefined) {
    if (!Array.isArray(patch.exclude)) {
      throw new ConfigError(
        `Invalid "exclude": expected an array of globs, got ${typeof patch.exclude}.`,
      );
    }
    out.exclude = patch.exclude.map(String);
  }
  if (isRecord(patch.rules)) out.rules = { ...out.rules, ...(patch.rules as RedteamConfig["rules"]) };
  if (patch.llm !== undefined) {
    // Accept a plain boolean (CLI --no-llm / .redteamrc.json "llm": false)
    // as shorthand for { enabled }.
    if (typeof patch.llm === "boolean") {
      out.llm = { ...out.llm, enabled: patch.llm };
    } else if (isRecord(patch.llm)) {
      out.llm = { ...out.llm, ...(patch.llm as RedteamConfig["llm"]) };
    } else {
      throw new ConfigError(
        `Invalid "llm": expected a boolean or an object, got ${typeof patch.llm}.`,
      );
    }
  }
  return out;
}

function validate(config: RedteamConfig): void {
  if (!isSeverity(config.failOn)) {
    throw new ConfigError(
      `Invalid "failOn" severity "${String(config.failOn)}": expected one of critical, high, medium, low, info.`,
    );
  }
  if (!FORMATS.includes(config.format as (typeof FORMATS)[number])) {
    throw new ConfigError(
      `Invalid "format" "${String(config.format)}": expected one of ${FORMATS.join(", ")}.`,
    );
  }
}

async function readJsonConfig(cwd: string): Promise<Record<string, unknown> | null> {
  const path = join(cwd, ".redteamrc.json");
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new ConfigError(`Failed to read .redteamrc.json: ${(err as Error).message}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new ConfigError(`.redteamrc.json is not valid JSON: ${(err as Error).message}`);
  }
  if (!isRecord(parsed)) {
    throw new ConfigError(".redteamrc.json must contain a JSON object.");
  }
  return parsed;
}

/**
 * True when `err` is a module-not-found for the config file *itself*.
 * A config that exists but has a broken transitive import must NOT be
 * treated as "absent" — that error propagates as a ConfigError.
 */
function isConfigAbsent(err: unknown, configFileName: string): boolean {
  if (typeof err !== "object" || err === null) return false;
  const message = (err as { message?: unknown }).message;
  if (typeof message !== "string") return false;
  // ESM: "Cannot find module '/path/redteam.config.js' imported from ..."
  // CJS: "Cannot find module 'redteam.config.js'". In both cases the
  // message names the config file only when the config itself is missing;
  // a broken import *inside* the config names the other module instead.
  return /cannot find module/i.test(message) && message.includes(configFileName);
}

async function readJsConfig(
  cwd: string,
  configPath?: string,
): Promise<Record<string, unknown> | null> {
  const fileName = configPath ? configPath.split("/").pop() ?? "redteam.config.js" : "redteam.config.js";
  const abs = configPath ? configPath : join(cwd, "redteam.config.js");
  const url = pathToFileURL(abs).href;
  let mod: unknown;
  try {
    mod = await import(url);
  } catch (err) {
    if (!configPath && isConfigAbsent(err, fileName)) return null;
    throw new ConfigError(
      `Failed to load ${configPath ?? "redteam.config.js"}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  // Support both `export default {...}` (ESM) and `module.exports = {...}` (CJS,
  // which surfaces as the namespace's `default` export).
  const exported =
    isRecord(mod) && "default" in mod && mod.default !== undefined ? mod.default : mod;
  if (!isRecord(exported)) {
    throw new ConfigError("redteam.config.js must export a config object.");
  }
  return exported;
}

/**
 * Load configuration with precedence:
 *   overrides > redteam.config.js > .redteamrc.json > defaults.
 */
export async function loadConfig(
  cwd: string,
  overrides: Partial<RedteamConfig> = {},
): Promise<RedteamConfig> {
  let config: RedteamConfig = {
    ...DEFAULT_CONFIG,
    exclude: [...DEFAULT_CONFIG.exclude],
    rules: { ...DEFAULT_CONFIG.rules },
    llm: { ...DEFAULT_CONFIG.llm },
  };

  const rc = await readJsonConfig(cwd);
  if (rc) config = applyPatch(config, rc);

  const js = await readJsConfig(cwd);
  if (js) config = applyPatch(config, js);

  config = applyPatch(config, overrides as Record<string, unknown>);

  validate(config);
  return config;
}
