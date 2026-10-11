/**
 * CLI tests for @tamtunnel/redteam.
 *
 * These drive the BUILT bin (`packages/cli/dist/index.js`) as a subprocess —
 * run `npx tsc -b` at the repo root before `npm test`.
 *
 * Integration caveats (coordinator re-runs at integration):
 * - "rules list shows builtin rules" needs the core index to register the
 *   builtin rules on import (currently only `registry` is wired).
 * - the `scan` tests need the core's loadConfig/runScan/reporters, which are
 *   still stubs. Until they land, `scan` exits 2 with a clear message.
 */
import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(here, "../dist/index.js");

interface CliSuccess {
  stdout: string;
  stderr: string;
}

interface CliFailure extends Error {
  code?: number;
  stdout?: string;
  stderr?: string;
}

/**
 * Spawned-CLI env. Vitest workers set NODE_ENV=test and TEST=true, which
 * makes consola (citty's --help/--version renderer) raise its default log
 * level to `warn` and silently drop `consola.log` output — strip both so the
 * child behaves like a real shell. The CLI's own scan/report output uses
 * process.stdout.write / console.log directly and is unaffected.
 */
function childEnv(): NodeJS.ProcessEnv {
  const env = { ...process.env };
  delete env.NODE_ENV;
  delete env.TEST;
  return env;
}

async function runCli(argv: string[], cwd?: string): Promise<CliSuccess> {
  return execFileAsync(process.execPath, [CLI, ...argv], { cwd, env: childEnv() });
}

/** Runs the CLI, expecting a non-zero exit; resolves with the thrown error. */
async function runCliExpectFail(argv: string[], cwd?: string): Promise<CliFailure> {
  try {
    await runCli(argv, cwd);
  } catch (err) {
    const e = err as CliFailure;
    if (e.code !== undefined) return e;
    throw err;
  }
  throw new Error(`expected non-zero exit for: redteam ${argv.join(" ")}`);
}

describe("redteam CLI", () => {
  it("has a built bin (run `npx tsc -b` at the repo root first)", () => {
    expect(existsSync(CLI), `missing ${CLI} — run \`npx tsc -b\` at the repo root`).toBe(true);
  });

  it("--help lists the subcommands", async () => {
    const { stdout } = await runCli(["--help"]);
    for (const cmd of ["scan", "rules", "init"]) {
      expect(stdout).toContain(cmd);
    }
  });

  it("--version prints the package version", async () => {
    const pkg = JSON.parse(readFileSync(resolve(here, "../package.json"), "utf8")) as {
      version: string;
    };
    const { stdout } = await runCli(["--version"]);
    expect(stdout.trim()).toBe(pkg.version);
  });

  it("rules list exits 0 and shows builtin rules", async () => {
    const { stdout } = await runCli(["rules", "list"]);
    expect(stdout).toContain("ID");
    expect(stdout).toContain("sec-aws-key");
  });

  it("init writes .redteamrc.json and refuses to overwrite without --force", async () => {
    const dir = mkdtempSync(join(tmpdir(), "redteam-init-"));
    try {
      await runCli(["init"], dir);
      const cfg = JSON.parse(readFileSync(join(dir, ".redteamrc.json"), "utf8")) as Record<
        string,
        unknown
      >;
      expect(cfg.failOn).toBe("medium");
      expect(cfg.format).toBe("markdown");
      expect(cfg.llm).toBe(true);
      expect(cfg.exclude).toContain("node_modules/**");

      const err = await runCliExpectFail(["init"], dir);
      expect(err.code).toBe(2);
      expect(String(err.stderr)).toContain("already exists");

      await runCli(["init", "--force"], dir); // overwrites cleanly
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("scan exits 1 and reports the rule id on a vulnerable fixture", async () => {
    const dir = mkdtempSync(join(tmpdir(), "redteam-scan-"));
    try {
      writeFileSync(join(dir, "leak.js"), 'const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";\n');
      // --fail-on medium: sec-aws-key is a medium rule, so the threshold is
      // deterministic regardless of the core's default. --no-llm keeps the
      // test hermetic (no network / API keys).
      const err = await runCliExpectFail(["scan", dir, "--fail-on", "medium", "--no-llm"]);
      expect(err.code).toBe(1);
      expect(String(err.stdout)).toContain("sec-aws-key");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("scan exits 0 on an empty directory", async () => {
    const dir = mkdtempSync(join(tmpdir(), "redteam-scan-"));
    try {
      await runCli(["scan", dir, "--no-llm"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("scan rejects an invalid --fail-on with exit 2", async () => {
    const err = await runCliExpectFail(["scan", ".", "--fail-on", "bogus"]);
    expect(err.code).toBe(2);
    expect(String(err.stderr)).toContain("invalid --fail-on");
  });
});
