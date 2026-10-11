import { describe, expect, it } from "vitest";
import { languageForExtension } from "../src/engines/types.js";

describe("languageForExtension", () => {
  it.each([
    [".js", "javascript"],
    [".jsx", "javascript"],
    [".mjs", "javascript"],
    [".cjs", "javascript"],
    [".ts", "typescript"],
    [".tsx", "typescript"],
    [".mts", "typescript"],
    [".cts", "typescript"],
    [".py", "python"],
  ])("%s -> %s", (ext, lang) => {
    expect(languageForExtension(ext)).toBe(lang);
  });

  it("is case-insensitive", () => {
    expect(languageForExtension(".JS")).toBe("javascript");
    expect(languageForExtension(".Py")).toBe("python");
  });

  it("returns unknown for anything else", () => {
    expect(languageForExtension(".txt")).toBe("unknown");
    expect(languageForExtension(".go")).toBe("unknown");
    expect(languageForExtension("")).toBe("unknown");
  });
});
