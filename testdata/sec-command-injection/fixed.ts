// Fixed: argv arrays — no shell, no string assembly.
import { execFile, spawn, ChildProcess } from "child_process";

export function showLog(branch: string, cb: (e: Error | null, out: string) => void): void {
  execFile("git", ["log", "--oneline", branch], cb);
}

export function convert(input: string, output: string): ChildProcess {
  return spawn("ffmpeg", ["-i", input, output]);
}
