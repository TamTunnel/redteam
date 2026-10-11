// Vulnerable: command string assembled from parts.
import { exec, spawn, ChildProcess } from "child_process";

export function showLog(branch: string, cb: (e: Error | null, out: string) => void): void {
  exec("git log --oneline " + branch, cb);
}

export function convert(input: string, output: string): ChildProcess {
  return spawn(`ffmpeg -i ${input} ${output}`);
}
